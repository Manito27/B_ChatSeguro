import logging
import json
import os

from django.contrib.auth import get_user_model


logger = logging.getLogger(__name__)
TRUTHY_VALUES = {'1', 'true', 'yes', 'on'}


def _env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in TRUTHY_VALUES


def _coerce_bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in TRUTHY_VALUES


def _legacy_superuser_spec():
    username = (os.getenv('DJANGO_SUPERUSER_USERNAME') or '').strip()
    password = os.getenv('DJANGO_SUPERUSER_PASSWORD')
    email = (os.getenv('DJANGO_SUPERUSER_EMAIL') or '').strip()
    reset_password = _env_bool('DJANGO_SUPERUSER_RESET_PASSWORD', False)

    if not username:
        logger.info('Skipping admin bootstrap: DJANGO_SUPERUSER_USERNAME not set.')
        return {}

    if password is None or not password.strip():
        logger.info('Skipping admin bootstrap: DJANGO_SUPERUSER_PASSWORD not set.')
        return {}

    return {
        'username': username,
        'password': password,
        'email': email,
        'is_staff': True,
        'is_superuser': True,
        'is_active': True,
        'reset_password': reset_password,
        'source': 'legacy superuser environment',
    }


def _bootstrap_users_from_env():
    raw_value = (os.getenv('DJANGO_BOOTSTRAP_USERS') or '').strip()
    if not raw_value:
        return []

    try:
        payload = json.loads(raw_value)
    except json.JSONDecodeError as exc:
        logger.warning('Skipping DJANGO_BOOTSTRAP_USERS: invalid JSON (%s).', exc)
        return []

    if isinstance(payload, dict):
        payload = [payload]

    if not isinstance(payload, list):
        logger.warning('Skipping DJANGO_BOOTSTRAP_USERS: expected a JSON list or object.')
        return []

    specs = []
    for index, item in enumerate(payload, start=1):
        if not isinstance(item, dict):
            logger.warning(
                'Skipping DJANGO_BOOTSTRAP_USERS[%s]: expected an object, got %s.',
                index,
                type(item).__name__,
            )
            continue

        username = str(item.get('username') or '').strip()
        password = item.get('password')
        email = str(item.get('email') or '').strip()
        is_superuser = _coerce_bool(item.get('is_superuser'), False)
        is_staff = _coerce_bool(item.get('is_staff'), is_superuser)
        is_active = _coerce_bool(item.get('is_active'), True)
        reset_password = _coerce_bool(item.get('reset_password'), False)

        if not username:
            logger.warning(
                'Skipping DJANGO_BOOTSTRAP_USERS[%s]: "username" is required.',
                index,
            )
            continue

        specs.append(
            {
                'username': username,
                'password': password,
                'email': email,
                'is_staff': is_staff or is_superuser,
                'is_superuser': is_superuser,
                'is_active': is_active,
                'reset_password': reset_password,
                'source': f'DJANGO_BOOTSTRAP_USERS[{index}]',
            }
        )

    return specs


def _iter_user_specs():
    deduped_specs = {}

    legacy_spec = _legacy_superuser_spec()
    if legacy_spec:
        deduped_specs[legacy_spec['username']] = legacy_spec

    for spec in _bootstrap_users_from_env():
        deduped_specs[spec['username']] = spec

    return list(deduped_specs.values())


def _sync_user_from_spec(user_model, spec):
    username = spec['username']
    password = spec.get('password')
    email = spec.get('email', '')
    is_staff = spec.get('is_staff', False)
    is_superuser = spec.get('is_superuser', False)
    is_active = spec.get('is_active', True)
    reset_password = spec.get('reset_password', False)
    source = spec.get('source', 'environment')

    try:
        user = user_model.objects.get(username=username)
        created = False
    except user_model.DoesNotExist:
        if password is None or not str(password).strip():
            logger.info(
                'Skipping Django user "%s" from %s: password not set for new user.',
                username,
                source,
            )
            return None

        user = user_model(
            username=username,
            email=email,
            is_staff=is_staff,
            is_superuser=is_superuser,
            is_active=is_active,
        )
        user.set_password(str(password))
        user.save()
        logger.info('Created Django user "%s" from %s.', username, source)
        return user

    changed = False
    if email and user.email != email:
        user.email = email
        changed = True
    if is_staff and not user.is_staff:
        user.is_staff = True
        changed = True
    if is_superuser and not user.is_superuser:
        user.is_superuser = True
        changed = True
    if is_active and not user.is_active:
        user.is_active = True
        changed = True
    if reset_password:
        if password is None or not str(password).strip():
            logger.info(
                'Skipping password reset for Django user "%s" from %s: password not set.',
                username,
                source,
            )
        else:
            user.set_password(str(password))
            changed = True

    if changed:
        user.save()

    if changed:
        logger.info('Updated Django user "%s" from %s.', username, source)
    else:
        logger.info('Django user "%s" from %s already up to date.', username, source)

    return user


def sync_users_from_env():
    user_model = get_user_model()
    users = []

    for spec in _iter_user_specs():
        user = _sync_user_from_spec(user_model, spec)
        if user is not None:
            users.append(user)

    return users


def sync_superuser_from_env():
    users = sync_users_from_env()
    return users[0] if users else None
