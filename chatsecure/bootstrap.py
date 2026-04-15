import logging
import os

from django.contrib.auth import get_user_model


logger = logging.getLogger(__name__)
TRUTHY_VALUES = {'1', 'true', 'yes', 'on'}


def _env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in TRUTHY_VALUES


def sync_superuser_from_env():
    username = (os.getenv('DJANGO_SUPERUSER_USERNAME') or '').strip()
    password = os.getenv('DJANGO_SUPERUSER_PASSWORD')
    email = (os.getenv('DJANGO_SUPERUSER_EMAIL') or '').strip()
    reset_password = _env_bool('DJANGO_SUPERUSER_RESET_PASSWORD', False)

    if not username:
        logger.info('Skipping admin bootstrap: DJANGO_SUPERUSER_USERNAME not set.')
        return None

    if password is None or not password.strip():
        logger.info('Skipping admin bootstrap: DJANGO_SUPERUSER_PASSWORD not set.')
        return None

    user_model = get_user_model()
    user, created = user_model.objects.get_or_create(
        username=username,
        defaults={
            'email': email,
            'is_staff': True,
            'is_superuser': True,
            'is_active': True,
        },
    )

    changed = created
    if created:
        user.set_password(password)
    else:
        if email and user.email != email:
            user.email = email
            changed = True
        if not user.is_staff:
            user.is_staff = True
            changed = True
        if not user.is_superuser:
            user.is_superuser = True
            changed = True
        if not user.is_active:
            user.is_active = True
            changed = True
        if reset_password:
            user.set_password(password)
            changed = True

    if changed:
        user.save()

    if created:
        logger.info('Created Django admin user "%s" from environment.', username)
    elif changed:
        logger.info('Updated Django admin user "%s" from environment.', username)
    else:
        logger.info('Django admin user "%s" already up to date.', username)

    return user
