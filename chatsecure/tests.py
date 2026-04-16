import json
import os
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase

from .bootstrap import sync_superuser_from_env, sync_users_from_env


class SuperuserBootstrapTests(TestCase):
    def test_creates_superuser_from_environment(self):
        with mock.patch.dict(
            os.environ,
            {
                'DJANGO_SUPERUSER_USERNAME': 'admin',
                'DJANGO_SUPERUSER_EMAIL': 'admin@example.com',
                'DJANGO_SUPERUSER_PASSWORD': 'strong-pass-123',
            },
            clear=False,
        ):
            user = sync_superuser_from_env()

        self.assertIsNotNone(user)
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)
        self.assertTrue(user.check_password('strong-pass-123'))

    def test_promotes_existing_user_and_can_reset_password(self):
        user_model = get_user_model()
        user = user_model.objects.create_user(
            username='admin',
            email='old@example.com',
            password='old-pass',
        )

        with mock.patch.dict(
            os.environ,
            {
                'DJANGO_SUPERUSER_USERNAME': 'admin',
                'DJANGO_SUPERUSER_EMAIL': 'admin@example.com',
                'DJANGO_SUPERUSER_PASSWORD': 'new-pass-456',
                'DJANGO_SUPERUSER_RESET_PASSWORD': 'true',
            },
            clear=False,
        ):
            sync_superuser_from_env()

        user.refresh_from_db()
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)
        self.assertEqual(user.email, 'admin@example.com')
        self.assertTrue(user.check_password('new-pass-456'))

    def test_creates_multiple_users_from_json_environment(self):
        with mock.patch.dict(
            os.environ,
            {
                'DJANGO_BOOTSTRAP_USERS': json.dumps(
                    [
                        {
                            'username': 'admin2',
                            'email': 'admin2@example.com',
                            'password': 'admin-pass-789',
                            'is_superuser': True,
                        },
                        {
                            'username': 'ana',
                            'email': 'ana@example.com',
                            'password': 'ana-pass-321',
                        },
                    ]
                ),
            },
            clear=False,
        ):
            users = sync_users_from_env()

        self.assertEqual(len(users), 2)

        user_model = get_user_model()
        admin_user = user_model.objects.get(username='admin2')
        normal_user = user_model.objects.get(username='ana')

        self.assertTrue(admin_user.is_staff)
        self.assertTrue(admin_user.is_superuser)
        self.assertTrue(admin_user.check_password('admin-pass-789'))

        self.assertFalse(normal_user.is_staff)
        self.assertFalse(normal_user.is_superuser)
        self.assertTrue(normal_user.check_password('ana-pass-321'))

    def test_updates_existing_user_from_json_environment(self):
        user_model = get_user_model()
        user = user_model.objects.create_user(
            username='joana',
            email='old@example.com',
            password='old-pass',
            is_active=False,
        )

        with mock.patch.dict(
            os.environ,
            {
                'DJANGO_BOOTSTRAP_USERS': json.dumps(
                    [
                        {
                            'username': 'joana',
                            'email': 'joana@example.com',
                            'password': 'new-pass-999',
                            'is_staff': True,
                            'is_active': True,
                            'reset_password': True,
                        }
                    ]
                ),
            },
            clear=False,
        ):
            sync_users_from_env()

        user.refresh_from_db()
        self.assertEqual(user.email, 'joana@example.com')
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_active)
        self.assertTrue(user.check_password('new-pass-999'))
