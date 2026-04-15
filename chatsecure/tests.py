import os
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase

from .bootstrap import sync_superuser_from_env


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
