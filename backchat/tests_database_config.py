import os
from unittest import mock

from django.test import SimpleTestCase

from . import settings as project_settings


class DatabaseConfigTests(SimpleTestCase):
    def test_postgres_database_url_builds_postgres_config(self):
        with mock.patch.dict(
            os.environ,
            {
                'DATABASE_URL': (
                    'postgresql://avnadmin:secret@pg-demo.aivencloud.com:12345/defaultdb'
                    '?sslmode=require&application_name=chatseguro'
                ),
                'POSTGRES_SSLMODE': 'verify-full',
                'POSTGRES_SSLROOTCERT': '/etc/secrets/aiven-ca.pem',
                'DB_CONN_MAX_AGE': '120',
            },
            clear=True,
        ):
            config = project_settings.database_config()

        self.assertEqual(config['ENGINE'], 'django.db.backends.postgresql')
        self.assertEqual(config['NAME'], 'defaultdb')
        self.assertEqual(config['USER'], 'avnadmin')
        self.assertEqual(config['PASSWORD'], 'secret')
        self.assertEqual(config['HOST'], 'pg-demo.aivencloud.com')
        self.assertEqual(config['PORT'], '12345')
        self.assertEqual(config['CONN_MAX_AGE'], 120)
        self.assertEqual(config['OPTIONS']['application_name'], 'chatseguro')
        self.assertEqual(config['OPTIONS']['sslmode'], 'verify-full')
        self.assertEqual(config['OPTIONS']['sslrootcert'], '/etc/secrets/aiven-ca.pem')

    def test_postgres_env_vars_build_postgres_config(self):
        with mock.patch.dict(
            os.environ,
            {
                'POSTGRES_DB': 'defaultdb',
                'POSTGRES_USER': 'avnadmin',
                'POSTGRES_PASSWORD': 'secret',
                'POSTGRES_HOST': 'pg-demo.aivencloud.com',
                'POSTGRES_PORT': '12345',
                'POSTGRES_SSLMODE': 'verify-ca',
                'POSTGRES_SSLROOTCERT': '/etc/secrets/aiven-ca.pem',
                'POSTGRES_CONNECT_TIMEOUT': '10',
            },
            clear=True,
        ):
            config = project_settings.database_config()

        self.assertEqual(config['ENGINE'], 'django.db.backends.postgresql')
        self.assertEqual(config['NAME'], 'defaultdb')
        self.assertEqual(config['USER'], 'avnadmin')
        self.assertEqual(config['HOST'], 'pg-demo.aivencloud.com')
        self.assertEqual(config['PORT'], '12345')
        self.assertEqual(config['OPTIONS']['sslmode'], 'verify-ca')
        self.assertEqual(config['OPTIONS']['sslrootcert'], '/etc/secrets/aiven-ca.pem')
        self.assertEqual(config['OPTIONS']['connect_timeout'], 10)
