from django.apps import AppConfig


class ChatsecureConfig(AppConfig):
    name = 'chatsecure'

    def ready(self):
        from django.db.models.signals import post_migrate

        from .signals import ensure_bootstrap_users

        post_migrate.connect(
            ensure_bootstrap_users,
            sender=self,
            dispatch_uid='chatsecure.ensure_bootstrap_users',
        )
