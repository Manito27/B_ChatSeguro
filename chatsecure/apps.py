from django.apps import AppConfig


class ChatsecureConfig(AppConfig):
    name = 'chatsecure'

    def ready(self):
        from django.db.models.signals import post_migrate

        from .signals import ensure_superuser

        post_migrate.connect(
            ensure_superuser,
            sender=self,
            dispatch_uid='chatsecure.ensure_superuser',
        )
