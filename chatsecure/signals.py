from .bootstrap import sync_superuser_from_env


def ensure_superuser(sender, **kwargs):
    sync_superuser_from_env()
