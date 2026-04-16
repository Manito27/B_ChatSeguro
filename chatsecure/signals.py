from .bootstrap import sync_users_from_env


def ensure_bootstrap_users(sender, **kwargs):
    sync_users_from_env()
