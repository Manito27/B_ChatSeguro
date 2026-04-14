from django.contrib import admin

from .models import (
    UserProfile,
    CertificateAuthority,
    Conversation,
    Message,
    MessageDeliveryStatus,
    SessionKey,
    KeyExchangeLog,
    SharedKey,
    RevokedCertificate,
)


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'created_at', 'certificate_serial']
    search_fields = ['user__username', 'user__email']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(CertificateAuthority)
class CertificateAuthorityAdmin(admin.ModelAdmin):
    list_display = ['name', 'is_root', 'created_at']
    readonly_fields = ['created_at']


@admin.register(Conversation)
class ConversationAdmin(admin.ModelAdmin):
    list_display = ['id', 'conversation_type', 'group_name', 'created_at']
    filter_horizontal = ['participants']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ['id', 'sender', 'conversation', 'message_type', 'timestamp', 'is_read']
    list_filter = ['message_type', 'is_read', 'hash_algorithm']
    search_fields = ['sender__username']
    readonly_fields = ['timestamp']
    filter_horizontal = ['read_by']


@admin.register(MessageDeliveryStatus)
class MessageDeliveryStatusAdmin(admin.ModelAdmin):
    list_display = ['message', 'recipient', 'status', 'sent_at']
    list_filter = ['status']
    readonly_fields = ['sent_at']


@admin.register(SessionKey)
class SessionKeyAdmin(admin.ModelAdmin):
    list_display = ['user1', 'user2', 'is_active', 'created_at', 'expires_at']
    list_filter = ['is_active']
    readonly_fields = ['created_at']


@admin.register(KeyExchangeLog)
class KeyExchangeLogAdmin(admin.ModelAdmin):
    list_display = ['user1', 'user2', 'exchange_type', 'status', 'timestamp']
    list_filter = ['exchange_type', 'status']
    readonly_fields = ['timestamp']


@admin.register(SharedKey)
class SharedKeyAdmin(admin.ModelAdmin):
    list_display = ['user1', 'user2', 'key_size', 'hash_algorithm', 'expires_at']
    list_filter = ['key_size', 'hash_algorithm']


@admin.register(RevokedCertificate)
class RevokedCertificateAdmin(admin.ModelAdmin):
    list_display = ['user_profile', 'certificate_serial', 'revoked_at']
    readonly_fields = ['revoked_at']
