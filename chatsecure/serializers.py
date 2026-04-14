from rest_framework import serializers
from django.contrib.auth.models import User
from .models import *
import base64
import json

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name']
        read_only_fields = ['id']

class UserProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = UserProfile
        fields = ['id', 'user', 'public_key_rsa', 'dh_public_key', 
                 'certificate', 'certificate_valid_from', 'certificate_valid_to']
        read_only_fields = ['id', 'user', 'certificate']

class UserRegistrationSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=False, allow_blank=True)
    first_name = serializers.CharField(required=False, allow_blank=True)
    last_name = serializers.CharField(required=False, allow_blank=True)
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'confirm_password', 'first_name', 'last_name']
    
    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError("As senhas não coincidem")
        return data
    
    def create(self, validated_data):
        validated_data.pop('confirm_password')
        password = validated_data.pop('password')
        user = User.objects.create(**validated_data)
        user.set_password(password)
        user.save()
        return user

class CertificateAuthoritySerializer(serializers.ModelSerializer):
    class Meta:
        model = CertificateAuthority
        fields = ['id', 'name', 'ca_certificate', 'is_root', 'created_at']
        read_only_fields = ['id', 'ca_certificate', 'created_at']

class ConversationSerializer(serializers.ModelSerializer):
    participants = UserSerializer(many=True, read_only=True)
    participant_ids = serializers.ListField(write_only=True, child=serializers.IntegerField())
    last_message = serializers.SerializerMethodField()
    
    class Meta:
        model = Conversation
        fields = ['id', 'participants', 'participant_ids', 'conversation_type', 
                 'group_name', 'last_message', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def get_last_message(self, obj):
        last_msg = obj.messages.order_by('-timestamp').first()
        if last_msg:
            return {
                'id': last_msg.id,
                'sender': last_msg.sender.username,
                'timestamp': last_msg.timestamp,
                'message_type': last_msg.message_type
            }
        return None
    
    def create(self, validated_data):
        participant_ids = validated_data.pop('participant_ids')
        conversation = Conversation.objects.create(**validated_data)
        
        # Adicionar participantes
        users = User.objects.filter(id__in=participant_ids)
        conversation.participants.set(users)
        
        return conversation

class MessageSerializer(serializers.ModelSerializer):
    sender_name = serializers.CharField(source='sender.username', read_only=True)
    sender_id = serializers.IntegerField(source='sender.id', read_only=True)
    
    class Meta:
        model = Message
        fields = ['id', 'conversation', 'sender', 'sender_name', 'sender_id',
                 'encrypted_content', 'encrypted_session_key', 'digital_signature',
                 'hash_algorithm', 'message_hash', 'message_type', 
                 'file_name', 'file_size', 'mime_type', 'timestamp', 'is_read']
        read_only_fields = ['id', 'sender', 'timestamp']
    
    def validate(self, data):
        # Validar se o usuário é participante da conversa
        user = self.context['request'].user
        conversation = data.get('conversation')
        
        if not conversation.participants.filter(id=user.id).exists():
            raise serializers.ValidationError("Você não é participante desta conversa")
        
        return data

class MessageDeliveryStatusSerializer(serializers.ModelSerializer):
    recipient_name = serializers.CharField(source='recipient.username', read_only=True)
    
    class Meta:
        model = MessageDeliveryStatus
        fields = ['id', 'message', 'recipient', 'recipient_name', 
                 'status', 'sent_at', 'delivered_at', 'read_at']
        read_only_fields = ['id', 'sent_at']

class SessionKeySerializer(serializers.ModelSerializer):
    user1_name = serializers.CharField(source='user1.username', read_only=True)
    user2_name = serializers.CharField(source='user2.username', read_only=True)
    
    class Meta:
        model = SessionKey
        fields = ['id', 'user1', 'user1_name', 'user2', 'user2_name',
                 'session_key_encrypted', 'dh_shared_secret',
                 'created_at', 'expires_at', 'is_active']
        read_only_fields = ['id', 'created_at']

class KeyExchangeLogSerializer(serializers.ModelSerializer):
    user1_name = serializers.CharField(source='user1.username', read_only=True)
    user2_name = serializers.CharField(source='user2.username', read_only=True)
    
    class Meta:
        model = KeyExchangeLog
        fields = ['id', 'user1', 'user1_name', 'user2', 'user2_name',
                 'exchange_type', 'parameters_used', 'status', 
                 'error_message', 'timestamp']
        read_only_fields = ['id', 'timestamp']

class SharedKeySerializer(serializers.ModelSerializer):
    user1_name = serializers.CharField(source='user1.username', read_only=True)
    user2_name = serializers.CharField(source='user2.username', read_only=True)
    
    class Meta:
        model = SharedKey
        fields = ['id', 'user1', 'user1_name', 'user2', 'user2_name',
                 'encrypted_shared_key', 'key_size', 'hash_algorithm',
                 'created_at', 'expires_at']
        read_only_fields = ['id', 'created_at']

class PublicKeyExchangeSerializer(serializers.Serializer):
    """Serializer para troca de chaves públicas"""
    recipient_id = serializers.IntegerField()
    public_key = serializers.CharField()
    dh_public_key = serializers.CharField(required=False)
    dh_prime = serializers.CharField(required=False)
    dh_generator = serializers.CharField(required=False)

class EncryptedMessageSerializer(serializers.Serializer):
    """Serializer para mensagens criptografadas"""
    conversation_id = serializers.IntegerField()
    encrypted_content = serializers.CharField()
    encrypted_session_key = serializers.CharField()
    digital_signature = serializers.CharField()
    hash_algorithm = serializers.ChoiceField(choices=['sha256', 'sha512', 'sha3_256', 'sha3_512'])
    message_hash = serializers.CharField()
    message_type = serializers.ChoiceField(choices=['text', 'image', 'file'])
    file_name = serializers.CharField(required=False, allow_blank=True)
    file_size = serializers.IntegerField(required=False, allow_null=True)
    mime_type = serializers.CharField(required=False, allow_blank=True)
