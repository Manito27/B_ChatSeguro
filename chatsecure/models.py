# chat/models.py
from django.db import models
from django.contrib.auth.models import User
import datetime
import json

class UserProfile(models.Model):
    """
    Perfil estendido do usuário com informações criptográficas
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    
    # Chaves assimétricas (RSA)
    public_key_rsa = models.TextField(help_text="Chave pública RSA (formato PEM)")
    private_key_rsa = models.TextField(help_text="Chave privada RSA (criptografada)")
    
    # Chaves para Diffie-Hellman
    dh_public_key = models.TextField(blank=True, null=True, help_text="Chave pública DH")
    dh_private_key = models.TextField(blank=True, null=True, help_text="Chave privada DH (criptografada)")
    dh_prime = models.TextField(blank=True, null=True, help_text="Número primo P para DH")
    dh_generator = models.TextField(blank=True, null=True, help_text="Gerador G para DH")
    
    # Certificado digital
    certificate = models.TextField(blank=True, null=True, help_text="Certificado digital X.509")
    certificate_issuer = models.CharField(max_length=255, blank=True, help_text="Emissor do certificado")
    certificate_valid_from = models.DateTimeField(null=True, blank=True)
    certificate_valid_to = models.DateTimeField(null=True, blank=True)
    certificate_serial = models.CharField(max_length=100, blank=True)
    
    # Metadados
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Perfil de {self.user.username}"

class CertificateAuthority(models.Model):
    """
    Autoridade Certificadora (CA) para PKI
    """
    name = models.CharField(max_length=100, help_text="Nome da CA")
    
    # Chaves da CA
    ca_public_key = models.TextField(help_text="Chave pública da CA")
    ca_private_key = models.TextField(help_text="Chave privada da CA (criptografada)")
    
    # Certificado autoassinado da CA
    ca_certificate = models.TextField(help_text="Certificado autoassinado da CA")
    
    is_root = models.BooleanField(default=True, help_text="É CA raiz?")
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"CA: {self.name}"

class SessionKey(models.Model):
    """
    Gerencia chaves de sessão para comunicação entre usuários
    (Simula acordo de chaves DH e chaves simétricas temporárias)
    """
    user1 = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sessions_as_user1')
    user2 = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sessions_as_user2')
    
    # Chave de sessão (simétrica) - armazenada criptografada
    session_key_encrypted = models.TextField(help_text="Chave de sessão criptografada com chave pública")
    
    # Parâmetros DH para esta sessão
    dh_shared_secret = models.TextField(blank=True, help_text="Segredo compartilhado DH (criptografado)")
    dh_prime_used = models.TextField(help_text="Primo P usado na troca DH")
    dh_generator_used = models.TextField(help_text="Gerador G usado na troca DH")
    
    # Metadados da sessão
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(help_text="Data de expiração da chave de sessão")
    is_active = models.BooleanField(default=True)
    
    class Meta:
        unique_together = ['user1', 'user2', 'is_active']
    
    def __str__(self):
        return f"Sessão: {self.user1.username} <-> {self.user2.username}"

class Conversation(models.Model):
    """
    Representa uma conversa entre dois ou mais usuários
    """
    participants = models.ManyToManyField(User, related_name='conversations')
    
    # Tipo de conversa
    CONVERSATION_TYPES = [
        ('private', 'Privada (1-1)'),
        ('group', 'Grupo'),
    ]
    conversation_type = models.CharField(max_length=10, choices=CONVERSATION_TYPES, default='private')
    
    # Para conversas em grupo
    group_name = models.CharField(max_length=100, blank=True, null=True)
    group_public_key = models.TextField(blank=True, null=True, help_text="Chave pública do grupo (para grupos)")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        if self.conversation_type == 'private':
            participants = self.participants.all()
            if participants.count() == 2:
                return f"Conversa: {participants[0].username} - {participants[1].username}"
        return f"Grupo: {self.group_name or 'Sem nome'}"

class Message(models.Model):
    """
    Mensagem criptografada no estilo PGP
    (Combinação de criptografia assimétrica + simétrica)
    """
    conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE, related_name='messages')
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    
    # Conteúdo criptografado
    encrypted_content = models.TextField(help_text="Conteúdo criptografado com chave simétrica")
    
    # Chave simétrica criptografada com chave pública do destinatário
    encrypted_session_key = models.TextField(
        help_text="Chave de sessão (simétrica) criptografada com chave pública do destinatário"
    )
    
    # Assinatura digital para autenticidade
    digital_signature = models.TextField(help_text="Assinatura RSA do hash da mensagem")
    
    # Hash para integridade
    MESSAGE_HASH_ALGORITHMS = [
        ('sha256', 'SHA-256'),
        ('sha512', 'SHA-512'),
        ('sha3_256', 'SHA3-256'),
        ('sha3_512', 'SHA3-512'),
    ]
    hash_algorithm = models.CharField(max_length=20, choices=MESSAGE_HASH_ALGORITHMS, default='sha256')
    message_hash = models.TextField(help_text="Hash da mensagem original para verificação de integridade")
    
    # Metadados da mensagem
    MESSAGE_TYPES = [
        ('text', 'Texto'),
        ('image', 'Imagem'),
        ('file', 'Arquivo'),
    ]
    message_type = models.CharField(max_length=10, choices=MESSAGE_TYPES, default='text')
    
    # Para mensagens de imagem/arquivo
    file_name = models.CharField(max_length=255, blank=True, null=True)
    file_size = models.IntegerField(blank=True, null=True)
    mime_type = models.CharField(max_length=100, blank=True, null=True)
    
    # Timestamps
    timestamp = models.DateTimeField(auto_now_add=True)
    edited_at = models.DateTimeField(null=True, blank=True)
    
    # Status
    is_read = models.BooleanField(default=False)
    read_by = models.ManyToManyField(User, related_name='read_messages', blank=True)
    
    def __str__(self):
        return f"Mensagem de {self.sender.username} às {self.timestamp}"

class MessageDeliveryStatus(models.Model):
    """
    Status de entrega das mensagens
    """
    message = models.ForeignKey(Message, on_delete=models.CASCADE, related_name='delivery_status')
    recipient = models.ForeignKey(User, on_delete=models.CASCADE)
    
    DELIVERY_STATUS = [
        ('sent', 'Enviada'),
        ('delivered', 'Entregue'),
        ('read', 'Lida'),
        ('failed', 'Falhou'),
    ]
    status = models.CharField(max_length=10, choices=DELIVERY_STATUS, default='sent')
    
    # Timestamps
    sent_at = models.DateTimeField(auto_now_add=True)
    delivered_at = models.DateTimeField(null=True, blank=True)
    read_at = models.DateTimeField(null=True, blank=True)
    
    # Chave de sessão individual para este destinatário
    individual_session_key = models.TextField(blank=True, null=True)
    
    class Meta:
        unique_together = ['message', 'recipient']
    
    def __str__(self):
        return f"Status: {self.message.id} -> {self.recipient.username}: {self.status}"

class RevokedCertificate(models.Model):
    """
    Lista de Certificados Revogados (CRL)
    """
    user_profile = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    certificate_serial = models.CharField(max_length=100)
    revoked_at = models.DateTimeField(auto_now_add=True)
    revocation_reason = models.TextField()
    revoked_by = models.ForeignKey(CertificateAuthority, on_delete=models.CASCADE)
    
    def __str__(self):
        return f"Certificado revogado: {self.certificate_serial}"

class KeyExchangeLog(models.Model):
    """
    Log das trocas de chaves para auditoria
    """
    user1 = models.ForeignKey(User, on_delete=models.CASCADE, related_name='key_exchanges_as_user1')
    user2 = models.ForeignKey(User, on_delete=models.CASCADE, related_name='key_exchanges_as_user2')
    
    EXCHANGE_TYPES = [
        ('rsa', 'Troca RSA'),
        ('dh', 'Diffie-Hellman'),
        ('hybrid', 'Híbrido (PGP)'),
    ]
    exchange_type = models.CharField(max_length=10, choices=EXCHANGE_TYPES)
    
    # Parâmetros usados
    parameters_used = models.JSONField(help_text="Parâmetros usados na troca (primos, geradores, etc)")
    
    # Status
    SUCCESS_STATUS = [
        ('success', 'Sucesso'),
        ('failure', 'Falha'),
        ('pending', 'Pendente'),
    ]
    status = models.CharField(max_length=10, choices=SUCCESS_STATUS)
    error_message = models.TextField(blank=True, null=True)
    
    timestamp = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Troca {self.exchange_type}: {self.user1.username} <-> {self.user2.username} - {self.status}"

class SharedKey(models.Model):
    """
    Armazena chaves compartilhadas entre usuários (simula PGP)
    """
    user1 = models.ForeignKey(User, on_delete=models.CASCADE, related_name='shared_keys_as_user1')
    user2 = models.ForeignKey(User, on_delete=models.CASCADE, related_name='shared_keys_as_user2')
    
    # Chave simétrica compartilhada (criptografada)
    encrypted_shared_key = models.TextField(help_text="Chave compartilhada criptografada")
    
    # Metadados da chave
    key_size = models.IntegerField(default=128, help_text="Tamanho da chave em bits (PRNG)")
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    
    # Algoritmo de hash usado para derivação
    HASH_ALGORITHMS = [
        ('sha256', 'SHA-256'),
        ('sha512', 'SHA-512'),
        ('sha3', 'SHA-3'),
    ]
    hash_algorithm = models.CharField(max_length=10, choices=HASH_ALGORITHMS, default='sha256')
    
    class Meta:
        unique_together = ['user1', 'user2']
    
    def __str__(self):
        return f"Chave compartilhada: {self.user1.username} - {self.user2.username}"