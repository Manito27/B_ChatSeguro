from datetime import datetime, timedelta
import base64
import hashlib
import json
import os
import secrets

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.db.models import Q
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status, viewsets
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .models import (
    CertificateAuthority,
    Conversation,
    KeyExchangeLog,
    Message,
    MessageDeliveryStatus,
    RevokedCertificate,
    SessionKey,
    SharedKey,
    UserProfile,
)
from .serializers import (
    CertificateAuthoritySerializer,
    ConversationSerializer,
    EncryptedMessageSerializer,
    KeyExchangeLogSerializer,
    MessageDeliveryStatusSerializer,
    MessageSerializer,
    PublicKeyExchangeSerializer,
    SessionKeySerializer,
    SharedKeySerializer,
    UserProfileSerializer,
    UserRegistrationSerializer,
    UserSerializer,
)

# RFC 3526 group 14 (2048-bit prime), DH private exponent uses 128-bit PRNG
DH_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF"
)
DH_P = int(DH_P_HEX, 16)
DH_G = 2
ROOT_CA_NAME = "ChatSeguro Root CA"

HASH_ALGORITHMS = {
    "sha256": hashes.SHA256,
    "sha512": hashes.SHA512,
    "sha3_256": hashes.SHA3_256,
    "sha3_512": hashes.SHA3_512,
}


# ----------------------------------------------------
# Helpers
# ----------------------------------------------------
def _canonical_json(data: dict) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _hash_algorithm(name: str):
    return HASH_ALGORITHMS.get((name or "sha256").lower())


def _generate_keys():
    # RSA 1024 to match the assignment requirement
    priv = rsa.generate_private_key(public_exponent=65537, key_size=1024, backend=default_backend())
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    # DH with 128-bit PRNG private value over RFC3526 group 14
    dh_priv = (int.from_bytes(os.urandom(16), "big") % (DH_P - 2)) + 2
    dh_pub = pow(DH_G, dh_priv, DH_P)

    return {
        "rsa_priv": priv_pem,
        "rsa_pub": pub_pem,
        "dh_priv": str(dh_priv),
        "dh_pub": str(dh_pub),
        "dh_p": str(DH_P),
        "dh_g": str(DH_G),
    }


def _sign_blob(private_pem: str, payload: bytes) -> bytes:
    private_key = serialization.load_pem_private_key(private_pem.encode(), password=None, backend=default_backend())
    return private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())


def _verify_blob(public_pem: str, signature: bytes, payload: bytes) -> bool:
    try:
        public_key = serialization.load_pem_public_key(public_pem.encode(), backend=default_backend())
        public_key.verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
        return True
    except (ValueError, InvalidSignature):
        return False


def _build_root_ca_material():
    ca_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    ca_pub = ca_priv.public_key()
    ca_priv_pem = ca_priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    ca_pub_pem = ca_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    now = timezone.now()
    cert_obj = {
        "subject": ROOT_CA_NAME,
        "issuer": ROOT_CA_NAME,
        "serial_number": secrets.token_hex(8),
        "valid_from": now.strftime("%Y-%m-%d"),
        "valid_to": (now + timedelta(days=3650)).strftime("%Y-%m-%d"),
        "signature_algorithm": "SHA256withRSA",
        "public_key": ca_pub_pem,
    }
    signature = base64.b64encode(_sign_blob(ca_priv_pem, _canonical_json(cert_obj).encode("utf-8"))).decode()
    ca_cert = json.dumps({"certificate": cert_obj, "signature": signature})
    return {
        "name": ROOT_CA_NAME,
        "ca_public_key": ca_pub_pem,
        "ca_private_key": ca_priv_pem,
        "ca_certificate": ca_cert,
        "is_root": True,
    }


def _ca_material_is_valid(ca: CertificateAuthority) -> bool:
    try:
        serialization.load_pem_private_key(ca.ca_private_key.encode(), password=None, backend=default_backend())
        serialization.load_pem_public_key(ca.ca_public_key.encode(), backend=default_backend())
    except Exception:
        return False

    try:
        cert_data = json.loads(ca.ca_certificate or "{}")
        cert_obj = cert_data.get("certificate", {})
        signature_b64 = cert_data.get("signature", "")
        payload = _canonical_json(cert_obj).encode("utf-8")
        signature = base64.b64decode(signature_b64 or "")
    except Exception:
        return False

    if cert_obj.get("public_key") != ca.ca_public_key:
        return False
    if cert_obj.get("issuer") != ca.name:
        return False
    if not signature:
        return False
    return _verify_blob(ca.ca_public_key, signature, payload)


def _get_or_create_root_ca(force_rotate: bool = False) -> CertificateAuthority:
    ca = CertificateAuthority.objects.filter(is_root=True).first()
    if not ca:
        material = _build_root_ca_material()
        return CertificateAuthority.objects.create(**material)

    if force_rotate or not _ca_material_is_valid(ca):
        material = _build_root_ca_material()
        ca.name = material["name"]
        ca.ca_public_key = material["ca_public_key"]
        ca.ca_private_key = material["ca_private_key"]
        ca.ca_certificate = material["ca_certificate"]
        ca.is_root = True
        ca.save(update_fields=["name", "ca_public_key", "ca_private_key", "ca_certificate", "is_root"])
        return ca

    return ca


def _issue_certificate_for_profile(profile: UserProfile, days: int = 365):
    ca = _get_or_create_root_ca()
    now = timezone.now()
    cert_obj = {
        "subject": profile.user.username,
        "issuer": ca.name,
        "serial_number": secrets.token_hex(8),
        "valid_from": now.strftime("%Y-%m-%d"),
        "valid_to": (now + timedelta(days=days)).strftime("%Y-%m-%d"),
        "signature_algorithm": "SHA256withRSA",
        "public_key": profile.public_key_rsa,
    }
    try:
        signature = base64.b64encode(_sign_blob(ca.ca_private_key, _canonical_json(cert_obj).encode("utf-8"))).decode()
    except Exception:
        # Handles legacy/corrupted CA rows by rotating the root material and retrying once.
        ca = _get_or_create_root_ca(force_rotate=True)
        signature = base64.b64encode(_sign_blob(ca.ca_private_key, _canonical_json(cert_obj).encode("utf-8"))).decode()
    profile.certificate = json.dumps({"certificate": cert_obj, "signature": signature})
    profile.certificate_issuer = ca.name
    profile.certificate_serial = cert_obj["serial_number"]
    profile.certificate_valid_from = now
    profile.certificate_valid_to = now + timedelta(days=days)
    profile.save(
        update_fields=[
            "certificate",
            "certificate_issuer",
            "certificate_serial",
            "certificate_valid_from",
            "certificate_valid_to",
        ]
    )


def _ensure_profile(user: User) -> UserProfile:
    try:
        profile = UserProfile.objects.get(user=user)
    except UserProfile.DoesNotExist:
        keys = _generate_keys()
        profile = UserProfile.objects.create(
            user=user,
            public_key_rsa=keys["rsa_pub"],
            private_key_rsa=keys["rsa_priv"],
            dh_public_key=keys["dh_pub"],
            dh_private_key=keys["dh_priv"],
            dh_prime=keys["dh_p"],
            dh_generator=keys["dh_g"],
        )
        _issue_certificate_for_profile(profile)
        return profile

    if not profile.dh_private_key or not profile.dh_public_key:
        keys = _generate_keys()
        profile.dh_public_key = keys["dh_pub"]
        profile.dh_private_key = keys["dh_priv"]
        profile.dh_prime = keys["dh_p"]
        profile.dh_generator = keys["dh_g"]
        profile.save(update_fields=["dh_public_key", "dh_private_key", "dh_prime", "dh_generator"])

    if not profile.certificate:
        _issue_certificate_for_profile(profile)
    else:
        cert_ok, cert_reason = _verify_profile_certificate(profile)
        # Auto-migrate old self-signed/invalid certs to CA-signed certs.
        if (not cert_ok) and cert_reason != "revoked":
            _issue_certificate_for_profile(profile)

    return profile


def _certificate_valid(certificate_json: str):
    try:
        data = json.loads(certificate_json)
        cert = data.get("certificate", {})
        valid_from = datetime.strptime(cert.get("valid_from"), "%Y-%m-%d").date()
        valid_to = datetime.strptime(cert.get("valid_to"), "%Y-%m-%d").date()
        today = timezone.now().date()
        return valid_from <= today <= valid_to
    except Exception:
        return False


def _is_revoked(profile: UserProfile, certificate_serial: str = "") -> bool:
    revoked_qs = RevokedCertificate.objects.filter(user_profile=profile)
    if certificate_serial:
        revoked_qs = revoked_qs.filter(certificate_serial=certificate_serial)
    return revoked_qs.exists()


def _verify_signature(public_pem: str, signature_b64: str, message_hash_hex: str, alg: str = "sha256"):
    """Verifies RSA PKCS#1 v1.5 signature over hash bytes.

    Supports two client behaviors:
    - Prehashed signing (sign raw digest bytes as prehashed)
    - WebCrypto style (sign digest bytes with algorithm hash, effectively hashing again)
    """
    hash_cls = _hash_algorithm(alg)
    if not hash_cls:
        return False

    try:
        public_key = serialization.load_pem_public_key(public_pem.encode(), backend=default_backend())
        hash_bytes = bytes.fromhex(message_hash_hex)
        signature = base64.b64decode(signature_b64)
    except (ValueError, TypeError):
        return False

    try:
        public_key.verify(signature, hash_bytes, padding.PKCS1v15(), utils.Prehashed(hash_cls()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        pass

    try:
        public_key.verify(signature, hash_bytes, padding.PKCS1v15(), hash_cls())
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _verify_profile_certificate(profile: UserProfile):
    if not profile.certificate:
        return False, "missing_certificate"

    if not _certificate_valid(profile.certificate):
        return False, "expired_or_invalid"

    ca = _get_or_create_root_ca()
    try:
        cert_data = json.loads(profile.certificate)
        cert_obj = cert_data.get("certificate", {})
        signature_b64 = cert_data.get("signature", "")
    except Exception:
        return False, "parse_error"

    cert_serial = cert_obj.get("serial_number") or profile.certificate_serial
    if _is_revoked(profile, cert_serial):
        return False, "revoked"

    if cert_obj.get("issuer") != ca.name:
        return False, "issuer_mismatch"

    if cert_obj.get("public_key") != profile.public_key_rsa:
        return False, "public_key_mismatch"

    payload = _canonical_json(cert_obj).encode("utf-8")
    signature = base64.b64decode(signature_b64 or "") if signature_b64 else b""
    if not signature or not _verify_blob(ca.ca_public_key, signature, payload):
        return False, "invalid_signature"

    return True, "ok"


def _derive_dh_shared(sender_profile: UserProfile, recipient_profile: UserProfile):
    sender_priv = int(sender_profile.dh_private_key)
    recipient_pub = int(recipient_profile.dh_public_key)
    shared = pow(recipient_pub, sender_priv, DH_P)
    shared_bytes = shared.to_bytes((shared.bit_length() + 7) // 8 or 1, "big")
    digest = hashlib.sha256(shared_bytes).digest()
    return shared, digest


# ----------------------------------------------------
# Auth / profile
# ----------------------------------------------------
@csrf_exempt
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_my_keys(request):
    profile = _ensure_profile(request.user)
    return Response(
        {
            "rsa_public_key": profile.public_key_rsa,
            "rsa_private_key": profile.private_key_rsa,
            "dh_public_key": profile.dh_public_key,
            "dh_private_key": profile.dh_private_key,
            "certificate": profile.certificate,
        }
    )


@csrf_exempt
@api_view(["POST"])
@permission_classes([AllowAny])
def register_user(request):
    serializer = UserRegistrationSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    user = serializer.save()
    keys = _generate_keys()
    profile = UserProfile.objects.create(
        user=user,
        public_key_rsa=keys["rsa_pub"],
        private_key_rsa=keys["rsa_priv"],
        dh_public_key=keys["dh_pub"],
        dh_private_key=keys["dh_priv"],
        dh_prime=keys["dh_p"],
        dh_generator=keys["dh_g"],
    )
    _issue_certificate_for_profile(profile)

    return Response(
        {"message": "Usuario registrado com sucesso", "user": UserSerializer(user).data},
        status=status.HTTP_201_CREATED,
    )


@csrf_exempt
@api_view(["POST"])
@permission_classes([AllowAny])
def login_user(request):
    user = authenticate(username=request.data.get("username"), password=request.data.get("password"))
    if not user:
        return Response({"error": "Credenciais invalidas"}, status=status.HTTP_401_UNAUTHORIZED)
    login(request, user)
    return Response({"message": "Login realizado com sucesso", "user": UserSerializer(user).data})


@csrf_exempt
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def logout_user(request):
    logout(request)
    return Response({"message": "Logout realizado com sucesso"})


@csrf_exempt
@api_view(["GET", "PATCH", "PUT"])
@permission_classes([IsAuthenticated])
def get_user_profile(request):
    profile = _ensure_profile(request.user)

    if request.method in ["PATCH", "PUT"]:
        data = request.data or {}
        user = request.user
        changed = False
        for field in ["username", "email", "first_name", "last_name"]:
            if field in data:
                setattr(user, field, data[field])
                changed = True
        if changed:
            user.save()

    profile = _ensure_profile(request.user)
    return Response(UserProfileSerializer(profile).data)


@csrf_exempt
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def list_users(request):
    users = User.objects.exclude(id=request.user.id)
    return Response(UserSerializer(users, many=True).data)


@csrf_exempt
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_public_key(request, user_id):
    try:
        target_user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({"error": "Usuario nao encontrado"}, status=status.HTTP_404_NOT_FOUND)

    profile = _ensure_profile(target_user)
    valid, reason = _verify_profile_certificate(profile)
    return Response(
        {
            "user_id": user_id,
            "public_key_rsa": profile.public_key_rsa,
            "dh_public_key": profile.dh_public_key,
            "certificate": profile.certificate,
            "certificate_valid": valid,
            "certificate_reason": reason,
        }
    )


@csrf_exempt
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def exchange_public_keys(request):
    serializer = PublicKeyExchangeSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    recipient_id = serializer.validated_data["recipient_id"]
    try:
        recipient_profile = UserProfile.objects.get(user_id=recipient_id)
        sender_profile = _ensure_profile(request.user)
    except UserProfile.DoesNotExist:
        return Response({"error": "Destinatario nao encontrado"}, status=status.HTTP_404_NOT_FOUND)

    shared, digest = _derive_dh_shared(sender_profile, recipient_profile)
    shared_hash = hashlib.sha256(str(shared).encode("utf-8")).hexdigest()

    KeyExchangeLog.objects.create(
        user1=request.user,
        user2_id=recipient_id,
        exchange_type="dh",
        parameters_used={
            "sender_rsa_key": serializer.validated_data.get("public_key"),
            "recipient_rsa_key": recipient_profile.public_key_rsa,
            "dh_public_sender": sender_profile.dh_public_key,
            "dh_public_recipient": recipient_profile.dh_public_key,
            "dh_prime": str(DH_P),
            "dh_generator": str(DH_G),
            "shared_hash": shared_hash,
        },
        status="success",
    )

    return Response(
        {
            "message": "Chaves trocadas com sucesso",
            "recipient_public_key": recipient_profile.public_key_rsa,
            "recipient_dh_key": recipient_profile.dh_public_key,
            "recipient_certificate": recipient_profile.certificate,
            "dh_shared_fingerprint": base64.b64encode(digest).decode()[:32],
        }
    )


# ----------------------------------------------------
# Conversas / mensagens
# ----------------------------------------------------
class ConversationViewSet(viewsets.ModelViewSet):
    serializer_class = ConversationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Conversation.objects.filter(participants=self.request.user).order_by("-updated_at")

    def perform_create(self, serializer):
        conversation = serializer.save()
        conversation.participants.add(self.request.user)

    @action(detail=True, methods=["get"])
    def messages(self, request, pk=None):
        conversation = self.get_object()
        messages = Message.objects.filter(conversation=conversation).order_by("timestamp")
        serializer = MessageSerializer(messages, many=True, context={"request": request})
        return Response(serializer.data)


class MessageViewSet(viewsets.ModelViewSet):
    serializer_class = MessageSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return (
            Message.objects.filter(conversation__participants=self.request.user)
            .select_related("conversation", "sender")
            .order_by("-timestamp")
        )

    def perform_create(self, serializer):
        serializer.save(sender=self.request.user)


@csrf_exempt
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def send_encrypted_message(request):
    serializer = EncryptedMessageSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    conv_id = serializer.validated_data["conversation_id"]
    try:
        conversation = Conversation.objects.get(id=conv_id, participants=request.user)
    except Conversation.DoesNotExist:
        return Response({"error": "Conversa nao encontrada"}, status=status.HTTP_404_NOT_FOUND)

    sender_profile = _ensure_profile(request.user)
    sender_cert_ok, sender_cert_reason = _verify_profile_certificate(sender_profile)
    if not sender_cert_ok:
        return Response(
            {"error": "Certificado do remetente invalido", "reason": sender_cert_reason},
            status=status.HTTP_400_BAD_REQUEST,
        )

    recipients = list(conversation.participants.exclude(id=request.user.id))
    for recipient in recipients:
        recipient_profile = _ensure_profile(recipient)
        valid, reason = _verify_profile_certificate(recipient_profile)
        if not valid:
            return Response(
                {"error": "Certificado do destinatario invalido", "recipient_id": recipient.id, "reason": reason},
                status=status.HTTP_400_BAD_REQUEST,
            )

    sig_ok = _verify_signature(
        sender_profile.public_key_rsa,
        serializer.validated_data.get("digital_signature", ""),
        serializer.validated_data.get("message_hash", ""),
        serializer.validated_data.get("hash_algorithm", "sha256"),
    )
    if not sig_ok:
        return Response({"error": "Assinatura invalida ou hash incorreto"}, status=status.HTTP_400_BAD_REQUEST)

    msg = Message.objects.create(
        conversation=conversation,
        sender=request.user,
        encrypted_content=serializer.validated_data["encrypted_content"],
        encrypted_session_key=serializer.validated_data.get("encrypted_session_key", ""),
        digital_signature=serializer.validated_data.get("digital_signature", ""),
        hash_algorithm=serializer.validated_data.get("hash_algorithm", "sha256"),
        message_hash=serializer.validated_data.get("message_hash", ""),
        message_type=serializer.validated_data.get("message_type", "text"),
        file_name=serializer.validated_data.get("file_name", ""),
        file_size=serializer.validated_data.get("file_size"),
        mime_type=serializer.validated_data.get("mime_type", ""),
    )

    for recipient in recipients:
        MessageDeliveryStatus.objects.get_or_create(
            message=msg,
            recipient=recipient,
            defaults={"status": "sent", "individual_session_key": serializer.validated_data.get("encrypted_session_key", "")},
        )

    if recipients:
        KeyExchangeLog.objects.create(
            user1=request.user,
            user2=recipients[0],
            exchange_type="hybrid",
            parameters_used={
                "message_id": msg.id,
                "message_type": msg.message_type,
                "hash_algorithm": msg.hash_algorithm,
                "has_encrypted_session_key": bool(msg.encrypted_session_key),
                "pgp_style": True,
            },
            status="success",
        )

    return Response(
        {
            "message_id": msg.id,
            "timestamp": msg.timestamp,
            "verification": {
                "signature_ok": sig_ok,
                "sender_certificate_ok": sender_cert_ok,
            },
        }
    )


@csrf_exempt
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def mark_message_as_read(request, message_id):
    try:
        msg = Message.objects.get(id=message_id, conversation__participants=request.user)
    except Message.DoesNotExist:
        return Response({"error": "Mensagem nao encontrada"}, status=status.HTTP_404_NOT_FOUND)
    msg.is_read = True
    msg.save(update_fields=["is_read"])
    return Response({"message": "Mensagem marcada como lida"})


# ----------------------------------------------------
# Sessao / key agreement
# ----------------------------------------------------
@csrf_exempt
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def establish_session_key(request):
    recipient_id = request.data.get("user2")
    if not recipient_id:
        return Response({"error": "Campo user2 e obrigatorio"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        recipient = User.objects.get(id=recipient_id)
    except User.DoesNotExist:
        return Response({"error": "Destinatario nao encontrado"}, status=status.HTTP_404_NOT_FOUND)

    if recipient.id == request.user.id:
        return Response({"error": "Nao e permitido abrir sessao consigo mesmo"}, status=status.HTTP_400_BAD_REQUEST)

    sender_profile = _ensure_profile(request.user)
    recipient_profile = _ensure_profile(recipient)
    shared, digest = _derive_dh_shared(sender_profile, recipient_profile)

    session_key_encrypted = base64.b64encode(digest).decode()
    expires_at = timezone.now() + timedelta(hours=1)

    user1, user2 = (request.user, recipient) if request.user.id < recipient.id else (recipient, request.user)
    session, _ = SessionKey.objects.update_or_create(
        user1=user1,
        user2=user2,
        is_active=True,
        defaults={
            "session_key_encrypted": session_key_encrypted,
            "dh_shared_secret": str(shared),
            "dh_prime_used": str(DH_P),
            "dh_generator_used": str(DH_G),
            "expires_at": expires_at,
        },
    )

    KeyExchangeLog.objects.create(
        user1=request.user,
        user2=recipient,
        exchange_type="dh",
        parameters_used={
            "dh_prime": str(DH_P),
            "dh_generator": str(DH_G),
            "sender_dh_public": sender_profile.dh_public_key,
            "recipient_dh_public": recipient_profile.dh_public_key,
            "shared_hash": hashlib.sha256(str(shared).encode("utf-8")).hexdigest(),
        },
        status="success",
    )

    return Response(
        {
            "session_id": session.id,
            "session_key_encrypted": session.session_key_encrypted,
            "expires_at": session.expires_at,
            "algorithm": "DH(128-bit private) + SHA-256 derivation",
        }
    )


@csrf_exempt
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_key_exchange_history(request):
    logs = KeyExchangeLog.objects.filter(Q(user1=request.user) | Q(user2=request.user)).order_by("-timestamp")
    return Response(KeyExchangeLogSerializer(logs, many=True).data)


# ----------------------------------------------------
# Hash / lab
# ----------------------------------------------------
@csrf_exempt
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def compute_hash(request):
    data = request.data.get("data", "")
    algorithm = (request.data.get("algorithm") or "sha256").lower().replace("-", "_")
    if algorithm not in ["sha256", "sha512", "sha3_256", "sha3_512"]:
        return Response({"error": "Algoritmo nao suportado"}, status=status.HTTP_400_BAD_REQUEST)

    h = hashlib.new(algorithm.replace("_", ""))
    h.update(data.encode("utf-8"))
    return Response({"hash": h.hexdigest()})


@csrf_exempt
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def lab_rsa(request):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=1024, backend=default_backend())
    pub = priv.public_key()
    pem_pub = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    pem_priv = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return Response(
        {
            "public_key": pem_pub.decode(),
            "private_key": pem_priv.decode(),
            "fingerprint_sha256": hashlib.sha256(pem_pub).hexdigest(),
        }
    )


@csrf_exempt
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def lab_diffie_hellman(request):
    a_priv = (int.from_bytes(os.urandom(16), "big") % (DH_P - 2)) + 2
    b_priv = (int.from_bytes(os.urandom(16), "big") % (DH_P - 2)) + 2
    A = pow(DH_G, a_priv, DH_P)
    B = pow(DH_G, b_priv, DH_P)
    shared_a = pow(B, a_priv, DH_P)
    shared_b = pow(A, b_priv, DH_P)
    shared = shared_a if shared_a == shared_b else 0
    shared_bytes = shared.to_bytes((shared.bit_length() + 7) // 8 or 1, "big")
    shared_hash = hashlib.sha256(shared_bytes).hexdigest()
    return Response(
        {
            "P_hex": hex(DH_P)[:64],
            "G_hex": hex(DH_G),
            "A_hex": hex(A)[:64],
            "B_hex": hex(B)[:64],
            "shared_hex": hex(shared)[:64],
            "shared_hash_sha256": shared_hash,
            "private_size_bits": 128,
        }
    )


@csrf_exempt
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def lab_hybrid(request):
    plaintext = request.data.get("plaintext", "")
    key = os.urandom(32)
    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    cipher = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)
    rsa_pub = rsa.generate_private_key(public_exponent=65537, key_size=1024, backend=default_backend()).public_key()
    wrapped_key = rsa_pub.encrypt(
        key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return Response(
        {
            "cipher_base64": base64.b64encode(cipher).decode(),
            "iv_hex": iv.hex(),
            "wrapped_key_base64": base64.b64encode(wrapped_key).decode(),
            "rsa_public_key": rsa_pub.public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode(),
        }
    )


@csrf_exempt
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def lab_pki(request):
    ca = _get_or_create_root_ca()
    profile = _ensure_profile(request.user)
    valid, reason = _verify_profile_certificate(profile)
    return Response(
        {
            "ca_certificate": ca.ca_certificate,
            "user_certificate": profile.certificate,
            "verification": {"valid": valid, "reason": reason},
        }
    )


# ----------------------------------------------------
# PKI endpoints
# ----------------------------------------------------
@csrf_exempt
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def verify_certificate(request, user_id):
    try:
        target_user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({"valid": False, "reason": "profile_not_found"}, status=404)

    profile = _ensure_profile(target_user)
    valid, reason = _verify_profile_certificate(profile)
    payload = {"valid": valid, "reason": reason}
    if profile.certificate:
        try:
            cert_obj = json.loads(profile.certificate).get("certificate", {})
            payload["issuer"] = cert_obj.get("issuer")
            payload["subject"] = cert_obj.get("subject")
            payload["valid_to"] = cert_obj.get("valid_to")
        except Exception:
            pass
    return Response(payload)


@csrf_exempt
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def revoke_certificate(request, user_id):
    try:
        profile = UserProfile.objects.get(user_id=user_id)
    except UserProfile.DoesNotExist:
        return Response({"error": "Perfil nao encontrado"}, status=404)

    ca = _get_or_create_root_ca()
    try:
        cert_obj = json.loads(profile.certificate).get("certificate", {}) if profile.certificate else {}
    except Exception:
        cert_obj = {}

    serial = cert_obj.get("serial_number") or profile.certificate_serial or secrets.token_hex(8)
    reason = request.data.get("reason", "revoked")

    revoked, created = RevokedCertificate.objects.get_or_create(
        user_profile=profile,
        certificate_serial=serial,
        defaults={
            "revocation_reason": reason,
            "revoked_by": ca,
        },
    )

    if not created:
        revoked.revocation_reason = reason
        revoked.revoked_by = ca
        revoked.save(update_fields=["revocation_reason", "revoked_by"])

    return Response({"message": "Certificado revogado", "user_id": user_id, "serial": serial})


# ----------------------------------------------------
# Participantes
# ----------------------------------------------------
@csrf_exempt
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_conversation_participants(request, conversation_id):
    try:
        conv = Conversation.objects.get(id=conversation_id, participants=request.user)
    except Conversation.DoesNotExist:
        return Response({"error": "Conversa nao encontrada"}, status=status.HTTP_404_NOT_FOUND)
    users = conv.participants.all()
    return Response(UserSerializer(users, many=True).data)
