from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'conversations', views.ConversationViewSet, basename='conversation')
router.register(r'messages', views.MessageViewSet, basename='message')

urlpatterns = [
    # Autenticação
    path('register/', views.register_user, name='register'),
    path('login/', views.login_user, name='login'),
    path('logout/', views.logout_user, name='logout'),
    
    # Perfil e chaves
    path('profile/', views.get_user_profile, name='profile'),
    path('profile/keys/', views.get_my_keys, name='profile-keys'),
    path('public-key/<int:user_id>/', views.get_public_key, name='public-key'),
    path('exchange-keys/', views.exchange_public_keys, name='exchange-keys'),
    path('users/', views.list_users, name='list-users'),
    
    # Mensagens
    path('messages/send/', views.send_encrypted_message, name='send-message'),
    path('messages/<int:message_id>/read/', views.mark_message_as_read, name='mark-read'),
    
    # Sessões e troca de chaves
    path('session/establish/', views.establish_session_key, name='establish-session'),
    path('key-exchange/history/', views.get_key_exchange_history, name='key-history'),
    
    # PKI e certificados
    path('certificate/<int:user_id>/verify/', views.verify_certificate, name='verify-cert'),
    path('certificate/<int:user_id>/revoke/', views.revoke_certificate, name='revoke-cert'),
    
    # Hash
    path('hash/compute/', views.compute_hash, name='compute-hash'),
    
    # Laboratório criptográfico (alinhado com o frontend)
    path('lab/rsa/', views.lab_rsa, name='lab-rsa'),
    path('lab/dh/', views.lab_diffie_hellman, name='lab-dh'),
    path('lab/hybrid/', views.lab_hybrid, name='lab-hybrid'),
    path('lab/pki/', views.lab_pki, name='lab-pki'),
    
    # Conversas (inclui rotas do router)
    path('', include(router.urls)),
    path('conversations/<int:conversation_id>/participants/', 
         views.get_conversation_participants, name='conversation-participants'),
]
