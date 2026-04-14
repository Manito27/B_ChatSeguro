from rest_framework.authentication import SessionAuthentication


class CsrfExemptSessionAuthentication(SessionAuthentication):
    """
    Session auth sem verificação CSRF (ambiente de laboratório/protótipo).
    Não use em produção.
    """

    def enforce_csrf(self, request):
        return
