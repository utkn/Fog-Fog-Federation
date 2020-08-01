from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oidc.core.grants import (
    OpenIDCode as _OpenIDCode,
    OpenIDImplicitGrant as _OpenIDImplicitGrant,
    OpenIDHybridGrant as _OpenIDHybridGrant,
)

global_vidp = None

class AuthorizationCodeGrant(_AuthorizationCodeGrant):
    def create_authorization_code(self, client, grant_user, request):
        return global_vidp.create_authorization_code(client, grant_user, request)

    def parse_authorization_code(self, code, client):
        return global_vidp.parse_authorization_code(code, client)

    def delete_authorization_code(self, authorization_code):
        return global_vidp.delete_authorization_code(authorization_code)

    def authenticate_user(self, authorization_code):
        return global_vidp.authenticate_user(authorization_code)


class OpenIDCode(_OpenIDCode):
    def exists_nonce(self, nonce, request):
        return global_vidp.exists_nonce(nonce, request)

    def get_jwt_config(self, grant):
        return global_vidp.get_jwt_config()

    def generate_user_info(self, user, scope):
        return global_vidp.generate_user_info(user, scope)


class ImplicitGrant(_OpenIDImplicitGrant):
    def exists_nonce(self, nonce, request):
        return global_vidp.exists_nonce(nonce, request)

    def get_jwt_config(self, grant):
        return global_vidp.get_jwt_config()

    def generate_user_info(self, user, scope):
        return global_vidp.generate_user_info(user, scope)


class HybridGrant(_OpenIDHybridGrant):
    def create_authorization_code(self, client, grant_user, request):
        return global_vidp.create_authorization_code(client, grant_user, request)

    def exists_nonce(self, nonce, request):
        return global_vidp.exists_nonce(nonce, request)

    def get_jwt_config(self, grant):
        return global_vidp.get_jwt_config()

    def generate_user_info(self, user, scope):
        return global_vidp.generate_user_info(user, scope)