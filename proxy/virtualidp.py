import json
import time

from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.integrations.sqla_oauth2 import (create_query_client_func,
                                              create_save_token_func)
from authlib.oidc.core import UserInfo
from werkzeug.security import gen_salt

import virtualidp_grants
from oidc_models import OAuth2AuthorizationCode, OAuth2Client, User

def read_file(path):
    with open(path, 'r') as file:
        return file.read()

public_key = read_file('./keys/jwtRS256.key.pub')
private_key = read_file('./keys/jwtRS256.key')

JWT_CONFIG = {
    'key': private_key,
    'alg': 'RS256',
    'iss': 'proxy',
    'exp': 3600,
}

class VirtualIdP:
    def __init__(self):
        self.client = None
        self.token = None
        self.auth_code = None
        self.user = None
    
    def get_jwt_config(self):
        return JWT_CONFIG
    
    # generates a temporary user that will be used by the idp.
    def generate_user(self, username):
        self.user = User(id=0, username=username)
    
    # removes the stored temporary user.
    def remove_user(self):
        self.user = None

    # generates a temporary client that will be used by the idp.
    def generate_client(self, client_id, client_uri, redirect_uri, scope, resp_type):
        d = {
            'client_name': 'Foreign RP',
            'client_uri': client_uri,
            'grant_types': ['authorization_code'],
            'client_type': 'public',
            'redirect_uris': [redirect_uri],
            'response_types': [resp_type],
            'scope': scope,
            'token_endpoint_auth_method': 'none'
        }
        self.client = OAuth2Client(client_id=client_id, _client_metadata=json.dumps(d), user_id=0)
        self.client.client_id_issued_at = 0
        self.client.client_secret = ''

    def create_query_client_function(self):
        def query_client(client_id):
            if self.client is None or client_id != self.client.client_id:
                return None
            return self.client
        return query_client
        
    def create_save_token_function(self):
        def save_token(token, request):
            self.token = token
        return save_token
    
    def exists_nonce(self, nonce, r):
        return self.auth_code is not None and self.auth_code.nonce == nonce
    
    def generate_user_info(self, user, scope):
        return UserInfo(sub=str(user.id), name=user.username)
    
    def create_authorization_code(self, client, grant_user, request):
        code = gen_salt(48)
        nonce = request.data.get('nonce')
        self.auth_code = OAuth2AuthorizationCode(
            code=code,
            client_id=client.client_id,
            redirect_uri=request.redirect_uri,
            scope=request.scope,
            user_id=grant_user.id,
            nonce=nonce
        )
        return self.auth_code.code
    
    def parse_authorization_code(self, code, client):
        if self.auth_code is None:
            return None
        if self.auth_code.code == code and self.auth_code.client_id == client.client_id:
            return self.auth_code
        return None
    
    def delete_authorization_code(self, auth_code):
        if self.auth_code is not None and self.auth_code.code == auth_code.code:
            self.auth_code = None
    
    def authenticate_user(self, auth_code):
        if self.auth_code is not None and self.auth_code.user_id == self.user.get_user_id():
            return self.user
        return None
    
    def start_server(self, app):
        # register with the global vidp that will be used by the grants
        virtualidp_grants.global_vidp = self
        # create the authorization server
        self.server = AuthorizationServer()
        query_client = self.create_query_client_function()
        save_token = self.create_save_token_function()
        # initialize the authorization server.
        self.server.init_app(
            app,
            query_client=query_client,
            save_token=save_token
        )
        # support all openid grants
        self.server.register_grant(virtualidp_grants.AuthorizationCodeGrant, [
            virtualidp_grants.OpenIDCode(require_nonce=True),
        ])
        self.server.register_grant(virtualidp_grants.ImplicitGrant)
        self.server.register_grant(virtualidp_grants.HybridGrant)
