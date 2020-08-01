class VirtualRP:
    def __init__(self):
        self.client_id = None
        self.client_scope = None
        self.client_secret = None
        self.idp_address = None
    
    def set_idp(self, address):
        self.idp_address = address

    def set_client_info(self, client_id, client_secret, scope):
        self.client_id = client_id
        self.client_secret = client_secret
        self.client_scope = scope
    
    def set_redirect_uri(self, redirect_uri):
        self.redirect_uri = redirect_uri

    def set_unparsed_token(self, token):
        self.unparsed_token = token
