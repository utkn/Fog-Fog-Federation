from authlib.integrations.flask_client import OAuth
from authlib.jose import JWK_ALGORITHMS, JsonWebKey
from authlib.oauth2 import OAuth2Error
from flask import (Flask, jsonify, redirect, render_template, request, session,
                   url_for)

from virtualidp import (VirtualIdP, read_file, 
                        public_key as vidp_public_key, 
                        private_key as vidp_private_key)
from virtualrp import VirtualRP
from virtualuser import VirtualUser
from virtualsupplicant import VirtualSupplicant
from virtualpac import VirtualPaC
from proxy_models import *
import jwt

proxy_idp_address = 'http://0.0.0.0:5000/idp'

vuser = VirtualUser()
vrp = VirtualRP()
vidp = VirtualIdP()
vsupplicant = VirtualSupplicant('eth0')
vpac = VirtualPaC()

def create_app(config=None):
    app = Flask(__name__)

    # load default configuration
    app.config.from_object('settings')

    # load app sepcified configuration
    if config is not None:
        if isinstance(config, dict):
            app.config.update(config)
        elif config.endswith('.py'):
            app.config.from_pyfile(config)
    vidp.start_server(app)
    db.init_app(app)

    return app

app = create_app({
    'SECRET_KEY': 'secret',
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    'SQLALCHEMY_DATABASE_URI': 'sqlite:///db.sqlite',
})

# used to initialize the database from the command line.
@app.cli.command()
def initdb():
    from proxy_models import db
    # create the database
    db.create_all()
    # initialize the services preemptively
    a = HomeService(name='Home A', auth_type='OIDC', auth_endpoint='https://172.21.0.112:8000')
    b = HomeService(name='Home B', auth_type='802.1x', auth_endpoint='02:42:AC:17:00:70')
    c = HomeService(name='Home C', auth_type='PANA', auth_endpoint='172.25.0.113')
    db.session.add(OIDCService(client_id='017264', scope='openid', home_service=a))
    db.session.add(OneXService(home_service=b))
    db.session.commit()

def constructClient(idp_address, client_id, client_secret, scope):
    oauth = OAuth()
    oauth.init_app(app)
    oauth.register(
        name='service', 
        server_metadata_url=idp_address + '/.well-known/openid-configuration',
        client_id=client_id,
        client_secret=client_secret,
        client_kwargs={
            'scope': scope,
        },
        overwrite=True
    )
    return oauth    

# vRP login endpoint
@app.route('/rp/login')
def login():
    # construct the client
    oauth = constructClient(vrp.idp_address, vrp.client_id, vrp.client_secret, vrp.client_scope)
    # get the redirection url to the home idp consent page
    redirect_uri = url_for('auth', _external=True)
    return oauth.service.authorize_redirect(redirect_uri)

# vRP auth endpoint.
@app.route('/rp/auth', methods=['GET', 'POST'])
def auth():
    # reconstruct the client
    oauth = constructClient(vrp.idp_address, vrp.client_id, vrp.client_secret, vrp.client_scope)
    # acquire the token from the code
    token = oauth.service.authorize_access_token()
    # save the unparsed token received from the home idp.
    vrp.set_unparsed_token(token)
    user = oauth.service.parse_id_token(token)
    session['user'] = user
    return jsonify(user)

# vIdP authorization endpoint (where we issue the authorization codes.)
@app.route('/idp/authorize', methods=['GET', 'POST'])
def authorize():
    # first check whether the credentials were supplied. if not, request them.
    if not vidp.user:
        return redirect(url_for('receive_credentials', next=request.url))
    # generate the client according to the foreign RP's needs.
    vidp.generate_client(request.args.get('client_id'), request.referrer, \
                        request.args.get('redirect_uri'), request.args.get('scope'), request.args.get('response_type'))
    # try to log in with the virtual user + virtual RP or through the virtual supplicant.
    login_successful = False
    if session['auth_type'] == 'OIDC':
        login_successful = vuser.login(url_for('login', _external=True))
    elif session['auth_type'] == '802.1x':
        login_successful = vsupplicant.login()
    elif session['auth_type'] == 'PANA':
        login_successful = vpac.login()
    # if the login was not successful, remove the stored credentials.
    if not login_successful:
        vidp.remove_user()
        vuser.reset_credentials()
        vsupplicant.reset_credentials()
        return redirect(url_for('receive_credentials', next=request.url, error='Invalid credentials.'))
    # now, we will ask the user to give consent.
    if request.method == 'GET':
        try:
            grant = vidp.server.validate_consent_request(end_user=vidp.user)
        except OAuth2Error as error:
            return jsonify(dict(error.get_body()))
        return render_template('authorize.html', user=vidp.user, grant=grant)
    # happily accept the consent in the case of non-OIDC method, as we are already authenticated.
    if session['auth_type'] != 'OIDC' and request.form.get('confirm'):
        grant_user = vidp.user
    # in the case of OIDC, when the user consents, try to also give consent through the virtual user.
    elif request.form.get('confirm'):
        token = vuser.give_consent()
        if token is None:
            return "could not give consent"
        grant_user = vidp.user
    else:
        grant_user = None
    return vidp.server.create_authorization_response(grant_user=grant_user)

# vIdP log-in page.
@app.route('/idp/login', methods=['GET', 'POST'])
def receive_credentials():
    # if the credentials are provided, save them and redirect back to the idp authorization endpoint.
    if request.form.get('username') and request.form.get('password') and request.form.get('service'):
        username = request.form.get('username')
        password = request.form.get('password')
        service_id = request.form.get('service')
        service = HomeService.query.filter_by(id=service_id).first()
        # create a temporary user for the virtual provider
        vidp.generate_user(username)
        session['auth_type'] = service.auth_type
        if service.auth_type == 'OIDC':
            # set the credentials of the virtual user
            vuser.set_credentials(username, password)
            # assign the client information of home provider with the virtual RP.
            oidc_service = OIDCService.query.filter_by(home_service_id=service.id).first()
            vrp.set_idp(service.auth_endpoint)
            vrp.set_client_info(oidc_service.client_id, '', oidc_service.scope)
            return redirect(request.args.get('next'))
        elif service.auth_type == '802.1x':
            vsupplicant.set_credentials(username, password)
            return redirect(request.args.get('next'))
        elif service.auth_type == 'PANA':
            vpac.set_credentials(username, password)
            vpac.set_endpoint(service.auth_endpoint)
            return redirect(request.args.get('next'))

    # if the credentials are not yet provided, show the login form.
    return render_template('login.html', services=HomeService.query.all(), error=request.args.get('error'))

# vIdP token endpoint (where we issue the tokens.) 
@app.route('/idp/token', methods=['POST'])
def issue_token():
    # construct the unparsed token response.
    vidp_token_response = vidp.server.create_token_response()
    # after issuing the token, remove the credentials.
    vuser.reset_credentials()
    vuser.session.cookies.clear()
    vsupplicant.reset_credentials()
    vpac.reset_credentials()
    vidp.remove_user()
    return vidp_token_response

# vIdP discovery endpoint (where we publish the provider configuration, like supported signing methods.)
@app.route('/idp/.well-known/openid-configuration')
def openid_config():
    config = {
        'issuer': 'proxy',
        'authorization_endpoint': url_for('authorize', _external=True),
        'token_endpoint': url_for('issue_token', _external=True),
        'response_types_supported': ['code', 'code id_token'],
        'jwks_uri': url_for('jwks', _external=True),
        'id_token_signing_alg_values_supported': ['RS256'],
        'subject_types_supported': ['public'],
        # we only support 'none' for now.
        'token_endpoint_auth_methods_supported': ['none']
    }
    return jsonify(config)

# vIdP jwks endpoint (where we publish the public keys.)
@app.route('/idp/jwks')
def jwks():
    jwk_obj = JsonWebKey(algorithms=JWK_ALGORITHMS).dumps(key=vidp_public_key, kty='RSA')
    return jsonify(jwk_obj)
