from authlib.integrations.flask_client import OAuth
from flask import Flask, redirect, render_template, request, session, url_for

client_id = "017264"
proxy_addr = "http://localhost:5000/idp"

app = Flask(__name__)
app.secret_key = 'secret'

def initializeOAuth():
    oauth = OAuth()
    oauth.init_app(app)
    oauth.register(
        name='service', 
        # all the settings will be received from the proxy's configuration endpoint.
        server_metadata_url=proxy_addr + '/.well-known/openid-configuration',
        client_id=client_id,
        client_kwargs={
            'scope': 'openid profile'
        },
        overwrite=True
    )
    return oauth


@app.route('/')
def homepage():
    user = session.get('user')
    return render_template('home.html', user=user)


@app.route('/login', methods=['POST'])
def login():
    if 'proxy' in request.form:
        oauth = initializeOAuth()
        redirect_uri = url_for('auth', _external=True)
        return oauth.service.authorize_redirect(redirect_uri)
    return redirect(url_for('homepage'))


@app.route('/auth')
def auth():
    # in case of an error, simply report it instead of proceeding with authentication.
    if request.args.get('error'):
        error_desc = request.args.get('error_description')
        return render_template('home.html', error=error_desc)
    oauth = initializeOAuth()
    # get the unparsed token.
    token = oauth.service.authorize_access_token()
    # parse the token with the provider's public keys.
    user = oauth.service.parse_id_token(token)
    session['user'] = user
    return redirect('/')


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')
