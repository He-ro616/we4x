from flask_login import current_user
from .models import OAuthToken, db
from . import oauth  # global instance from __init__.py

def fetch_token(name):
    if not current_user.is_authenticated:
        return None
    token = OAuthToken.query.filter_by(name=name, user_id=current_user.id).first()
    return token.to_dict() if token else None

def update_token(name, token):
    if not current_user.is_authenticated:
        return
    tok = OAuthToken.query.filter_by(name=name, user_id=current_user.id).first()
    if not tok:
        tok = OAuthToken(name=name, user_id=current_user.id)
        db.session.add(tok)
    tok.access_token = token.get('access_token')
    tok.refresh_token = token.get('refresh_token', tok.refresh_token)
    tok.expires_at = token.get('expires_at')
    tok.scope = token.get('scope')
    db.session.commit()

def init_oauth(app):
    scopes = ['openid', 'email', 'profile']
    oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={
            'scope': ' '.join(scopes),
            'access_type': 'offline',  # 'offline' allows refresh tokens
            'prompt': 'consent'        # ensures user consent each time (needed for offline)
        },
        redirect_uri=app.config['OAUTH_REDIRECT_URI']  # explicitly set redirect URI
    )
