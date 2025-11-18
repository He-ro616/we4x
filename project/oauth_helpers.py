# project/oauth_helpers.py
from flask_login import current_user
from .models import OAuthToken, db
from authlib.integrations.flask_client import OAuth

# Global OAuth instance
oauth = OAuth()

# ------------------------
# Token Helpers
# ------------------------
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


# ------------------------
# Initialize OAuth
# ------------------------
def init_oauth(app):
    scopes = ['openid', 'email', 'profile']
    oauth.init_app(app)
    oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={
            'scope': ' '.join(scopes),
            'access_type': 'offline',  # allows refresh tokens
            'prompt': 'consent'        # ensures consent each time
        }
    )
