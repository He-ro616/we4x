import os
from dotenv import load_dotenv

load_dotenv()
basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    # -----------------------------
    # General Config
    # -----------------------------
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")
    DEBUG = os.getenv("FLASK_DEBUG", "1") == "1"

    # -----------------------------
    # Database Config
    # -----------------------------
    DATABASE_URL = os.getenv("DATABASE_URL")

    if DATABASE_URL:
        # Normalize Render URL
        if DATABASE_URL.startswith("postgres://"):
            DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://")

        # Ensure SSL mode is enabled on Render
        if "sslmode" not in DATABASE_URL:
            DATABASE_URL += "?sslmode=require"

        SQLALCHEMY_DATABASE_URI = DATABASE_URL
    else:
        # Local development fallback
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{os.path.join(basedir, '..', 'dev.db')}"

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # -----------------------------
    # OAuth / Google Config
    # -----------------------------
    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

    OAUTH_REDIRECT_URI = os.getenv(
        "OAUTH_REDIRECT_URI",
        "http://127.0.0.1:5000/auth/login/google/authorize"
    )

    # -----------------------------
    # Initial Admin/User Setup
    # -----------------------------
    INITIAL_ADMIN_EMAIL = os.getenv("INITIAL_ADMIN_EMAIL", "admin@example.com")

    # -----------------------------
    # Roles
    # -----------------------------
    ROLES = {
        "ADMIN": "admin",
        "TEAM": "team",
        "PUBLIC": "public",
        "VIEWER": "viewer"
    }

    # -----------------------------
    # Flask-Login
    # -----------------------------
    LOGIN_VIEW = "auth.login"
    LOGIN_MESSAGE_CATEGORY = "info"

    # -----------------------------
    # Uploads
    # -----------------------------
    UPLOAD_FOLDER = os.path.join(basedir, "static", "uploads")
