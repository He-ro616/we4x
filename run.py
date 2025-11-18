import sys
import os
from flask import render_template, url_for
from flask_migrate import Migrate

# Ensure the project folder is in Python's path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

try:
    from project import create_app, db
except ModuleNotFoundError as e:
    print("ERROR: Could not import 'project'. Make sure 'project/' exists and contains '__init__.py'.")
    raise e

# Create Flask app
app = create_app()

# Initialize Flask-Migrate
migrate = Migrate(app, db)

# =========================
# Routes
# =========================

@app.route('/')
def index():
    """Homepage — no sample events or posts."""
    # Default banner image URL (replace with your static or uploaded image path)
    banner_image_url = url_for('static', filename='images/default_banner.jpg')

    return render_template(
        'index.html',
        banner_image_url=banner_image_url,
        events=[],   # Empty list
        posts=[]     # Empty list
    )


# Optional: redirect logged-in users to dashboard (if using Flask-Login)
@app.route('/dashboard')
def dashboard():
    return "Dashboard placeholder — implement your dashboard here."


# =========================
# Main entry
# =========================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
