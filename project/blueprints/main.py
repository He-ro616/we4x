from flask import Blueprint, render_template, redirect, url_for, current_app, flash, request
from flask_login import current_user, login_required
from sqlalchemy.exc import OperationalError
from ..models import Event, SiteConfig, db
from ..forms import SiteConfigForm
from werkzeug.utils import secure_filename
import os

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    """Homepage — show upcoming events and redirect logged-in users to their dashboard"""
    if current_user.is_authenticated:
        # Redirect automatically to dashboard
        return redirect(url_for('auth.dashboard'))
    
    db_error = None
    events = []
    banner_image_url = None

    try:
        events = Event.query.order_by(Event.start_datetime).limit(5).all()
        site_config = SiteConfig.get_current()
        # Use a banner image instead of YouTube link
        banner_image_url = getattr(site_config, 'banner_image', None) or url_for('static', filename='default_banner.jpg')
    except OperationalError as e:
        db_error = "⚠️ Cannot connect to database." if "getaddrinfo failed" in str(e) else str(e)
        current_app.logger.warning("Database issue: %s", e)
    
    return render_template(
        'index.html',
        events=events,
        db_error=db_error,
        banner_image_url=banner_image_url
    )

@main_bp.route('/admin/settings', methods=['GET', 'POST'])
@login_required
def admin_settings():
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('main.index'))

    form = SiteConfigForm()
    site_config = SiteConfig.get_current()

    if form.validate_on_submit():
        # Save banner URL
        site_config.banner_image = form.banner_url.data or site_config.banner_image

        # Handle uploaded file
        if form.banner_file.data:
            file = form.banner_file.data
            filename = secure_filename(file.filename)
            file.save(os.path.join(current_app.root_path, 'static', 'uploads', filename))
            site_config.banner_image = url_for('static', filename=f'uploads/{filename}')

        db.session.commit()
        flash('Site configuration updated successfully!', 'success')
        return redirect(url_for('main.admin_settings'))

    # Prefill form with current banner
    form.banner_url.data = getattr(site_config, 'banner_image', '')

    return render_template('admin_settings.html', form=form)

@main_bp.route('/about')
def about():
    """Simple About page"""
    return render_template('about.html')

@main_bp.route('/contact')
def contact():
    """Contact or feedback page"""
    return render_template('contact.html')

@main_bp.route('/products')
def products():
    """Products page."""
    return render_template('products.html')
