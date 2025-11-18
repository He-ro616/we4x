# project/blueprints/auth.py
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, session
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy.orm import joinedload
from datetime import datetime
from project.models import db, User, Event, Post, Comment
from project.oauth_helpers import oauth
from project.forms import LoginForm
from project.models import YoutubeLink

# extras for secure oauth handling
import secrets
from authlib.jose.errors import ExpiredTokenError
from authlib.integrations.base_client.errors import MismatchingStateError

# ---------------------------------------------
# Blueprint Setup
# ---------------------------------------------
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

# ---------------------------------------------
# LOGIN PAGE
# ---------------------------------------------
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('auth.dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('auth.dashboard'))
        else:
            flash('Invalid email or password', 'danger')
    return render_template('login.html', form=form)

# ---------------------------------------------
# GOOGLE OAUTH LOGIN (robust: state, nonce, single-use)
# ---------------------------------------------
@auth_bp.route('/login/google')
def login_google():
    redirect_uri = url_for("auth.google_authorize", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@auth_bp.route('/login/google/authorize')
def google_authorize():
    try:
        token = oauth.google.authorize_access_token()

        user_info = oauth.google.parse_id_token(
            token,
            nonce=None,
            leeway=300   # allow 5 min system time difference
        )

        email = user_info.get("email")
        name = user_info.get("name")
        if not email:
            flash("Login failed: No email from Google", "danger")
            return redirect(url_for("auth.login"))

        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(
                email=email,
                name=name,
                google_id=user_info.get("sub"),
                role=current_app.config["ROLES"]["PUBLIC"]
            )
            db.session.add(user)

        db.session.commit()
        login_user(user)
        return redirect(url_for("auth.dashboard_public"))

    except MismatchingStateError:
        flash("Login failed: CSRF warning! Mismatching state. Please try again.", "danger")
        return redirect(url_for("auth.login"))
    except ExpiredTokenError:
        flash("Login failed: The authentication token expired. Please try again.", "danger")
        return redirect(url_for("auth.login"))
    except Exception as e:
        current_app.logger.error(f"OAuth ERROR: {e}")
        flash("An unexpected error occurred during login. Please try again.", "danger")
        return redirect(url_for("auth.login"))

# ---------------------------------------------
# LOGOUT
# ---------------------------------------------
@auth_bp.route('/logout')
@login_required
def logout():
    # clear session keys related to oauth and general session data
    session.clear()
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('auth.login'))

# ---------------------------------------------
# DASHBOARD REDIRECTOR
# ---------------------------------------------
@auth_bp.route('/dashboard')
@login_required
def dashboard():
    roles = current_app.config['ROLES']
    if current_user.role == roles['ADMIN']:
        return redirect(url_for('auth.dashboard_admin'))
    elif current_user.role == roles['TEAM']:
        return redirect(url_for('auth.dashboard_team'))
    else:
        return redirect(url_for('auth.dashboard_public'))

# ---------------------------------------------
# ADMIN DASHBOARD
# ---------------------------------------------
from datetime import datetime

@auth_bp.route('/dashboard/admin')
@login_required
def dashboard_admin():
    if current_user.role != current_app.config['ROLES']['ADMIN']:
        flash("Access denied: Admins only.", "danger")
        return redirect(url_for('auth.dashboard'))

    events = Event.query.all()
    posts = Post.query.options(joinedload(Post.author), joinedload(Post.comments)).order_by(Post.created_at.desc()).all()
    user_count = User.query.count()
    team_members = User.query.filter_by(role=current_app.config['ROLES']['TEAM']).all()
    team_count = len(team_members)

    return render_template(
        'dashboard_admin.html',
        events=events,
        posts=posts,
        user_count=user_count,
        team_count=team_count,
        team_members=team_members,
        now=datetime.utcnow()   # pass current time to template
    )

# ---------------------------------------------
# TEAM DASHBOARD
# ---------------------------------------------
@auth_bp.route('/dashboard/team')
@login_required
def dashboard_team():
    if current_user.role not in (current_app.config['ROLES']['TEAM'], current_app.config['ROLES']['ADMIN']):
        flash("Access denied: Team members only.", "danger")
        return redirect(url_for('auth.dashboard_public'))

    events = Event.query.filter_by(created_by=current_user.id).order_by(Event.start_datetime.desc()).all()
    team_members = User.query.filter_by(role=current_app.config['ROLES']['TEAM']).all()
    return render_template('dashboard_team.html', events=events, team_members=team_members)

# ---------------------------------------------
# PUBLIC DASHBOARD (with posts & events)
# ---------------------------------------------
from project.forms import PostForm, CommentForm
from werkzeug.utils import secure_filename
import os

@auth_bp.route('/dashboard/public')
@login_required
def dashboard_public():
    """Displays the public dashboard with all posts and events."""
    form = PostForm()
    posts = Post.query.options(joinedload(Post.author), joinedload(Post.comments)).order_by(Post.created_at.desc()).all()
    user_count = User.query.count()
    events = Event.query.filter(Event.start_datetime > datetime.utcnow()).order_by(Event.start_datetime).all()

    # Fetch YouTube link and convert to embed URL
    youtube_link_obj = YoutubeLink.query.first()
    raw_youtube_url = youtube_link_obj.url if youtube_link_obj else "https://www.youtube.com/watch?v=dQw4w9WgXcQ" # Default link

    # Convert regular YouTube URL to embed URL
    if "watch?v=" in raw_youtube_url:
        youtube_link = raw_youtube_url.replace("watch?v=", "embed/")
    elif "youtu.be/" in raw_youtube_url:
        youtube_link = raw_youtube_url.replace("youtu.be/", "www.youtube.com/embed/")
    else:
        youtube_link = raw_youtube_url # Assume it's already an embed URL or a fallback

    return render_template('dashboard_public.html', posts=posts, form=form, user_count=user_count, events=events, youtube_link=youtube_link)

@auth_bp.route('/post/create', methods=['GET', 'POST'])
@login_required
def create_post():
    """Handles the creation of a new post, including image uploads."""
    form = PostForm()
    if form.validate_on_submit():
        filename = None
        if form.post_image.data:
            filename = secure_filename(form.post_image.data.filename)
            upload_path = os.path.join(current_app.root_path, 'static/uploads', filename)
            form.post_image.data.save(upload_path)

        new_post = Post(
            title=form.title.data,
            content=form.content.data,
            post_image=filename,
            author_id=current_user.id
        )
        db.session.add(new_post)
        db.session.commit()
        flash("Post created successfully!", "success")
        return redirect(url_for('auth.dashboard_public'))

    # If form validation fails, redirect with errors
    for field, errors in form.errors.items():
        for error in errors:
            flash(f"Error in {getattr(form, field).label.text}: {error}", "danger")
    return redirect(url_for('auth.dashboard_public'))

@auth_bp.route('/post/<int:post_id>/like', methods=['POST'])
@login_required
def like_post(post_id):
    # Note: Liking functionality is not fully implemented in the database model.
    # This is a placeholder for future development.
    flash("Liking is not yet implemented.", "info")
    return redirect(url_for('auth.dashboard_public'))

@auth_bp.route('/post/<int:post_id>/comment', methods=['POST'])
@login_required
def comment_post(post_id):
    """Handles adding a comment to a post."""
    form = CommentForm()
    if form.validate_on_submit():
        new_comment = Comment(
            content=form.content.data,
            author_id=current_user.id,
            post_id=post_id
        )
        db.session.add(new_comment)
        db.session.commit()
        flash("Comment added!", "success")
    else:
        flash("Comment cannot be empty.", "warning")
    return redirect(url_for('auth.dashboard_public'))

@auth_bp.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    print(f"Current user role: {current_user.role}")
    print(f"Admin role: {current_app.config['ROLES']['ADMIN']}")
    if post.author_id != current_user.id and current_user.role != current_app.config['ROLES']['ADMIN']:
        flash('You are not authorized to delete this post.', 'danger')
        return redirect(url_for('auth.dashboard_public'))
    
    db.session.delete(post)
    db.session.commit()
    flash('Post deleted successfully.', 'success')
    return redirect(url_for('auth.dashboard_public'))

@auth_bp.route('/team/add', methods=['POST'])
@login_required
def add_team_member():
    if current_user.role != current_app.config['ROLES']['ADMIN']:
        flash('You are not authorized to perform this action.', 'danger')
        return redirect(url_for('auth.manage_team'))

    email = request.form.get('email')
    if not email:
        flash('Email is required.', 'danger')
        return redirect(url_for('auth.manage_team'))

    user = User.query.filter_by(email=email).first()
    if user:
        user.role = current_app.config['ROLES']['TEAM']
        db.session.commit()
        flash(f'User {email} updated to team member.', 'success')
    else:
        password = secrets.token_urlsafe(12)
        new_user = User(
            email=email,
            name=email.split('@')[0],
            role=current_app.config['ROLES']['TEAM']
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash(f'Team member {email} created with password: {password}', 'success')
    
    return redirect(url_for('auth.manage_team'))

@auth_bp.route('/team/remove/<int:user_id>', methods=['POST'])
@login_required
def remove_team_member(user_id):
    if current_user.role != current_app.config['ROLES']['ADMIN']:
        flash('You are not authorized to perform this action.', 'danger')
        return redirect(url_for('auth.manage_team'))

    user = User.query.get_or_404(user_id)
    user.role = current_app.config['ROLES']['PUBLIC']
    db.session.commit()
    flash(f'Team member {user.email} has been removed.', 'success')
    
    return redirect(url_for('auth.manage_team'))

@auth_bp.route('/team/password', methods=['GET'])
@login_required
def update_password_page():
    return render_template('update_password.html')


@auth_bp.route('/password/update', methods=['POST'])
@login_required
def update_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')

    if not current_password or not new_password:
        flash('Both fields are required.', 'danger')
        return redirect(url_for('auth.update_password_page'))

    if not current_user.check_password(current_password):
        flash('Invalid current password.', 'danger')
        return redirect(url_for('auth.update_password_page'))

    current_user.set_password(new_password)
    db.session.commit()
    flash('Password updated successfully.', 'success')
    return redirect(url_for('auth.update_password_page'))

@auth_bp.route('/admin/team')
@login_required
def manage_team():
    if current_user.role != current_app.config['ROLES']['ADMIN']:
        flash("Access denied: Admins only.", "danger")
        return redirect(url_for('auth.dashboard'))

    team_members = User.query.filter_by(role=current_app.config['ROLES']['TEAM']).all()
    return render_template('manage_team.html', team_members=team_members)

