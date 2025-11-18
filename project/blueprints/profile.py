from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from ..models import db, User
from werkzeug.utils import secure_filename
import os
from datetime import datetime
import traceback

# ------------------------
# Blueprint
# ------------------------
profile_bp = Blueprint('profile', __name__, url_prefix='/profile')


# ------------------------
# Helper: Handle Profile Picture Upload
# ------------------------
def handle_profile_upload():
    if 'profile_picture' in request.files:
        file = request.files['profile_picture']
        if file and file.filename:
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{current_user.id}_{timestamp}_{filename}"
            # Ensure upload folder exists
            upload_folder = current_app.config.get('UPLOAD_FOLDER', 'uploads')
            os.makedirs(upload_folder, exist_ok=True)
            file_path = os.path.join(upload_folder, filename)
            file.save(file_path)
            return filename
    return None


# ------------------------
# Route: Profile Setup / Edit
# ------------------------
@profile_bp.route('/setup', methods=['GET', 'POST'])
@login_required
def setup():
    if request.method == 'POST':
        try:
            # Update user profile
            current_user.name = request.form.get('name')
            current_user.headline = request.form.get('headline')
            current_user.bio = request.form.get('bio')
            current_user.company = request.form.get('company')
            current_user.position = request.form.get('position')
            current_user.location = request.form.get('location')
            current_user.website = request.form.get('website')
            current_user.linkedin_url = request.form.get('linkedin_url')
            current_user.skills = request.form.get('skills')

            # Handle profile picture
            filename = handle_profile_upload()
            if filename:
                current_user.profile_picture = filename

            current_user.profile_completed = True
            db.session.commit()  # Commit changes
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile.view', user_id=current_user.id))

        except Exception as e:
            db.session.rollback()  # Rollback if error occurs
            current_app.logger.error(f"Profile setup error: {e}")
            return f"<pre>Debug Error:\n{traceback.format_exc()}</pre>"

    return render_template('profile/setup.html', user=current_user)


# ------------------------
# Route: View Profile
# ------------------------
@profile_bp.route('/<int:user_id>')
def view(user_id):
    try:
        user = User.query.get_or_404(user_id)

        # Safely coerce relationship/query-like objects to lists so templates
        # that use len() or iterate over them do not fail on SQLAlchemy
        def _to_list(maybe_q):
            if maybe_q is None:
                return []
            # If object exposes .all() (typical for dynamic relationships / Query), use it
            try:
                if hasattr(maybe_q, 'all') and callable(getattr(maybe_q, 'all')):
                    return maybe_q.all()
                # If iterable (but not a string/bytes), convert to list
                if hasattr(maybe_q, '__iter__') and not isinstance(maybe_q, (str, bytes)):
                    return list(maybe_q)
            except Exception:
                current_app.logger.exception('Error converting relationship to list')
            return []

        e_attending = _to_list(getattr(user, 'events_attending', []))
        e_created = _to_list(getattr(user, 'events_created', []))

        # Pre-compute attendees counts on each event so templates can safely
        # render them without calling SQLAlchemy methods or using Python
        # builtin functions (like hasattr) that Jinja may not expose.
        def _attendees_count(ev):
            try:
                att = getattr(ev, 'attendees', None)
                if att is None:
                    return 0
                # If SQLAlchemy dynamic relationship, it may have .count()
                if hasattr(att, 'count') and callable(getattr(att, 'count')):
                    return int(att.count())
                # If it's iterable, return its length
                if hasattr(att, '__len__'):
                    return len(att)
            except Exception:
                current_app.logger.exception('Error getting attendees count for event id %s', getattr(ev, 'id', None))
            return 0

        for ev in e_attending + e_created:
            try:
                ev.attendees_count = _attendees_count(ev)
            except Exception:
                ev.attendees_count = 0

        return render_template(
            'profile/view.html',
            user=user,
            attending_events=e_attending,
            created_events=e_created
        )
    except Exception as e:
        return f"<pre>Debug Error:\n{traceback.format_exc()}</pre>"
