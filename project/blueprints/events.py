from flask import Blueprint, request, render_template, flash, redirect, url_for, current_app
from flask_login import current_user, login_required
from ..models import db, Event, Registration
import dateutil.parser
from werkzeug.utils import secure_filename
import os
from datetime import datetime

events_bp = Blueprint('events', __name__)

# Helper: Handle Event Banner Upload
def handle_event_banner_upload():
    if 'banner_image' in request.files:
        file = request.files['banner_image']
        if file and file.filename:
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"event_{timestamp}_{filename}"
            upload_folder = current_app.config.get('UPLOAD_FOLDER', 'uploads')
            os.makedirs(upload_folder, exist_ok=True)
            file_path = os.path.join(upload_folder, filename)
            file.save(file_path)
            return filename
    return None

@events_bp.route('/create_event', methods=['GET','POST'])
@login_required
def create_event():
    if current_user.role not in (current_app.config['ROLES']['TEAM'], current_app.config['ROLES']['ADMIN']):
        flash('Only team/admin can create events', 'danger')
        return redirect(url_for('main.index'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form.get('description','')
        start = dateutil.parser.parse(request.form['start_datetime'])
        end = dateutil.parser.parse(request.form['end_datetime'])
        meet_link = request.form.get('meet_link')
        banner_image = handle_event_banner_upload()

        ev = Event(
            title=title,
            description=description,
            start_datetime=start,
            end_datetime=end,
            meet_link=meet_link,
            banner_image=banner_image,
            calendar_event_id=None,
            created_by=current_user.id
        )
        db.session.add(ev)
        db.session.commit()
        flash('Event created', 'success')
        return redirect(url_for('auth.dashboard_team'))

    return render_template('create_event.html')


@events_bp.route('/event/<int:event_id>')
def event_detail(event_id):
    ev = Event.query.get_or_404(event_id)
    regs = Registration.query.filter_by(event_id=ev.id).all()
    return render_template('event_detail.html', event=ev, regs=regs)


@events_bp.route('/register/<int:event_id>', methods=['POST'])
def register(event_id):
    ev = Event.query.get_or_404(event_id)
    reg = Registration(
        event_id=ev.id,
        user_name=request.form.get('name'),
        user_email=request.form.get('email')
    )
    db.session.add(reg)
    db.session.commit()
    flash('Registered successfully', 'success')
    return redirect(url_for('events.event_detail', event_id=event_id))

@events_bp.route('/event/<int:event_id>/delete', methods=['POST'])
@login_required
def delete_event(event_id):
    if current_user.role != current_app.config['ROLES']['ADMIN']:
        flash('You are not authorized to delete this event.', 'danger')
        return redirect(url_for('main.index'))
    
    event = Event.query.get_or_404(event_id)
    db.session.delete(event)
    db.session.commit()
    flash('Event deleted successfully.', 'success')
    return redirect(url_for('auth.dashboard_admin'))
