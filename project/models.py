from flask_login import UserMixin
from datetime import datetime
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
# project/models.py
from . import db

class YoutubeLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    link = db.Column(db.String(255), nullable=False)


# ---------------------------------------------------
# EVENT ATTENDEE ASSOCIATION TABLE
# ---------------------------------------------------
event_attendees = db.Table(
    'event_attendees',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True),
    db.Column('event_id', db.Integer, db.ForeignKey('event.id', ondelete='CASCADE'), primary_key=True),
    db.Column('registered_at', db.DateTime, default=datetime.utcnow),
    extend_existing=True
)


# ---------------------------------------------------
# USER MODEL
# ---------------------------------------------------
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    google_id = db.Column(db.String(255), unique=True, nullable=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(255))
    password_hash = db.Column(db.String(255))
    role = db.Column(db.String(20), default='viewer')

    headline = db.Column(db.String(255))
    bio = db.Column(db.Text)
    company = db.Column(db.String(255))
    position = db.Column(db.String(255))
    location = db.Column(db.String(255))
    website = db.Column(db.String(255))
    linkedin_url = db.Column(db.String(255))
    profile_picture = db.Column(db.String(255))
    skills = db.Column(db.Text)

    tokens = db.relationship(
        'OAuthToken',
        backref='user',
        uselist=False,
        cascade="all, delete-orphan"
    )

    events_created = db.relationship(
        'Event',
        backref=db.backref('creator', lazy='joined'),
        foreign_keys='Event.created_by',
        lazy='dynamic',
        cascade="all, delete-orphan"
    )

    events_attending = db.relationship(
        'Event',
        secondary=event_attendees,
        backref=db.backref('attendees', lazy='dynamic'),
        lazy='dynamic'
    )

    posts = db.relationship(
        'Post',
        backref='author',
        lazy='dynamic',
        cascade="all, delete-orphan"
    )

    comments = db.relationship(
        'Comment',
        backref='author',
        lazy='dynamic',
        cascade="all, delete-orphan"
    )

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    profile_completed = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.email}>"


# ---------------------------------------------------
# OAUTH TOKEN MODEL
# ---------------------------------------------------
class OAuthToken(db.Model):
    __tablename__ = 'oauth_token'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'))
    access_token = db.Column(db.Text)
    refresh_token = db.Column(db.Text)
    token_type = db.Column(db.String(50))
    expires_at = db.Column(db.Integer)
    scope = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<OAuthToken {self.name}>"


# ---------------------------------------------------
# EVENT MODEL
# ---------------------------------------------------
class Event(db.Model):
    __tablename__ = 'event'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    start_datetime = db.Column(db.DateTime, nullable=False)
    end_datetime = db.Column(db.DateTime, nullable=False)
    meet_link = db.Column(db.String(512))
    calendar_event_id = db.Column(db.String(255))
    created_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'))
    banner_image = db.Column(db.String(255))
    capacity = db.Column(db.Integer)
    event_type = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    registrations = db.relationship(
        'Registration',
        backref='event',
        lazy='select',
        cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<Event {self.title}>"


# ---------------------------------------------------
# REGISTRATION MODEL
# ---------------------------------------------------
class Registration(db.Model):
    __tablename__ = 'registration'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id', ondelete='CASCADE'), nullable=False)
    user_name = db.Column(db.String(255))
    user_email = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Registration {self.user_email}>"


# ---------------------------------------------------
# POST MODEL
# ---------------------------------------------------
class Post(db.Model):
    __tablename__ = 'post'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    post_image = db.Column(db.String(255))
    author_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    messages = db.relationship(
        'Message',
        backref='post',
        lazy='select',
        cascade="all, delete-orphan"
    )

    comments = db.relationship(
        'Comment',
        backref='post',
        lazy='select',
        cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<Post {self.title}>"


# ---------------------------------------------------
# MESSAGE MODEL
# ---------------------------------------------------
class Message(db.Model):
    __tablename__ = 'message'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id', ondelete='CASCADE'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Message {self.id}>"


# ---------------------------------------------------
# COMMENT MODEL
# ---------------------------------------------------
class Comment(db.Model):
    __tablename__ = 'comment'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'))
    post_id = db.Column(db.Integer, db.ForeignKey('post.id', ondelete='CASCADE'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Comment {self.id}>"


# ---------------------------------------------------
# SITE CONFIG MODEL (Updated for Banner)
# ---------------------------------------------------
class SiteConfig(db.Model):
    __tablename__ = 'site_config'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True, default=1)  # Singleton row
    banner_image = db.Column(db.String(512), nullable=True)   # Admin-controlled banner image

    @classmethod
    def get_current(cls):
        """Retrieve or create the single SiteConfig row."""
        config = cls.query.get(1)
        if not config:
            config = cls(id=1)
            db.session.add(config)
            db.session.commit()
        return config

    def __repr__(self):
        return f"<SiteConfig (ID: {self.id})>"

