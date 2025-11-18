from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, FileField, PasswordField
from wtforms.validators import DataRequired, Length, Email
from flask_wtf.file import FileAllowed

class LoginForm(FlaskForm):
    """Form for user login."""
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class PostForm(FlaskForm):
    """Form for creating a new post with optional image upload."""
    title = StringField('Title', validators=[DataRequired(), Length(min=1, max=255)])
    content = TextAreaField('Content', validators=[DataRequired()])
    post_image = FileField('Post Image', validators=[FileAllowed(['jpg', 'png', 'jpeg', 'gif'], 'Images only!')])
    submit = SubmitField('Create Post')

class CommentForm(FlaskForm):
    """Form for adding a comment to a post."""
    content = TextAreaField('Comment', validators=[DataRequired(), Length(min=1, max=1000)])
    submit = SubmitField('Add Comment')

from flask_wtf import FlaskForm
from wtforms import StringField, FileField, SubmitField
from wtforms.validators import Optional, URL

class SiteConfigForm(FlaskForm):
    banner_url = StringField('Banner Image URL', validators=[Optional(), URL()])
    banner_file = FileField('Upload Banner Image', validators=[Optional()])
    submit = SubmitField('Save')
