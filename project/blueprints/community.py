from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from project.models import db, Post, Message, Comment
from project.forms import PostForm, CommentForm

community_bp = Blueprint('community', __name__)

@community_bp.route('/posts')
@login_required
def post_list():
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template('post_list.html', posts=posts)

@community_bp.route('/posts/new', methods=['GET', 'POST'])
@login_required
def create_post():
    if current_user.role not in ['admin', 'team']:
        flash('You are not authorized to create a post.', 'danger')
        return redirect(url_for('community.post_list'))
    form = PostForm()
    if form.validate_on_submit():
        post = Post(title=form.title.data, content=form.content.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created!', 'success')
        return redirect(url_for('community.post_list'))
    return render_template('create_post.html', title='New Post', form=form)

@community_bp.route('/posts/<int:post_id>', methods=['GET', 'POST'])
@login_required
def post_detail(post_id):
    post = Post.query.get_or_404(post_id)
    form = CommentForm()
    if form.validate_on_submit():
        comment = Comment(content=form.content.data, post=post, author=current_user)
        db.session.add(comment)
        db.session.commit()
        flash('Your comment has been published.', 'success')
        return redirect(url_for('community.post_detail', post_id=post.id))
    comments = post.comments.order_by(Comment.created_at.asc()).all()
    return render_template('post_detail.html', title=post.title, post=post, comments=comments, form=form)
