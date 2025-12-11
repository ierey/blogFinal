

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database Models
post_contributors = db.Table('post_contributors',
                             db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
                             db.Column('post_id', db.Integer, db.ForeignKey('post.id'))
                             )


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    posts = db.relationship('Post', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)
    contributed_posts = db.relationship('Post', secondary=post_contributors, backref='contributors')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comments = db.relationship('Comment', backref='post', lazy=True, cascade='all, delete-orphan')


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Routes
@app.route('/')
def index():
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template('index.html', posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))


@app.route('/posts')
def posts():
    all_posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template('posts.html', posts=all_posts)


@app.route('/post/<int:post_id>')
def view_post(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('view_post.html', post=post)


@app.route('/post/new', methods=['GET', 'POST'])
@login_required
def new_post():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')

        post = Post(title=title, content=content, author=current_user)
        db.session.add(post)
        db.session.commit()

        flash('Post created successfully!', 'success')
        return redirect(url_for('view_post', post_id=post.id))

    return render_template('new_post.html')


@app.route('/post/<int:post_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)

    if post.author != current_user:
        flash('You can only edit your own posts', 'danger')
        return redirect(url_for('view_post', post_id=post_id))

    if request.method == 'POST':
        post.title = request.form.get('title')
        post.content = request.form.get('content')
        post.updated_at = datetime.utcnow()
        db.session.commit()

        flash('Post updated successfully!', 'success')
        return redirect(url_for('view_post', post_id=post_id))

    return render_template('edit_post.html', post=post)


@app.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)

    if post.author != current_user:
        flash('You can only delete your own posts', 'danger')
        return redirect(url_for('view_post', post_id=post_id))

    db.session.delete(post)
    db.session.commit()

    flash('Post deleted successfully!', 'success')
    return redirect(url_for('posts'))


@app.route('/post/<int:post_id>/comment', methods=['POST'])
@login_required
def add_comment(post_id):
    post = Post.query.get_or_404(post_id)
    content = request.form.get('content')

    comment = Comment(content=content, post=post, author=current_user)
    db.session.add(comment)
    db.session.commit()

    flash('Comment added successfully!', 'success')
    return redirect(url_for('view_post', post_id=post_id))


@app.route('/comment/<int:comment_id>/delete', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    post_id = comment.post_id

    if comment.author != current_user:
        flash('You can only delete your own comments', 'danger')
        return redirect(url_for('view_post', post_id=post_id))

    db.session.delete(comment)
    db.session.commit()

    flash('Comment deleted successfully!', 'success')
    return redirect(url_for('view_post', post_id=post_id))


@app.route('/users')
def users():
    all_users = User.query.all()
    return render_template('users.html', users=all_users)


@app.route('/user/<int:user_id>')
def user_profile(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('user_profile.html', user=user)


# API Endpoints for CRUD operations
@app.route('/api/posts', methods=['GET', 'POST'])
def api_posts():
    if request.method == 'GET':
        posts = Post.query.all()
        return jsonify([{
            'id': p.id,
            'title': p.title,
            'content': p.content,
            'author': p.author.username,
            'created_at': p.created_at.isoformat()
        } for p in posts])

    elif request.method == 'POST':
        data = request.get_json()
        post = Post(
            title=data['title'],
            content=data['content'],
            author_id=data['author_id']
        )
        db.session.add(post)
        db.session.commit()
        return jsonify({'id': post.id, 'message': 'Post created'}), 201


@app.route('/api/posts/<int:post_id>', methods=['GET', 'PUT', 'DELETE'])
def api_post(post_id):
    post = Post.query.get_or_404(post_id)

    if request.method == 'GET':
        return jsonify({
            'id': post.id,
            'title': post.title,
            'content': post.content,
            'author': post.author.username,
            'created_at': post.created_at.isoformat()
        })

    elif request.method == 'PUT':
        data = request.get_json()
        post.title = data.get('title', post.title)
        post.content = data.get('content', post.content)
        db.session.commit()
        return jsonify({'message': 'Post updated'})

    elif request.method == 'DELETE':
        db.session.delete(post)
        db.session.commit()
        return jsonify({'message': 'Post deleted'})


def init_db():
    with app.app_context():
        db.create_all()

        # Create sample data if database is empty
        if User.query.count() == 0:
            # Create sample users
            admin = User(username='admin', email='admin@blog.com')
            admin.set_password('admin123')

            john = User(username='john_doe', email='john@blog.com')
            john.set_password('password123')

            db.session.add_all([admin, john])
            db.session.commit()

            # Create sample post about Flask-Login
            sample_post = Post(
                title='Building Authentication with Flask-Login',
                content='''In building this blog application, one of the most critical features was implementing user authentication. I chose Flask-Login as the library to handle this functionality, and in this post, I'll discuss why I made this choice, the challenges I faced, and what alternatives exist.

**Why Flask-Login?**

Flask-Login is a lightweight library that provides user session management for Flask applications. It handles the common tasks of logging users in and out, remembering user sessions, and restricting pages to logged-in users. The library is well-maintained, extensively documented, and integrates seamlessly with Flask's architecture.

**Implementation Challenges**

The biggest challenge I encountered was setting up the password hashing correctly. Flask-Login doesn't handle password storage or verification—it only manages sessions. I had to use Werkzeug's security functions to hash passwords before storing them and verify them during login. Initially, I made the mistake of storing plain passwords, which would be a severe security vulnerability in a production application.

Another challenge was understanding the `@login_required` decorator. While it's simple to use, configuring the login_manager's `login_view` property correctly took some trial and error. If not set properly, users are redirected to the wrong page when trying to access protected routes.

**Alternative Options**

There are several alternatives to Flask-Login:

1. **Flask-User**: This is a more comprehensive solution that includes user registration, email confirmation, and password recovery out of the box. However, it's more opinionated and can be overkill for simple applications.

2. **Flask-Security**: This combines Flask-Login with additional features like role-based access control and two-factor authentication. It's excellent for enterprise applications but adds complexity.

3. **Manual Implementation**: You could implement authentication manually using Flask sessions and custom decorators. This gives you complete control but requires more code and careful attention to security best practices. You'd need to handle session tokens, CSRF protection, and secure password storage yourself.

**Conclusion**

For this blog application, Flask-Login struck the right balance between functionality and simplicity. It provided exactly what I needed—secure session management—without imposing unnecessary complexity. The library's focused approach allowed me to implement authentication quickly while maintaining full control over user registration and password policies.

If I were building a larger application with more complex permission requirements, I might consider Flask-Security or even a complete authentication service like Auth0. But for a straightforward blog with basic login/logout functionality, Flask-Login is an excellent choice that I would recommend to other developers.''',
                author=admin
            )

            db.session.add(sample_post)
            db.session.commit()

            # Add sample comments
            comment1 = Comment(
                content='Great explanation! Flask-Login has been my go-to for authentication as well.',
                post=sample_post,
                author=john
            )

            comment2 = Comment(
                content='Thanks for sharing your experience. The password hashing issue is something many developers encounter when starting out.',
                post=sample_post,
                author=admin
            )

            db.session.add_all([comment1, comment2])
            db.session.commit()

            print("Sample data created successfully!")


if __name__ == '__main__':
    init_db()
    app.run(debug=True)