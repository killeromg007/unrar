from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer.storage.sqla import SQLAlchemyStorage
from flask_dance.consumer import oauth_authorized
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import secrets
from oauthlib.oauth2.rfc6749.errors import InvalidGrantError, TokenExpiredError, OAuth2Error
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Google OAuth blueprint
google_bp = make_google_blueprint(
    client_id=app.config['GOOGLE_OAUTH_CLIENT_ID'],
    client_secret=app.config['GOOGLE_OAUTH_CLIENT_SECRET'],
    scope=['profile', 'email'],
    storage=SQLAlchemyStorage(OAuth, db.session, user=current_user)
)
app.register_blueprint(google_bp, url_prefix='/login')

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=True)  # Made nullable for Google login
    email = db.Column(db.String(120), unique=True, nullable=True)
    google_id = db.Column(db.String(100), unique=True, nullable=True)
    message_boxes = db.relationship('MessageBox', backref='owner', lazy=True)

class OAuth(db.Model):
    __tablename__ = 'oauth'
    id = db.Column(db.Integer, primary_key=True)
    provider = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    token = db.Column(db.String(300), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey(User.id), nullable=False)
    user = db.relationship(User)

class MessageBox(db.Model):
    __tablename__ = 'message_boxes'
    id = db.Column(db.Integer, primary_key=True)
    link_id = db.Column(db.String(16), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    messages = db.relationship('Message', backref='message_box', lazy=True)

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    box_id = db.Column(db.Integer, db.ForeignKey('message_boxes.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@oauth_authorized.connect_via(google_bp)
def google_logged_in(blueprint, token):
    if not token:
        flash("Failed to log in with Google.", category="error")
        return False

    resp = blueprint.session.get("/oauth2/v1/userinfo")
    if not resp.ok:
        flash("Failed to fetch user info from Google.", category="error")
        return False

    google_info = resp.json()
    google_user_id = str(google_info["id"])

    # Find this OAuth token in the database, or create it
    user = User.query.filter_by(google_id=google_user_id).first()
    if not user:
        # Create a new user
        username = google_info["email"].split("@")[0]  # Use email prefix as username
        # Ensure username is unique
        base_username = username
        counter = 1
        while User.query.filter_by(username=username).first():
            username = f"{base_username}{counter}"
            counter += 1
            
        user = User(
            username=username,
            email=google_info["email"],
            google_id=google_user_id,
        )
        db.session.add(user)
        db.session.commit()

    # Log in the user
    login_user(user)
    flash("Successfully signed in with Google.")

    # Disable Flask-Dance's default behavior for saving the OAuth token
    return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        
        # Auto login after registration
        login_user(user)
        flash('Registration successful! Welcome to Anonymous Messages!')
        return redirect(url_for('dashboard'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/login/google')
def google_login():
    if not google.authorized:
        return redirect(url_for('google.login'))
    try:
        resp = google.get("/oauth2/v1/userinfo")
        assert resp.ok, resp.text
        return redirect(url_for('dashboard'))
    except (InvalidGrantError, TokenExpiredError) as e:
        return redirect(url_for('google.login'))

@app.route('/dashboard')
@login_required
def dashboard():
    message_boxes = MessageBox.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', message_boxes=message_boxes)

@app.route('/create_box')
@login_required
def create_box():
    link_id = secrets.token_urlsafe(12)
    message_box = MessageBox(link_id=link_id, user_id=current_user.id)
    db.session.add(message_box)
    db.session.commit()
    return redirect(url_for('view_box', link_id=link_id))

@app.route('/box/<link_id>')
def view_box(link_id):
    message_box = MessageBox.query.filter_by(link_id=link_id).first_or_404()
    messages = Message.query.filter_by(box_id=message_box.id).order_by(Message.timestamp.desc()).all()
    return render_template('message_box.html', link_id=link_id, messages=messages, message_box=message_box)

@app.route('/send/<link_id>', methods=['GET', 'POST'])
def send_message(link_id):
    message_box = MessageBox.query.filter_by(link_id=link_id).first_or_404()
    
    if request.method == 'POST':
        content = request.form.get('content')
        if content:
            message = Message(content=content, box_id=message_box.id)
            db.session.add(message)
            db.session.commit()
            flash('Message sent successfully!')
            return redirect(url_for('send_message', link_id=link_id))
    
    return render_template('send_message.html', link_id=link_id)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.drop_all()
        db.create_all()
    app.run(debug=True)
