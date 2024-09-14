#pip install Flask Flask-SQLAlchemy Flask-Bcrypt Flask-Login

from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
from flask_socketio import SocketIO, send, emit
from flask_dance.contrib.google import make_google_blueprint, google
import os

app = Flask(__name__)

# Set the secret key and configure the database
app.config['SECRET_KEY'] = 'supersecretkey'  # Change this in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
socketio = SocketIO(app)
migrate = Migrate(app, db)  # Initialize Flask-Migrate with the app and db
bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = 'google_login'

# Configure Flask-Dance with Google OAuth
google_bp = make_google_blueprint(client_id='Your_google_clientID_here',
                                  client_secret='Your_google_client_Secret_here',
                                  redirect_to='google_login')
app.register_blueprint(google_bp, url_prefix='/google_login')

# Flask-Login User Loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Define the User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    profile_image = db.Column(db.String(120), nullable=True)  # Profile picture for OAuth users

# Create the database tables
with app.app_context():
    db.create_all()

# Google OAuth login route
@app.route("/google_login")
def google_login():
    if not google.authorized:
        return redirect(url_for('google.login'))

    # Fetch user information from Google
    resp = google.get("/plus/v1/people/me")
    assert resp.ok, resp.text
    google_info = resp.json()
    google_email = google_info['emails'][0]['value']
    google_username = google_info['displayName']

    # Check if user exists
    user = User.query.filter_by(email=google_email).first()
    if not user:
        # Create a new user if not found
        user = User(username=google_username, email=google_email)
        db.session.add(user)
        db.session.commit()

    login_user(user)
    flash('Login successful!', 'success')
    return redirect(url_for('home'))

# Logout route
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# Home route (only accessible when logged in)
@app.route("/home")
@login_required
def home():
    return redirect("/")

# Route to chat page
@app.route('/')
@login_required
def index():
    messages = Message.query.all()
    return render_template('chat.html', username=current_user.username)

# Chat model (Optional for message history)
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    content = db.Column(db.String(200), nullable=False)

# SocketIO event for real-time messages
socketio = SocketIO(app, async_mode='eventlet')

users_sessions = {}

@socketio.on('connect')
def handle_connect():
    users_sessions[current_user.username] = request.sid
    print(f'{current_user.username} connected with session id: {request.sid}')

@socketio.on('message')
def handle_message(msg):
    print(f"Message: {msg}")
    # Save message to database
    message = Message(username=current_user.username, content=msg)
    db.session.add(message)
    db.session.commit()
    
    # Broadcast message to all clients
    emit('message', {'username': current_user.username, 'msg': msg}, broadcast=True)

@socketio.on('private_message')
def handle_private_message(data):
    recipient_username = data['recipient_username']
    recipient_session_id = users_sessions.get(recipient_username)
    
    if recipient_session_id:
        emit('message', {'msg': data['msg'], 'from': current_user.username}, room=recipient_session_id)
    else:
        emit('message', {'msg': f"User {recipient_username} is not online."}, room=request.sid)

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.username in users_sessions:
        del users_sessions[current_user.username]
    print(f'{current_user.username} has disconnected')

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5002, use_reloader=False)


#Send JWT in Headers
#When making API requests to protected routes, the client needs to send the JWT token in the request headers.

# Example client-side code to send a request with a JWT token:
# fetch('/protected', {
#   method: 'GET',
#   headers: {
#     'Authorization': 'Bearer <your-jwt-token>'
#   }
# }).then(response => response.json())
#   .then(data => console.log(data));
# The JWT token should be stored securely on the client side (e.g., in memory or local storage).
