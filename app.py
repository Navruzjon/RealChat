#pip install Flask Flask-SQLAlchemy Flask-Bcrypt Flask-Login

#Set up the Flask app
from flask import Flask, render_template, url_for, flash, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
from flask_socketio import SocketIO, send, emit
import os
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo

app = Flask(__name__)
#if __name__ == '__main__':
#    app.run(host="0.0.0.0", port=5002, debug=True)
# Set the secret key and configure the database
#app.config['SECRET_KEY'] = 'supersecretkey'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///site.db')
##You can set environment variables like this in your environment:
##export SECRET_KEY='your_production_secret_key'
##export DATABASE_URL='your_database_url'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
socketio = SocketIO(app)
migrate = Migrate(app, db)  # Initialize Flask-Migrate with the app and db
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Define a User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    # Adding a new column for profile picture
    profile_image = db.Column(db.String(120), nullable=True)
# Create database tables
with app.app_context():#@app.before_first_request
#def create_tables():
    db.create_all()

# Registration route
@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered!', 'danger')
            return redirect(url_for('register'))
        
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created!', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# Login route
@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login failed! Please check email and password.', 'danger')
    
    return render_template('login.html')

# Home route (only accessible when logged in)
@app.route("/home")
@login_required
def home():
    return redirect("/")
    #return f"Hello, {current_user.username}! Welcome to the chat."

# Logout route
@app.route("/logout")
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))
##SocketIO part
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")

users_sessions = {}

@socketio.on('connect')
def handle_connect():
    users_sessions[current_user.username] = request.sid
    print(f'{current_user.username} connected with session id: {request.sid}')

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.username in users_sessions:
        del users_sessions[current_user.username]
    print(f'{current_user.username} has disconnected')


# Chat model (Optional for message history)
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    content = db.Column(db.String(200), nullable=False)

# Route to chat page
@app.route('/')
@login_required
def index():
    # Fetch all messages from the database ordered by their ID (you can change this as needed)
    messages = Message.query.order_by(Message.id.asc()).all()  # Fetch messages in order
    # Pass the messages to the chat.html template
    return render_template('chat.html', username=current_user.username, messages=messages)

# SocketIO event for real-time messages
@socketio.on('message')
def handle_message(data):
    print(f"Message: {data}")
    # Save only the message content and username to the database
    message = Message(username=data['username'], content=data['msg'])
    db.session.add(message)
    db.session.commit()
    
    # Broadcast message to all clients
    emit('message', {'username': data['username'], 'msg': data['msg']}, broadcast=True)
    
@socketio.on('private_message')
def handle_private_message(data):
    recipient_username = data['recipient_username']
    recipient_session_id = users_sessions.get(recipient_username)

    if recipient_session_id:
        emit('message', {'msg': data['msg'], 'from': current_user.username}, room=recipient_session_id)
    else:
        emit('message', {'msg': f"User {recipient_username} is not online."}, room=request.sid)

###You would need to maintain a mapping of connected users to their session IDs using something like users_sessions.
@socketio.on('disconnect')
def handle_disconnect():
    print(f'{current_user.username} has disconnected')

##SocketIO part

if __name__ == '__main__':
     socketio.run(app, debug=True, host='0.0.0.0', port=5002, use_reloader=False)
     #app.run(host="0.0.0.0", port=5002, debug=True)#app.run(debug=True)
