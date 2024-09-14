#pip install Flask Flask-SQLAlchemy Flask-Bcrypt Flask-Login

#Set up the Flask app
from flask import Flask, render_template, url_for, flash, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
from flask_socketio import SocketIO, send, emit
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
#from flask_jwt_extended import jwt_refresh_token_required
from flask_jwt_extended import get_jwt



app = Flask(__name__)
#if __name__ == '__main__':
#    app.run(host="0.0.0.0", port=5002, debug=True)
# Set the secret key and configure the database
app.config['SECRET_KEY'] = 'supersecretkey' # Change this in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'jwtsecretkey'  # Change this in production
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 3600  # Token expires in 1 hour
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = 86400  # Refresh token expires in 1 day
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
db = SQLAlchemy(app)
socketio = SocketIO(app)
migrate = Migrate(app, db)  # Initialize Flask-Migrate with the app and db
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

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
        data = request.get_json()
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered!', 'danger')
            return redirect(url_for('register'))
        
        new_user = User(username=data['username'], email=data['email'], password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created!', 'success')
        #return jsonify({"message": "User registered successfully!"}), 201
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
            access_token = create_access_token(identity=user.id)
            refresh_token = create_refresh_token(identity=user.id)
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login failed! Please check email and password.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')


#Add a refresh route to exchange the refresh token for a new access token
@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user_id = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user_id)
    return jsonify(access_token=new_access_token), 200


#To secure routes, like a chat API endpoint, use the @jwt_required() decorator. Only users with a valid JWT token can access these routes.
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    return jsonify({"message": f"Hello user {current_user_id}, you are authenticated!"}), 200



# Home route (only accessible when logged in)
@app.route("/home")
@login_required
def home():
    return redirect("/")
    #return f"Hello, {current_user.username}! Welcome to the chat."

#Implement a token blacklist and check against it
blacklist = set()

@jwt.token_in_blocklist_loader
def check_if_token_revoked(decoded_token):
    return decoded_token['jti'] in blacklist

@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    blacklist.add(jti)
    return jsonify({"message": "Successfully logged out"}), 200

##SocketIO part
# Chat model (Optional for message history)
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    content = db.Column(db.String(200), nullable=False)

# Route to chat page
@app.route('/')
@login_required
def index():
    messages = Message.query.all()
    return render_template('chat.html', username=current_user.username)

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
###You would need to maintain a mapping of connected users to their session IDs using something like users_sessions.
@socketio.on('disconnect')
def handle_disconnect():
    if current_user.username in users_sessions:
        del users_sessions[current_user.username]
    print(f'{current_user.username} has disconnected')

##SocketIO part

if __name__ == '__main__':
     socketio.run(app, debug=True, host='0.0.0.0', port=5002, use_reloader=False)
     #app.run(host="0.0.0.0", port=5002, debug=True)#app.run(debug=True)



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
