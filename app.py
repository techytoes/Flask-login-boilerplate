from flask import Flask, request, jsonify, make_response
from  werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import uuid
import jwt
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.config["DEBUG"] = True
app.config['SECRET_KEY'] = 'thisissecret'

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# decorator for verifying the JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # Read token from cookies

        # jwt is passed in the request header
        if "token" in request.cookies:
            token = request.cookies["token"]
        # return 401 if token is not passed
        if not token:
            return jsonify({'message' : 'Token is missing !!'}), 401
  
        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'])
            # Check if the user is valid
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE id = ?", (data['id'],))
            current_user = cur.fetchone()
            if not current_user:
                return jsonify({
                    'message' : 'User not found !!'
                }), 401
            
        except:
            return jsonify({
                'message' : 'Token is invalid !!'
            }), 401
        # returns the current logged in users contex to the routes
        return  f(*args, **kwargs)
  
    return decorated
  
# API home route
@app.route('/', methods=['GET'])
def Home():
    return "Hello, World!"

# API for registering new users
@app.route('/register', methods=['POST'])
def Register():
    """
    Register API
        - takes in a email and password
        - creates a new user
    """
    conn = get_db_connection()
    # Read data from API call
    name = request.json['name']
    email = request.json['email']
    password = request.json['password']
    
    # Check if user already exists
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = ?", (email,))
    rows = cur.fetchall()
    if len(rows) > 0:
        return "User already exists"
    
    # Create new user
    cur.execute("INSERT INTO users (id, name, email, password) VALUES (?, ?, ?, ?)", (
        str(uuid.uuid4()), name, email, generate_password_hash(password)))
    conn.commit()
    return "User created"

# API for login users
@app.route('/login', methods=['POST'])
def Login():
    """
    Login API
        - takes email and password
        - saves jwt token in cookie
    """
    conn = get_db_connection()
    # Read data from API call
    email = request.json['email']
    password = request.json['password']
    
    # Check if user exists
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = ?", (email,))
    rows = cur.fetchall()
    if len(rows) == 0:
        return "User does not exist"
    
    if check_password_hash(rows[0]['password'], password):
        # generates the JWT Token
        token = jwt.encode({
            'id': rows[0]['id'],
            'exp' : datetime.utcnow() + timedelta(minutes = 30)
        }, app.config['SECRET_KEY'])
  
        # Create a cookie to save the token
        response = make_response(jsonify({
            'message' : 'Logged in successfully',
            'token' : token.decode('UTF-8')
        }))
        response.set_cookie('token', token.decode('UTF-8'))
        return response
    
    return make_response(
        'Could not verify',
        403,
        {'WWW-Authenticate' : 'Basic realm ="Wrong Password !!"'}
    )

# API for logging out users
@app.route('/logout', methods=['POST'])
@token_required
def Logout():
    """
    Logout API
        - removes the jwt token from cookie
    """
    response = make_response(jsonify({
        'message' : 'Logged out successfully'
    }))
    response.set_cookie('token', '', expires=0)
    return response

if __name__ == "__main__":
    # setting debug to True enables hot reload
    # and also provides a debugger shell
    # if you hit an error while running the server
    app.run(debug = True)

"""
DB Structure:

Users:
    - id
    - email
    - password

Photos:
    - id
    - user_id
    - S3 link
    - lat
    - lng
"""