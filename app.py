from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import jwt


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Mydata.db'
app.config['SECRET_KEY'] = 'SUPER_SECRET_KEY'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), unique=True, nullable=False)
    user_name = db.Column(db.String(200),nullable=False)
    password = db.Column(db.String(200),nullable=False)

    def __init__(self, email, user_name, password):
        self.email = email
        self.user_name = user_name
        self.password = password

    def __str__(self):
        return self.user_name

blacklisted_tokens = set()

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = request.cookies.get('access_token_cookie')

        if not token:
            return jsonify({"message": "Token not found"}), 401
        
        if is_token_blacklisted(token):
            return jsonify({"message": "Token is no longer valid"}), 401
        
        try:
            # decode is the process of verify and extracting information from jwt using secret key
            user_data = jwt.decode(token, app.config['SECRET_KEY'], algorithms = ['HS256'])
            user = User.query.get(user_data['user_id'])

        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token is expired"}), 401
        
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid Token"}), 401
        
        except Exception as e:
            return jsonify({"message": "Error decoding token", "error": str(e)}), 401
        
        return f(user, *args, **kwargs)
    
    return decorator


@app.route('/register', methods = ['POST'])
def signup():
    data = request.json
    email = data.get('email')
    user_name = data.get('user_name')
    password = data.get('password')

    if not email or not user_name or not password:
        return jsonify({"message": "Missing fields"}), 400

    hashed_password = generate_password_hash(password)
    new_user = User(email=email, user_name=user_name, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User Created Successfully"})

@app.route('/login', methods = ['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"message": "Missing Credentials"}), 400
    
    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({"message": "Invalid Credentials"}), 401
    
    # encode is the process of creating jwt 
    access_token = jwt.encode({'user_id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=120)}, app.config['SECRET_KEY'], algorithm = 'HS256')

    response = make_response(jsonify({"message": "Login Successfully"}))
    response.set_cookie('access_token_cookie', access_token, httponly=True)
    return response

@app.route('/logout', methods = ['GET'])
@token_required
def logout(user):

    response = make_response(jsonify({"message": "Successfully Logout"}))
    response.set_cookie('access_token_cookie', expires=0)

    return response

@app.route('/greet')
@token_required
def hello(user):
    # user = User.query.filter_by(user)
    print(user)
    return jsonify(f"Hello {user.user_name}")

def is_token_blacklisted(token):
    return token in blacklisted_tokens


if __name__ == '__main__':
    app.run(debug=True, port=8000, use_reloader=False)

        

    