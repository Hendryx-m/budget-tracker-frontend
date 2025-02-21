from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///budget.db'
app.config['JWT_SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    type = db.Column(db.String(10), nullable=False)  # 'income' or 'expense'

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_pw = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], password=hashed_pw)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()

    if user and bcrypt.check_password_hash(user.password, data['password']):  # Verify hashed password
        access_token = create_access_token(identity=str(user.id))  # Create JWT token
        return jsonify({'access_token': access_token})

    return jsonify({'message': 'Invalid credentials'}), 401


    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=str(user.id))  # Ensure it's a string
        return jsonify({'access_token': access_token})

    return jsonify({'message': 'Invalid credentials'}), 401



@app.route('/transactions', methods=['POST'])
@jwt_required()
def add_transaction():
    data = request.get_json()
    user_id = get_jwt_identity()
    new_transaction = Transaction(user_id=user_id, amount=data['amount'], 
                                  category=data['category'], type=data['type'])
    db.session.add(new_transaction)
    db.session.commit()
    return jsonify({'message': 'Transaction added'})

@app.route('/transactions', methods=['GET'])
@jwt_required()
def get_transactions():
    user_id = get_jwt_identity()
    transactions = Transaction.query.filter_by(user_id=user_id).all()
    return jsonify([{'id': t.id, 'amount': t.amount, 'category': t.category, 'date': t.date, 'type': t.type} for t in transactions])

@app.route('/')
def home():
    return jsonify({"message": "Welcome to the Budget Tracker API!"})



if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001)

app.config['DEBUG'] = True

from app import db
#db.create_all()

from app import db, User
#user = User.query.filter_by(username='testuser').first()
#print(user)

class Budget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    limit = db.Column(db.Float, nullable=False, default=0)

@app.route('/budget', methods=['POST'])
@jwt_required()
def set_budget():
    user_id = get_jwt_identity()
    data = request.get_json()
    
    budget = Budget.query.filter_by(user_id=user_id).first()
    
    if budget:
        budget.limit = data['limit']
    else:
        budget = Budget(user_id=user_id, limit=data['limit'])
        db.session.add(budget)
    
    db.session.commit()
    return jsonify({"message": "Budget limit updated!"})

@app.route('/budget', methods=['GET'])
@jwt_required()
def get_budget():
    user_id = get_jwt_identity()
    budget = Budget.query.filter_by(user_id=user_id).first()
    
    if budget:
        return jsonify({"limit": budget.limit})
    return jsonify({"limit": 0})
