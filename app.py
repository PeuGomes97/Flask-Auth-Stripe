from flask import Flask, request, jsonify, g, url_for
from flask_sqlalchemy import SQLAlchemy
import stripe
import os
import jwt
from functools import wraps
from models1 import User, db, connect_db


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql:///stripe_users'

connect_db(app)
stripe.api_key = 'your_stripe_secret_key'

# Middleware para verificar o token JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # Obtenha o token do header Authorization
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            # Decodificar o token JWT
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['sub']).first()
            if current_user is None:
                return jsonify({'message': 'User not found!'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401
        
        # Armazena o usuário atual em `g` para ser acessado em rotas
        g.current_user = current_user
        g.username = data.get('username')  # Armazena o username decodificado em `g`
        return f(*args, **kwargs)
    
    return decorated

@app.route('/', methods=['GET'])
def hello_world():
    return "Hello, World!"


@app.route('/register', methods=['POST'])
def register():
    data = request.json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'User already exists'}), 400

    customer = stripe.Customer.create(email=email)
    new_user = User(
        email=email,
        password=password,
        stripe_customer_id=customer.id,
        subscription_status='inactive'
    )
    db.session.add(new_user)
    db.session.commit()

    # Gerar token JWT
    auth_token = new_user.encode_auth_token(app.config['SECRET_KEY'])

    return jsonify({'message': 'User registered successfully', 'auth_token': auth_token.decode()}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    user = User.query.filter_by(email=email).first()
    if user and user.password == password:
        # Gerar token JWT
        auth_token = user.encode_auth_token(app.config['SECRET_KEY'])
        return jsonify({'message': 'Login successful', 'auth_token': auth_token.decode()}), 200
    else:
        return jsonify({'error': 'Invalid email or password'}), 401


# @app.route('/subscribe', methods=['POST'])
# @token_required
# def subscribe():
#     session = stripe.checkout.Session.create(
#         payment_method_types=['card'],
#         line_items=[{
#             'price': 'your_stripe_price_id',
#             'quantity': 1,
#         }],
#         mode='subscription',
#         success_url=url_for('dashboard', _external=True),
#         cancel_url=url_for('dashboard', _external=True),
#         customer=g.current_user.stripe_customer_id
#     )
#     return jsonify({'checkout_url': session.url}), 303


# @app.route('/webhook', methods=['POST'])
# def webhook():
#     payload = request.get_data(as_text=True)
#     sig_header = request.headers.get('Stripe-Signature')
#     endpoint_secret = 'your_stripe_webhook_secret'

#     try:
#         event = stripe.Webhook.construct_event(
#             payload, sig_header, endpoint_secret
#         )
#     except ValueError:
#         return jsonify({'error': 'Invalid payload'}), 400
#     except stripe.error.SignatureVerificationError:
#         return jsonify({'error': 'Invalid signature'}), 400

#     if event['type'] == 'checkout.session.completed':
#         session = event['data']['object']
#         customer_id = session['customer']
#         user = User.query.filter_by(stripe_customer_id=customer_id).first()
#         if user:
#             user.subscription_status = 'active'
#             db.session.commit()

#     return jsonify({'message': 'Webhook received'}), 200


@app.route('/dashboard', methods=['GET'])
@token_required
def dashboard():
    if g.current_user.subscription_status != 'active':
        return jsonify({'error': 'Subscription inactive. Please subscribe to access this content.'}), 403
    return jsonify({'message': 'Welcome to your dashboard, {}!'.format(g.current_user.username)}), 200

@app.route('/verify', methods=['GET'])
@token_required
def verify():
    return jsonify({
        'message': 'Token is valid',
        'user_id': g.current_user.id,
        'username': g.current_user.username
    }), 200



if __name__ == '__main__':
    app.run(debug=True)
