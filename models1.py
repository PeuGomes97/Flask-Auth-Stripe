from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
import datetime
import jwt

bcrypt = Bcrypt()
db = SQLAlchemy()

def connect_db(app):
    with app.app_context():
        db.app = app
        db.init_app(app)
        db.create_all()

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(16), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    stripe_customer_id = db.Column(db.String(150), nullable=False)
    subscription_status = db.Column(db.String(150), nullable=False)

    def __repr__(self):
        return f"<User #{self.id}: {self.username}, {self.email}>"

    @classmethod
    def signup(cls, username, email, password):
        hashed_pwd = bcrypt.generate_password_hash(password).decode('UTF-8')
        user = User(
            username=username,
            email=email,
            password=hashed_pwd,
        )
        db.session.add(user)
        return user

    @classmethod
    def authenticate(cls, email, password):
        """
        Autentica um usuário e gera um token JWT contendo o id e o email do usuário.
        """
        user = cls.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            # Gera o token JWT com id e email no payload
            auth_token = user.encode_auth_token(os.getenv('SECRET_KEY'))  # Usa variável de ambiente para a chave secreta
            return user, auth_token
        return False

    def encode_auth_token(self, secret_key):
        """
        Gera um token JWT com id e email do usuário no payload.
        """
        try:
            payload = {
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1),  # Token expira em 1 dia
                'iat': datetime.datetime.utcnow(),  # Hora de emissão do token
                'sub': self.id,  # ID do usuário
                'email': self.email  # Email do usuário
            }
            token = jwt.encode(payload, secret_key, algorithm='HS256')
            return token
        except Exception as e:
            return str(e)