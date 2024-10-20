from . import db
from flask_login import UserMixin


# User Model
class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False, unique=True)
    phone_number = db.Column(db.String(25), nullable=False)
    address = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    cart_items = db.relationship('Cart', backref='user', lazy=True)


# Items Model
class Items(db.Model):
    __tablename__ = 'items'
    id = db.Column(db.Integer, primary_key=True)
    dish = db.Column(db.String(250), nullable=False)
    rating = db.Column(db.String(10), nullable=False)
    time = db.Column(db.String(250), nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    price = db.Column(db.String(10), nullable=False)


# Cart Model 
class Cart(db.Model):
    __tablename__ = 'cart'
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    dish = db.Column(db.String(250), nullable=False)
    rating = db.Column(db.String(10), nullable=False)
    time = db.Column(db.String(250), nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    price = db.Column(db.String(10), nullable=False)