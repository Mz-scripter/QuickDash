from flask import Flask, redirect, render_template, flash, url_for
from flask import request, abort, g
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from forms import AddItemForm, RegisterForm, LoginForm
from flask_bootstrap import Bootstrap
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from sqlalchemy.orm import relationship
from sqlalchemy import func, cast, Integer
from functools import wraps
import random
import time
import requests

app = Flask(__name__)
app.config['SECRET_KEY'] = "LXS2U[j&'iMg<)5R~@!Q%0TKn"
bcrypt = Bcrypt(app)
Bootstrap(app)

# Connect to db
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quickdash.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
FLW_PUBLIC_KEY = "FLWPUBK_TEST-ed3c41c9fd4929475cc8d2a642a795cf-X"
FLW_SECRET_KEY = "FLWSECK_TEST-4b6c7cd2d1b1328a353f78d1b3f4749a-X"
FLW_REDIRECT_URL = "https://github.com/Mzed-io"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Configure Tables
class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    cart_items = db.relationship('Cart', backref='user', lazy=True)

class Items(db.Model):
    __tablename__ = 'items'
    id = db.Column(db.Integer, primary_key=True)
    dish = db.Column(db.String(250), nullable=False)
    rating = db.Column(db.String(10), nullable=False)
    time = db.Column(db.String(250), nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    price = db.Column(db.String(10), nullable=False)

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

# with app.app_context():
#     db.create_all()

@app.before_request
def set_variable():
    if current_user.is_authenticated:
        g.cart_num = calculate_num_cart()
    else:
        g.cart_num = 0

@app.route('/', methods=["GET", "POST"])
def home():
    items = Items.query.all()
    random.shuffle(items)
    return render_template('index.html', all_items=items, numc=g.cart_num)

@app.route('/search', methods=["GET", "POST"])
def search():
    if request.method == "POST":
        with app.app_context():
            search = request.form['search']
            search_results = Items.query.filter(Items.dish.ilike(f"%{search}%")).all()
            if not search_results:
                return render_template("no-result.html", search=search)
            return render_template('index.html',all_items=search_results)
    return redirect(url_for('home'))

@app.route('/header', methods=["GET", "POST"])
def header():
    return render_template('header.html', numc=g.cart_num)

@app.route('/add-to-cart', methods=["GET", "POST"])
@login_required
def add_to_cart():
    item_id = request.args.get('id')
    with app.app_context():
        user_id = User.query.get(current_user.id)
        item_to_add = db.session().query(Items).get(item_id)
        cart_item = Cart(
            item_id = item_to_add.id,
            user_id = user_id.id,
            dish = item_to_add.dish,
            rating = item_to_add.rating,
            time = item_to_add.time,
            img_url = item_to_add.img_url,
            price = item_to_add.price,
        )
        db.session.add(cart_item)
        db.session.commit()
        return redirect(request.referrer)

@app.route('/remove_item/<int:item_id>', methods=["GET", "POST"])
@login_required
def remove_item(item_id):
    with app.app_context():
        cart_item = Cart.query.filter_by(user_id=current_user.id, item_id=item_id).first()
        if cart_item:
            total_quantity = db.session.query(func.count(Cart.id)).filter_by(user_id=current_user.id, item_id=item_id).scalar()
            if total_quantity > 1:
                item_to_delete = Cart.query.filter_by(user_id=current_user.id, item_id=item_id).first()
                db.session.delete(item_to_delete)
            else:
                item_to_delete = Cart.query.filter_by(user_id=current_user.id, item_id=item_id).first()
                db.session.delete(item_to_delete)
            db.session.commit()
        return redirect(request.referrer)

@app.route('/remove-all/<int:item_id>', methods=["GET", "POST"])
@login_required
def remove_all(item_id):
    with app.app_context():
        Cart.query.filter_by(user_id=current_user.id, item_id=item_id).delete()
        db.session.commit()
        return redirect(request.referrer)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if request.method == "POST":
        if User.query.filter_by(email=form.email.data).first():
            flash("You've already registered with that email, login instead", 'error')
            return redirect(url_for('login'))
        else:
            with app.app_context():
                hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
                new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user, remember=True)
                return redirect(url_for('home'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == "POST":
        with app.app_context():
            user = User.query.filter_by(email=form.email.data).first()
            if not user:
                flash("Email doesn't exist. Register instead", "error")
                return redirect(url_for('register'))
            else:
                if bcrypt.check_password_hash(user.password, request.form['password']):
                    flash('Logged in successfully')
                    login_user(user, remember=True)
                    return redirect(url_for('home'))
                else:
                    flash("Password incorrect, try again", 'error')
    return render_template('login.html', form=form)

@app.route('/add-item', methods=['GET', 'POST'])
@login_required
def add_item():
    form = AddItemForm()
    if request.method == "POST":
        with app.app_context():
            new_item = Items(
                dish = form.dish.data,
                rating = form.rating.data,
                time = form.time.data,
                img_url = form.img_url.data,
                price = form.price.data
            )
            db.session.add(new_item)
            db.session.commit()
            return redirect(url_for('home'))
    return render_template('add-item.html', form=form, numc=g.cart_num)

@app.route('/cart', methods=["GET", "POST"])
@login_required
def cart():
    cart_items = db.session.query(
        Cart.dish,
        Cart.img_url,
        cast(Cart.price, Integer).label('price'),
        Cart.item_id,
        func.count(Cart.dish).label('quantity')
    ).filter(Cart.user_id == current_user.id)
    cart_items = cart_items.group_by(Cart.dish).all()
    return render_template("cart.html", numc=g.cart_num, cart_items=cart_items)

@app.route('/profile', methods=["GET", "POST"])
@login_required
def profile():
    return render_template('profile.html', numc=g.cart_num, name=current_user.username, email=current_user.email)

@app.route('/logout', methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@login_required
def calculate_num_cart():
    cart_items = Cart.query.filter_by(user_id=current_user.id).all()
    return len(cart_items)

@app.route('/success', methods=["GET", "POST"])
@login_required
def success():
    return render_template('success.html')

@app.route('/failure', methods=["GET", "POST"])
@login_required
def failure():
    return render_template('failure.html')

@app.route('/checkout', methods=["GET", "POST"])
@login_required
def checkout():
    if request.method == "POST":
        total_amount = request.form['total_price']
        headers = {
            'Authorization': f"Bearer {FLW_SECRET_KEY}",
            'Content-Type': 'application/json'
        }
        payment_data = {
            "tx_ref": f"order_{current_user.id}_{int(time.time())}",
            "amount": total_amount,
            "currency": "NGN",
            "redirect_url": url_for('success'),
            "customer": {
                "email": current_user.email,
                "name": current_user.username
            },
            "payment_options": "card, banktransfer",
            "customizations": {
                "title": "Your Food Order",
                "description": "Payment for your food order"
            }
        }
        response = requests.post('https://api.flutterwave.com/v3/payments', json=payment_data, headers=headers)
        response_data = response.json()

        if response_data.get('status') == 'success':
            return redirect(url_for('success'))
        else:
            flash('An error occured while initiating payment. Please try again.', 'danger')
            return redirect(url_for('failure'))


if __name__ == "__main__":
    app.run(port=5000, debug=True)