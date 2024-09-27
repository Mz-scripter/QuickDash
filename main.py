from flask import Flask, redirect, render_template, flash, url_for
from flask import request, abort, g
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from forms import AddItemForm
from flask_bootstrap import Bootstrap
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from sqlalchemy.orm import relationship
from functools import wraps

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

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

# Configure Tables
class Users(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)

class Items(db.Model):
    __tablename__ = 'items'
    id = db.Column(db.Integer, primary_key=True)
    dish = db.Column(db.String(250), nullable=False)
    rating = db.Column(db.String(10), nullable=False)
    time = db.Column(db.String(250), nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

class Cart(db.Model):
    __tablename__ = 'cart'
    id = db.Column(db.Integer, primary_key=True)
    dish = db.Column(db.String(250), nullable=False)
    rating = db.Column(db.String(10), nullable=False)
    time = db.Column(db.String(250), nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

# with app.app_context():
#     db.create_all()
@app.before_request
def set_variable():
    g.cart_num = calculate_num_cart()

@app.route('/', methods=["GET", "POST"])
def home():
    items = Items.query.all()
    return render_template('index.html', all_items=items, numc=g.cart_num)

@app.route('/add-to-cart', methods=["GET", "POST"])
def add_to_cart():
    item_id = request.args.get('id')
    with app.app_context():
        item_to_add = db.session().query(Items).get(item_id)
        cart_item = Cart(
            dish = item_to_add.dish,
            rating = item_to_add.rating,
            time = item_to_add.time,
            img_url = item_to_add.img_url
        )
        db.session.add(cart_item)
        db.session.commit()
        return redirect(request.referrer)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        if Users.query.filter_by(email=request.form['email']).first():
            flash("You've already registered with that email, login instead", 'error')
            return redirect(url_for('login'))
        else:
            with app.app_context():
                hashed_password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
                new_user = Users(username=request.form['username'], email=request.form['email'], password=hashed_password)
                db.session.add(new_user)
                db.session.commit()
                return redirect(url_for('home'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        with app.app_context():
            user_email = request.form['email']
            user = Users.query.filter_by(email=user_email).first()
            if not user:
                flash("Email doesn't exist. Register instead", "error")
                return redirect(url_for('register'))
            else:
                if bcrypt.check_password_hash(user.password, request.form['password']):
                    flash('Logged in successfully')
                    return redirect(url_for('home'))
                else:
                    flash("Password incorrect, try again", 'error')
    return render_template('login.html')

@app.route('/add-item', methods=['GET', 'POST'])
def add_item():
    form = AddItemForm()
    if request.method == "POST":
        with app.app_context():
            new_item = Items(
                dish = form.dish.data,
                rating = form.rating.data,
                time = form.time.data,
                img_url = form.img_url.data
            )
            db.session.add(new_item)
            db.session.commit()
            return redirect(url_for('home'))
    return render_template('add-item.html', form=form)

def calculate_num_cart():
    cart = Cart.query.all()
    return len(cart)

if __name__ == "__main__":
    app.run(port=5000, debug=True)