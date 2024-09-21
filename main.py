from flask import Flask, redirect, render_template, flash, url_for
from flask import request, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from sqlalchemy.orm import relationship
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = "LXS2U[j&'iMg<)5R~@!Q%0TKn"

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
    __table__name = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)

# with app.app_context():
#     db.create_all()



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        with app.app_context():
            user_email = request.form['email']
            user = Users.query.filter_by(email=user_email).first()
            if not user:
                flash("Email doesn't exist. Register instead.", 'error')
                return redirect('register')
            else:
                if check_password_hash(user.password, request.form['password']):
                    login_user(user)
                    flash("Logged in Successfully")
                    return render_template('index.html')
                else:
                    flash("Password incorrect, try again", 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        with app.app_context():
            if Users.query.filter_by(email=request.form['email']).first():
                flash("You've already registered with that email, login instead.", 'error')
                return redirect(url_for('login'))
            else:
                with app.app_context():
                    hashed_password = generate_password_hash(request.form['password'], method='pbkdf2:sha256', salt_length=8)
                    new_user = Users(username=request.form['username'], email=request.form['email'], password=hashed_password)
                    db.session.add(new_user)
                    db.session.commit()
                    login_user(new_user)
                    return render_template('index.html')
    return render_template('register.html')


@app.route('/', methods=["GET", "POST"])
def home():
    return render_template('index.html')


if __name__ == "__main__":
    app.run(port=5000, debug=True)