from flask import Blueprint, render_template, redirect, url_for, flash, request, session, g, abort
from flask import current_app
from flask_login import login_required, current_user, login_user, logout_user
from sqlalchemy import func, cast, Integer
from .models import User, Items, Cart
from . import db, bcrypt, mail
from .forms import RegisterForm, LoginForm, AddItemForm, RequestResetForm, ResetPasswordForm, VerifyEmail
from  flask_mail import Message
from itsdangerous import URLSafeTimedSerializer
import secrets, time, random
import requests

main = Blueprint('main', __name__)

# Password Reset Functionality
def generate_reset_token(email):
    s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return s.dumps(email, salt='password-reset-salt')

def verify_reset_token(token, expiration=1800):
    s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=expiration)
        return email
    except Exception as e:
        print(f"Token verification failed: {e}")
        return None
    
# Calculate Cart Number
def set_variable():
    if current_user.is_authenticated:
        g.cart_num = calculate_num_cart()
    else:
        g.cart_num = 0

# Home route
@main.route('/', methods=["GET", "POST"])
def home():
    items = Items.query.all()
    random.shuffle(items)
    return render_template('index.html', all_items=items, numc=g.cart_num)

# Search route
@main.route('/search', methods=["GET", "POST"])
def search():
    if request.method == "POST":
        with current_app.app_context():
            search = request.form['search']
            search_results = Items.query.filter(Items.dish.ilike(f"%{search}%")).all()
            if not search_results:
                return render_template("no-result.html", search=search)
            return render_template('index.html',all_items=search_results)
    return redirect(url_for('main.home'))

# Header route
@main.route('/header', methods=["GET", "POST"])
@login_required
def header():
    return render_template('header.html', numc=g.cart_num)

# Add to Cart Route
@main.route('/add-to-cart', methods=["GET", "POST"])
@login_required
def add_to_cart():
    item_id = request.args.get('id')
    with current_app.app_context():
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
    
# Remove item route
@main.route('/remove_item/<int:item_id>', methods=["GET", "POST"])
@login_required
def remove_item(item_id):
    with current_app.app_context():
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

# Remove all route
@main.route('/remove-all/<int:item_id>', methods=["GET", "POST"])
@login_required
def remove_all(item_id):
    with current_app.app_context():
        Cart.query.filter_by(user_id=current_user.id, item_id=item_id).delete()
        db.session.commit()
        return redirect(request.referrer)

# Register route
@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if request.method == "POST":
        if User.query.filter_by(email=form.email.data).first():
            flash("You've already registered with that email, login instead", 'error')
            return redirect(url_for('main.login'))
        else:
            email = form.email.data
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            verification_code = secrets.token_hex(3).upper()
            session['verification_code'] = verification_code
            session['fullname'] = form.fullname.data
            session['user_email'] = form.email.data
            session['phone_number'] = form.phone_number.data
            session['address'] = form.address.data
            session['password'] = hashed_password
            msg = Message(subject='QuickDash | Email Verification', sender=('QuickDash', 'adekomuheez567@gmail.com'), recipients=[email])
            msg.body = f"Your verification code is: {verification_code}"
            mail.send(msg)
            return redirect(url_for('main.verify_email'))
    return render_template('register.html', form=form)

# Verify email route
@main.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    form = VerifyEmail()
    if request.method == "POST":
        code = form.code.data
        if code == session.get('verification_code'):
            with current_app.app_context():
                new_user = User(fullname=session.get('fullname'),
                                 email=session.get('user_email'),
                                 phone_number=session.get('phone_number'),
                                 address=session.get('address'),
                                 password=session.get('password')
                            )
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user, remember=True)
                return redirect(url_for('main.home'))
        elif code != session.get('verification_code'):
            flash('Incorrect verification code. Try again.', 'error')
            return redirect(url_for('main.register'))
    return render_template('verify-email.html', form=form)

# Reset password route
@main.route('/reset-password', methods=['GET', 'POST'])
def reset_request():
    form = RequestResetForm()
    if request.method == 'POST':
        with current_app.app_context():
            user = User.query.filter_by(email=form.email.data).first()
            print(user.email)
            if user:
                token = generate_reset_token(user.email)
                print(token)
                msg = Message('Password Reset Request',
                              sender=current_app.config['MAIL_USERNAME'],
                              recipients=[user.email])
                reset_url = url_for('main.reset_token', token=token, _external=True)
                msg.body = f"To reset your password, visit the following link: \n {reset_url} \n If you did not make this request then simply ignore this email."
                msg.subject = "QuickDash | Reset Password"
                mail.send(msg)
            else:
                flash("No account found with that email.", "error")
            return redirect(url_for('main.login'))
    return render_template('reset-request.html', form=form)

# Reset Password Functionality route
@main.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    email = verify_reset_token(token)
    print(email)
    if email is None:
        flash("That is an invalid or expired token", 'error')
        return redirect(url_for('main.reset_request'))
    form = ResetPasswordForm()
    if request.method == "POST":
        with current_app.app_context():
            user = User.query.filter_by(email=email).first()
            if user:
                hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
                user.password = hashed_password
                db.session.commit()
                flash("Your password has been updated!", 'success')
                return redirect(url_for('main.login'))
    return render_template('reset-token.html', form=form, token=token, _external=True)

# Login route
@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == "POST":
        with current_app.app_context():
            user = User.query.filter_by(email=form.email.data).first()
            if not user:
                flash("Email doesn't exist. Register instead", "error")
                return redirect(url_for('main.register'))
            else:
                if bcrypt.check_password_hash(user.password, request.form['password']):
                    flash('Logged in successfully')
                    login_user(user, remember=True)
                    return redirect(url_for('main.home'))
                else:
                    flash("Password incorrect, try again", 'error')
    return render_template('login.html', form=form)

# Functionality for add item route
@main.route('/add-item', methods=['GET', 'POST'])
@login_required
def add_item():
    form = AddItemForm()
    allowed_emails = ['mzscripterx5@gmail.com']
    if current_user.email in allowed_emails:
        if request.method == "POST":
            with current_app.app_context():
                new_item = Items(
                    dish = form.dish.data,
                    rating = form.rating.data,
                    time = form.time.data,
                    img_url = form.img_url.data,
                    price = form.price.data
                )
                db.session.add(new_item)
                db.session.commit()
                return redirect(url_for('main.home'))
        return render_template('add-item.html', form=form, numc=g.cart_num)
    else:
        abort(404)

# Cart route
@main.route('/cart', methods=["GET", "POST"])
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

# Checkout route
@main.route('/checkout', methods=["GET", "POST"])
@login_required
def checkout():
    # if request.method == "POST":
    #     total_amount = request.form['total_price']
    #     headers = {
    #         'Authorization': f"Bearer {FLW_SECRET_KEY}",
    #         'Content-Type': 'application/json'
    #     }
    #     payment_data = {
    #         "tx_ref": f"order_{current_user.id}_{int(time.time())}",
    #         "amount": total_amount,
    #         "currency": "NGN",
    #         "redirect_url": url_for('success'),
    #         "customer": {
    #             "email": current_user.email,
    #             "name": current_user.username
    #         },
    #         "payment_options": "card, banktransfer",
    #         "customizations": {
    #             "title": "Your Food Order",
    #             "description": "Payment for your food order"
    #         }
    #     }
    #     response = requests.post('https://api.flutterwave.com/v3/payments', json=payment_data, headers=headers)
    #     response_data = response.json()

    #     if response_data.get('status') == 'success':
    #         with current_app.app_context():
    #             Cart.query.filter_by(user_id=current_user.id).delete()
    #             db.session.commit()
    #             return redirect(url_for('success'))
    #     else:
    #         flash('An error occured while initiating payment. Please try again.', 'danger')
    #         return redirect(url_for('failure'))
    pass

# Payment successful route
@main.route('/success', methods=["GET", "POST"])
@login_required
def success():
    return render_template('success.html')

# Payment failed route
@main.route('/failure', methods=["GET", "POST"])
@login_required
def failure():
    return render_template('failure.html')

# Profile route
@main.route('/profile', methods=["GET", "POST"])
@login_required
def profile():
    return render_template('profile.html', numc=g.cart_num, name=current_user.username, email=current_user.email)

# Logout route
@main.route('/logout', methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.home'))

# Help route
@main.route('/help', methods=["GET", "POST"])
@login_required
def help():
    # if request.method == "POST":
    #     with smtplib.SMTP("smtp.gmail.com", 587) as connection:
    #         connection.starttls()
    #         connection.login(user=my_email, password=password)
    #         connection.sendmail(
    #             from_addr=my_email, 
    #             to_addrs=my_email, 
    #             msg=f"Subject:QuickDash| Help\n\nName: {request.form['name']}\n Email: {request.form['email']}\n Message: {request.form['message']}"
    #         )
    #         return redirect(url_for('help'))
    return render_template("help.html", numc=g.cart_num)

# Functionality for number of cart items
@login_required
def calculate_num_cart():
    cart_items = Cart.query.filter_by(user_id=current_user.id).all()
    return len(cart_items)
