from flask_wtf import FlaskForm
from wtforms import StringField, EmailField, PasswordField, SubmitField
from wtforms.validators import DataRequired,URL, Email, Length

class RegisterForm(FlaskForm):
    fullname = StringField("Full Name", validators=[DataRequired()])
    email = EmailField("Email", validators=[DataRequired(), Email()])
    phone_number = StringField("Phone Number (+234 xxx xxxx xxx)", validators=[DataRequired()])
    address = StringField("Address", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8, max=20)])

class VerifyEmail(FlaskForm):
    code = StringField("Verification Code", validators=[DataRequired()])

class RequestResetForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Request Password Reset")

class ResetPasswordForm(FlaskForm):
    password = PasswordField("New Password", validators=[DataRequired()])
    confirm_password = PasswordField("Confirm New Password", validators=[DataRequired()])
    submit = SubmitField("Reset Password")

class LoginForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8, max=20)])

class AddItemForm(FlaskForm):
    dish = StringField("Dish", validators=[DataRequired()])
    rating = StringField("Rating", validators=[DataRequired()])
    time = StringField("Time", validators=[DataRequired()])
    img_url = StringField("Dish Image Url", validators=[DataRequired(), URL()])
    price = StringField("Price", validators=[DataRequired()])
    submit = SubmitField("Add Item")