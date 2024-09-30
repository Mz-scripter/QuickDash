from flask_wtf import FlaskForm
from wtforms import StringField, EmailField, PasswordField, SubmitField
from wtforms.validators import DataRequired,URL, Email, Length

class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    email = EmailField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8, max=20)])

class LoginForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8, max=20)])

class AddItemForm(FlaskForm):
    dish = StringField("Dish", validators=[DataRequired()])
    rating = StringField("Rating", validators=[DataRequired()])
    time = StringField("Time", validators=[DataRequired()])
    img_url = StringField("Dish Image Url", validators=[DataRequired(), URL()])
    submit = SubmitField("Add Item")