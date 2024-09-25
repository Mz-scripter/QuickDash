from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired,URL

class AddItemForm(FlaskForm):
    dish = StringField("Dish", validators=[DataRequired()])
    rating = StringField("Rating", validators=[DataRequired()])
    time = StringField("Time", validators=[DataRequired()])
    img_url = StringField("Dish Image Url", validators=[DataRequired(), URL()])
    submit = SubmitField("Add Item")