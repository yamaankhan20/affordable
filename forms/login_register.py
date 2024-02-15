from flask import flash, Blueprint
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField, validators, BooleanField, TextAreaField, HiddenField,  SelectField
from wtforms.validators import InputRequired, Length, ValidationError, Email, DataRequired, EqualTo
from models.user_db import All_users



class RegisterationFrom(FlaskForm):
    name = StringField(validators=[InputRequired(), Length(min=1, max=40)], render_kw={"class": "form-control", "placeholder" : "Name"})
    email = StringField('Email', validators=[DataRequired(), InputRequired(), Email()], render_kw={"class": "form-control", "placeholder": "Email"})
    password = PasswordField("password", validators=[InputRequired(), EqualTo('confirm_password', message='Passwords Must Match!'), Length(min=5, max=225)], render_kw={"class": "form-control", "placeholder" : "Password"})
    confirm_password = PasswordField("Comfirm Password", validators=[InputRequired(), Length(min=5, max=225)], render_kw={"class": "form-control", "placeholder" : "Comfirm Password"})
    submit = SubmitField("Submit & Register", render_kw={"class": "btn btn-fill-out btn-block hover-up font-weight-bold"})

    def validate_email(self, email):
        user_data = All_users()
        existing_email = user_data.load_user_by_email(email.data)
        if existing_email:
            flash('Email already registered', 'danger')
            raise ValidationError('Email already registered')

class LoginFrom(FlaskForm):
    email = StringField(validators=[InputRequired(), Length(
        min= 1, max=40)], render_kw = {"class":"form-control mb-3", "placeholder":"Email *"})
    password = PasswordField(validators=[InputRequired(), Length(
        min= 5, max=225)], render_kw = {"class":"form-control", "placeholder":"Your password *"})
    submit = SubmitField("Login", render_kw = {"class":"btn btn-primary btn-lg"})


class Confirm_Password(FlaskForm):
    password = PasswordField("password",
                             validators=[InputRequired(), EqualTo('confirm_password', message='Passwords Must Match!'),
                                         Length(min=5, max=225)],
                             render_kw={"class": "form-control", "placeholder": "Password"})
    confirm_password = PasswordField("Comfirm Password", validators=[InputRequired(), Length(min=5, max=225)],
                                     render_kw={"class": "form-control", "placeholder": "Comfirm Password"})

