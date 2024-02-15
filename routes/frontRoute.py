# routes/frontRoute.py
from flask import Blueprint, render_template
frontroute = Blueprint("frontroute", __name__)



@frontroute.route('/')
def home():
    from controllers.frontController import home_details
    return home_details()









