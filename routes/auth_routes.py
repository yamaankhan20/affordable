from flask import Blueprint, redirect, url_for, jsonify, current_app,  session, request, flash
from flask_login import logout_user, login_required, current_user
from authlib.integrations.flask_client import OAuth

auth_route = Blueprint("auth_route", __name__, url_prefix="/auth")



@auth_route.after_request
def add_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'DELETE, GET, POST, PUT'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response



@auth_route.route('/google-login', methods=['GET','POST'])
def google_login():
    from controllers.UserAuthentication import google_Login_done
    return google_Login_done()

@auth_route.route('/login', methods=['GET','POST'])
def login():
    from app import oauth
    from controllers.UserAuthentication import Loginverify
    token = ''
    if 'code' in request.args:
        # Exchange the authorization code for an access token
        token = oauth.Affordable.authorize_access_token()

    response = Loginverify(token)
    return response


@auth_route.route('/signup', methods=["GET", "POST"])
def signup():
    if "Email" in session:
        return redirect(url_for('adminRoute.admin_dashboard'))

    from controllers.UserAuthentication import registeration_verify
    return registeration_verify()


@auth_route.route('/logout')
def logout():
    if not "Email" in session:
        return redirect(url_for('auth_route.login'))
    session.clear()
    session.pop('Email', None)
    return redirect(url_for('frontroute.home'))





@auth_route.route('/forgot-password', methods= ['GET', 'POST'])
def forgot_password():
    from controllers.UserAuthentication import forgot_user_password
    return forgot_user_password()


@auth_route.route("/reset-password/<string:auth_token>/<string:forgot_token>", methods=['GET', 'POST'])
def reset_password(auth_token, forgot_token):
    from controllers.UserAuthentication import reset_password_user
    return reset_password_user(auth_token, forgot_token)