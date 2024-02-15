from flask import render_template, request, current_app, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash
from app import oauth
import secrets
from wtforms.validators import ValidationError
import jwt


def Loginverify(google_login_token):
    from models.user_db import User_check, login_or_register_google
    from forms.login_register import LoginFrom

    if "Email" in session:
        return redirect(url_for('adminRoute.admin_dashboard'))

    form = LoginFrom()
    Log_verification = User_check()
    google_login_check = login_or_register_google()

    if google_login_token:
        done_login = google_login_check.Login_check(google_login_token)
        return done_login
        # if done_login:
            # return redirect(url_for('adminRoute.admin_dashboard'))


    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        all_details = {'email': email, 'password': password}
        usr_verify = Log_verification.User_login_model(all_details)
        if usr_verify:
            if 'token' and 'Email' in session:
                # flash('You Are Already Logged In', 'success')
                return redirect(url_for('adminRoute.admin_dashboard'))
            else:
                flash("Error Logged In", 'danger')
                return redirect(url_for('auth_route.login'))
    return render_template('authentication/login.html', form= form)

def registeration_verify():
    from forms.login_register import RegisterationFrom
    from models.user_db import register_User
    user_data = register_User()
    form = RegisterationFrom()
    if "Email" in session:
        flash('You Are Already Registered', 'success')
        return redirect(url_for('adminRoute.admin_dashboard'))
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password_hashed = generate_password_hash(form.password.data)
        new_User = user_data.user_data_insert(name, email, password_hashed)
        if new_User:
            flash("You are registered!", "success")
        else:
            flash('Something Is Wrong', 'danger')

        return redirect(url_for('auth_route.login'))
    return render_template('authentication/register.html', form=form)


def google_Login_done():
    csrf_state = secrets.token_urlsafe(16)
    session['csrf_state'] = csrf_state

    return oauth.Affordable.authorize_redirect(
        redirect_uri=url_for('auth_route.login', _external=True),
        state=csrf_state  # Include the CSRF state parameter in the authorization request
    )

def forgot_user_password():
    from models.user_db import All_users, change_password
    # user = All_users()
    chnge_pswrd = change_password()

    email = request.form.get('forgotemail')

    # email_check = chnge_pswrd.load_user_by_email(email)
    if email:
        if not chnge_pswrd.load_user_by_email(email):
            flash('Email not found', 'danger')
            return redirect(url_for('auth_route.forgot_password'))

        give_data_to_db = chnge_pswrd.reset_password(email)
        if give_data_to_db:
            flash('Email Is Sent!!!', 'success')
            return redirect(url_for('auth_route.forgot_password'))

    return render_template('authentication/forgot-password.html')


def reset_password_user(auth_token, forgot_token):
    from forms.login_register import Confirm_Password
    from models.user_db import change_password

    form = Confirm_Password()
    chnge_password = change_password()

    forgot_token_url = forgot_token

    splited_token = forgot_token_url.split(' ')

    if not forgot_token:
        return redirect(url_for('auth_route.forgot_password'))

    try:
        payload = jwt.decode(splited_token[1], current_app.config['SECRET_KEY'], algorithms=['HS256'])
        email = payload['email']
        # auth_token = payload['auth_token']

        if form.validate_on_submit():
            password_hashed = generate_password_hash(form.password.data)
            # return password_hashed
            insert_new_password = chnge_password.setNew_password_forgot_user(email, password_hashed)
            # return insert_new_password
            if insert_new_password:
                flash("Password is changed!!!", "success")
                return redirect(url_for('auth_route.login'))
            else:
                flash('Can\'t Change The Password ', 'danger')

    except jwt.ExpiredSignatureError:
        flash('Link Has Been Expired!!!', 'danger')
        return redirect(url_for('auth_route.forgot_password'))
    except jwt.InvalidTokenError:
        flash('Link Has Been Expired!!!', 'danger')
        return redirect(url_for('auth_route.forgot_password'))

    return render_template('authentication/reset-password.html', form=form, auth_token=auth_token, forgot_token= forgot_token)
