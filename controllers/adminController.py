from flask import render_template, request, current_app, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash


def admin_dashboard():
    return render_template('admin/dashboard.html')

def dashboard_user_details():
    return render_template('admin/profile-setting.html')

def confirm_password():
    from forms.login_register import Confirm_Password
    from models.user_db import change_password
    form = Confirm_Password()
    chnge_password = change_password()

    user_email = session['Email']

    if form.validate_on_submit():
        password_hashed = generate_password_hash(form.password.data)
        insert_new_password = chnge_password.setNew_password(user_email, password_hashed)
        if insert_new_password:
            flash("Password is changed!!!", "success")
            return redirect(url_for('adminRoute.admin_dashboard'))
        else:
            flash('Can\'t Change The Password ', 'danger')
    return render_template('admin/new-password.html', form=form)