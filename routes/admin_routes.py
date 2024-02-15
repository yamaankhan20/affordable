# routes/frontRoute.py
from flask import Blueprint, render_template, session
from models.auth_tokens import JWTAuthentication


adminRoute = Blueprint("adminRoute", __name__, url_prefix='/admin')



@adminRoute.route('/dashboard', methods=['GET', 'POST'])
@JWTAuthentication()
def admin_dashboard(role_id):
    from controllers.adminController import admin_dashboard
    return admin_dashboard()

@adminRoute.route('/dashboard-edit', methods= ['GET', 'POST'])
@JWTAuthentication()
def dashboard_edit(role_id):
    from controllers.adminController import dashboard_user_details
    return dashboard_user_details()


@adminRoute.route('/dashboard-password', methods=['GET', 'POST'])
@JWTAuthentication()
def dashboard_password_google_user(role_id):
    from controllers.adminController import confirm_password
    return confirm_password()

