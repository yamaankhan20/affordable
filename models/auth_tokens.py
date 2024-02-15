from flask import request, jsonify, current_app, make_response, session, redirect, url_for, flash
import jwt
from functools import wraps

class JWTAuthentication:

    def __call__(self, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            endpoints = request.url_rule
            from models.user_db import User_check
            usr_chk = User_check()
            # token = request.headers.get('Authorization')

            token = session.get('token')

            if not token:
                flash('Login To Proceed!!!', 'danger')
                return redirect(url_for('auth_route.login'))

            splited_token = token.split(' ')

            try:
                payload = jwt.decode(splited_token[1], current_app.config['SECRET_KEY'], algorithms=['HS256'])
                role_id = payload['role_id']
                is_allowed, roles_id = usr_chk.User_roles_validate(endpoints, role_id)
                if not is_allowed:
                    return redirect(url_for('auth_route.login'))

                return func(roles_id, *args, **kwargs)

            except jwt.ExpiredSignatureError:
                flash('You have been Logged out. Login to continue', 'danger')
                session.clear()
                return redirect(url_for('auth_route.login'))
            except jwt.InvalidTokenError:
                flash('You have been Logged out. Login to continue', 'danger')
                session.clear()
                return redirect(url_for('auth_route.login'))

        return wrapper

