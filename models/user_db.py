from app import mysql
from datetime import datetime, timedelta
import secrets
from flask import  session, redirect, url_for, flash, render_template
import jwt
from app import app
import requests
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Message
from middleware.gmail_smtp import mail
import socket


def generate_auth_token(length=32):
    # Generate a random token of the specified length
    token = secrets.token_hex(length)
    return token

def generate_jwt_token(user_data):
    expiration_date = datetime.now() + timedelta(days=1)
    exp_epoch_time = int(expiration_date.timestamp())
    date_str = user_data[4].isoformat() if isinstance(user_data[4], datetime) else None
    payload = {
        'id': user_data[0],
        'name': user_data[1],
        'email': user_data[2],
        'auth_token': user_data[3],
        'date': date_str,
        'role_id': f'{user_data[5]}',
        'exp': exp_epoch_time
    }
    token_encoded = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return f'Bearer {token_encoded}'

def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip_address = s.getsockname()[0]
    s.close()
    return ip_address

def get_location():
    ip_info_response = requests.get('https://ipinfo.io')
    ip_info = ip_info_response.json()

    # Get location details
    city = ip_info.get('city')
    region = ip_info.get('region')
    country = ip_info.get('country')
    postal = ip_info.get('postal')

    location_str = f"{city}, {region}, {country} - {postal}"
    return location_str


class All_users:
    def __init__(self):
        self.con = mysql.connection
        self.con.autocommit(True)
        self.cur = self.con.cursor()

    def load_user(self, id):
        self.cur.execute(f'SELECT * FROM all_users WHERE id = {id}')
        return self.cur.fetchall()

    def load_user_by_email(self, email):
        self.cur.execute(f"SELECT email FROM all_users WHERE email = '{email}'")
        result = self.cur.fetchone()
        return result


class User_check:
    def __init__(self):
        self.con = mysql.connection
        self.con.autocommit(True)
        self.cur = self.con.cursor()


    def User_login_model(self, data):
        if 'email' not in data or 'password' not in data:
            return flash("Email or password is missing", "danger")


        self.cur.execute(
            f"SELECT id, name, email, auth_token, date, role_id FROM all_users WHERE email='{data['email']}'")
        result = self.cur.fetchall()

        if not result:
            return flash("Invalid email or password", "danger")


        userData = result[0]

        session['token'] = generate_jwt_token(userData)

        fetch_user_for_login = self.con.cursor()
        fetch_user_for_login.execute(
            f"SELECT * FROM all_users WHERE email='{data['email']}'"
        )
        log_user = fetch_user_for_login.fetchone()
        fetch_user_for_login.close()

        if log_user and check_password_hash(log_user[3], data['password']):
            session['Email'] = log_user[2]
            flash(f'{userData[1]} Logged In Successfully!!!', 'success')

            mail_subject = 'You Have Been Logged In'
            device_name = socket.gethostname()
            ip_address = get_ip_address()
            location = get_location()
            msg = Message(
                    recipients=[f'{log_user[2]}'],
                    sender='khanyamaan1@gmail.com',
                    subject=mail_subject,
                    body=""
                )
            mail_data = {
                'App_name': "Affordable",
                "user_name": f"{log_user[1]}",
                "ip_address": ip_address,
                "device_name": device_name,
                "location": location
            }
            msg.html = render_template('emailTemplates/login.html', data=mail_data)
            # mail.send(msg)

            return True
        else:
            flash("Invalid email or password", "danger")
            return False

        # return log_user

    def User_roles_validate(self, url_validate, role_id):
        self.cur.execute(f'SELECT roles FROM accessibility_view WHERE endpoint = "{url_validate}"')
        result = self.cur.fetchall()
        if result:
            allowed_roles = result[0][0]
            allowed_roles = allowed_roles.replace('[', '').replace(']', '').replace("'", "")
            split_roles = allowed_roles.split(',')
            for diff in split_roles:
                if role_id == diff:
                    return True, role_id
                else:
                    return False, 'Error generating'
        return False, None

class register_User:
    def __init__(self):
        self.con = mysql.connection
        self.cur = self.con.cursor()

    def user_data_insert(self, name, email, password_hashed):
        token_random_generate = generate_auth_token()
        insert_user = self.con.cursor()
        insert_user.execute(
             f"INSERT INTO all_users (name, email, password, auth_token, date, role_id) VALUES ('{name}', '{email}', '{password_hashed}', '{token_random_generate}', '{datetime.now()}', '{3}')")
        insert_user.close()  # Close the cursor after executing the query
        return True

    def User_data_register_google_Id(self, name, email):
        token_random_generate_google = generate_auth_token()
        insert_user_google = self.con.cursor()
        insert_user_google.execute(
            f"INSERT INTO all_users (name, email, auth_token, date, role_id) VALUES ('{name}', '{email}', '{token_random_generate_google}', '{datetime.now()}', '{3}')")
        insert_user_google.close()  # Close the cursor after executing the query
        return True

class login_or_register_google:
    def __init__(self):
        self.con = mysql.connection
        self.cur = self.con.cursor()
    def Login_check(self, google_token):
        personDataUrl = f'https://people.googleapis.com/v1/people/me?personFields=birthdays,genders,phoneNumbers,emailAddresses,names'
        personData = requests.get(
            personDataUrl,
            headers={
                'Authorization': f"Bearer {google_token['access_token']}"
            }
        ).json()
        google_token['personData']= personData
        all_data_from_google = google_token
        user_email = all_data_from_google['userinfo']['email']
        user_name = all_data_from_google['userinfo']['name']
        self.cur.execute(f"SELECT email FROM all_users WHERE email = '{user_email}'")
        result = self.cur.fetchone()

        Get_User_data = self.con.cursor()
        Get_User_data.execute(
            f"SELECT id, name, email, auth_token, date, role_id FROM all_users WHERE email='{user_email}'")
        google_data = Get_User_data.fetchall()


        if result:
            userData_By_google = google_data[0]
            get_token_generate_JWT = generate_jwt_token(userData_By_google)

            session['Email'] = user_email
            session['token'] = get_token_generate_JWT

            mail_subject = 'You Have Been Logged In From Your Google Account'
            device_name = socket.gethostname()
            ip_address = get_ip_address()
            location = get_location()
            msg = Message(
                recipients=[f'{user_email}'],
                sender='khanyamaan1@gmail.com',
                subject=mail_subject,
                body=""
            )
            mail_data = {
                'App_name': "Affordable",
                "user_name": f"{user_name}",
                "ip_address": ip_address,
                "device_name": device_name,
                "location": location
            }
            msg.html = render_template('emailTemplates/login.html', data=mail_data)
            # mail.send(msg)

            return redirect(url_for('adminRoute.admin_dashboard'))
        else:
            rgstr_User = register_User()
            insert_data = rgstr_User.User_data_register_google_Id(user_name, user_email)

            if insert_data:

                Get_google_inserted_User_data = self.con.cursor()
                Get_google_inserted_User_data.execute(
                    f"SELECT id, name, email, auth_token, date, role_id FROM all_users WHERE email='{user_email}'"
                )
                Inserted_google_data = Get_google_inserted_User_data.fetchall()
                if Inserted_google_data:
                    Inserted_userData_By_google = Inserted_google_data[0]
                    get_token_generate_JWT_for_google = generate_jwt_token(Inserted_userData_By_google)

                    flash("You are registered!", "success")
                    flash("Please Setup Your Password Before Logging Out", "warning")
                    session['Email'] = user_email
                    session['token'] = get_token_generate_JWT_for_google

                    mail_subject = 'You Have Been Logged In And Registered From Your Google Account'
                    device_name = socket.gethostname()
                    ip_address = get_ip_address()
                    location = get_location()
                    msg = Message(
                        recipients=[f'{user_email}'],
                        sender='khanyamaan1@gmail.com',
                        subject=mail_subject,
                        body=""
                    )
                    mail_data = {
                        'App_name': "Affordable Logged In And Registered",
                        "user_name": f"{user_name}",
                        "ip_address": ip_address,
                        "device_name": device_name,
                        "location": location
                    }
                    msg.html = render_template('emailTemplates/login.html', data=mail_data)
                    # mail.send(msg)

                    return redirect(url_for('adminRoute.admin_dashboard'))
            else:
                flash('Something Is Wrong', 'danger')


def generate_jwt_token_forgot_password(email, auth_token):
    expiration_date = datetime.now() + timedelta(minutes=15)
    exp_epoch_time = int(expiration_date.timestamp())
    payload = {
        'email': email,
        'auth_token': auth_token,
        'exp': exp_epoch_time
    }
    token_encoded = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return f'Forgot-password {token_encoded}'

class change_password:
    def __init__(self):
        self.con = mysql.connection
        self.cur = self.con.cursor()

    def setNew_password(self, email, password):
        insert_user_google = self.con.cursor()
        insert_user_google.execute(
            f"UPDATE all_users SET password = '{password}' WHERE email = '{email}'")
        insert_user_google.close()
        return True

    def setNew_password_forgot_user(self, email, password):
        insert_user_forgot_user = self.con.cursor()
        insert_user_forgot_user.execute(
            f"UPDATE all_users SET password = '{password}' WHERE email = '{email}'"
        )
        self.con.commit()  # Commit the transaction to make changes permanent
        insert_user_forgot_user.close()  # Close the cursor after executing the query
        return True

    def load_user_by_email(self, email):
        self.cur.execute(f"SELECT email FROM all_users WHERE email = '{email}'")
        result = self.cur.fetchone()
        return result

    def reset_password(self, email):
        Get_User_data = self.con.cursor()
        Get_User_data.execute(
            f"SELECT auth_token FROM all_users WHERE email='{email}'")
        reset_data = Get_User_data.fetchall()


        if reset_data:
            all_data = reset_data[0]
            create_token_forgot_password = generate_jwt_token_forgot_password(email, all_data[0])
            session['forgot-token'] = create_token_forgot_password
            mail_subject = 'Reset Password Requested'
            reset_link = f'http://127.0.0.1:200{url_for("auth_route.reset_password", auth_token=all_data[0], forgot_token=create_token_forgot_password)}'
            msg = Message(
                recipients=[f'{email}'],
                sender='khanyamaan1@gmail.com',
                subject=mail_subject,
                body=""
            )
            mail_data = {
                "reset_link": reset_link
            }
            msg.html = render_template('emailTemplates/forgotpassword-template.html', data=mail_data)
            mail.send(msg)
            return True

