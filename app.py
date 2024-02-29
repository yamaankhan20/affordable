from flask import Flask
from flask_login import LoginManager
from models.database_connect import mysql
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
import json
from middleware.google_auth import oauth
from middleware.gmail_smtp import mail
app = Flask(__name__)
oauth.init_app(app)




with open('config.json', 'r') as c:
    parameters = json.load(c)["parameters"]

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = parameters["gmail"]
app.config['MAIL_PASSWORD'] = parameters["gmail_app_password"]
mail.init_app(app)

oauth.register(
    "Affordable",
    client_id="##################",
    client_secret="##################",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={'scope': f'openid profile email {parameters["Birthday_scope"]} {parameters["gender_scope"]} {parameters["phonenumbers_scope"]} {parameters["userinfo_email_scope"]} {parameters["userinfo_profile_scope"]}'}
)



app.config['MYSQL_HOST'] = parameters['DB_host']
app.config['MYSQL_USER'] = parameters['DB_user']
app.config['MYSQL_PASSWORD'] = parameters['DB_password']
app.config['MYSQL_DB'] = parameters['DB_name']
mysql.init_app(app)


app.secret_key = parameters['Secret_Key']
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view= "auth_route.login"

app.config['JWT_SECRET_KEY'] = parameters['JWT_SECRET_KEY']
# app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(seconds=10)
jwt = JWTManager(app)


@login_manager.user_loader
def load_user(id):
    from models.user_db import All_users
    get_USER = All_users
    return get_USER.load_user(id)


# ----------------------------------------------------------
# ------------------ ROUTES REGISTRATION -------------------
# ----------------------------------------------------------

#-----------------ROUTE REGISTERATION-----------------

from routes.frontRoute import frontroute
app.register_blueprint(frontroute)

from routes.auth_routes import auth_route
app.register_blueprint(auth_route)

from utils.user_APi import user_api
app.register_blueprint(user_api)


from routes.admin_routes import adminRoute
app.register_blueprint(adminRoute)


@app.errorhandler(404)
def page_not_found(error):
    from controllers.frontController import page_not_found_template
    return page_not_found_template()


#-----------------ROUTE REGISTERATION END-------------


if __name__ == "__main__":
    app.run(debug=True, port=200)
