from flask import Blueprint, jsonify, request

user_api = Blueprint('user_api', __name__, url_prefix="/API")


@user_api.after_request
def add_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'DELETE, GET, POST, PUT'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response

@user_api.route('/users', methods=['GET', 'POST'])
def get_user():
    from models.user_db import All_users
    user_db = All_users()
    user_data = user_db.get_user()
    # if user_data:
    return user_data
    # else:
    #     return jsonify({'message': 'User not found'}), 404


@user_api.route('/add-users', methods=['GET', 'POST'])
def add_user():
    from models.user_db import All_users
    user_db = All_users()
    return user_db.add_new_user(request.form)

@user_api.route('/update-users', methods=['PUT'])
def update_users():
    from models.user_db import All_users
    user_db = All_users()
    return user_db.update_user(request.form)


@user_api.route('/delete-users/<int:user_ID>', methods=['GET', 'POST'])
def delete_users(user_ID):
    from models.user_db import All_users
    user_db = All_users()
    return user_db.delete_User(user_ID)

@user_api.route('/patch-users/<int:user_ID>', methods=['DELETE'])
def patch_users(user_ID):
    from models.user_db import All_users
    user_db = All_users()
    return user_db.patch_User(request.form, user_ID)