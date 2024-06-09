#!/usr/bin/env python3
"""
Vew that handles all routes for the Session authentication.
"""
from os import getenv
from typing import Tuple, Any

from api.v1.views import app_views
from flask import abort, jsonify, request
from models.user import User


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login() -> Tuple[Any, int]:
    """

    :return:
    """

    email = request.form.get('email')
    password = request.form.get('password')

    if not email:
        return jsonify({"error": "email missing"}), 400
    if not password:
        return jsonify({"error": "password missing"}), 400

    users = User.search({'email': email})

    if not users:
        return jsonify({"error": "no user found for this email"}), 404

    for user in users:
        if user.is_valid_password(password):
            from api.v1.auth.session_auth import SessionAuth
            session_auth = SessionAuth()
            session_id = session_auth.create_session(user.id)
            response = jsonify(user.to_json())
            response.set_cookie(getenv('SESSION_NAME'), session_id)
            return response
        else:
            return jsonify({"error": "wrong password"}), 401


@app_views.route('/auth_session/logout', methods=['DELETE'],
                 strict_slashes=False)
def logout() -> Tuple[Any, int]:
    """

    :return:
    """

    from api.v1.auth.session_auth import SessionAuth
    session_auth = SessionAuth()
    session_id = session_auth.destroy_session(request)
    if not session_id:
        abort(404)
    else:
        response = jsonify({}, 200)
        response.set_cookie(getenv('SESSION_NAME'), '')
    return response
