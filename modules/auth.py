"""
auth.py
--------
Role-based session authentication, backed by database.py's users table.

Three roles: administrator, soc_analyst, student.
Login checks the DB (not a hardcoded dict anymore), and the session stores
enough info (user_id, username, role, org_id) for every route to make
access-control decisions without hitting the DB again on every request.
"""

from functools import wraps
from flask import session, redirect, url_for, request, jsonify
from werkzeug.security import check_password_hash

from modules import database


def verify_login(username, password):
    """
    Returns the user dict (from the DB) if credentials are valid, else None.
    Never returns the password_hash to callers beyond this function.
    """
    user = database.get_user_by_username(username)
    if user and check_password_hash(user["password_hash"], password):
        return user
    return None


def login_user_session(user):
    """Stores the minimal info needed in the session after a successful login."""
    session["user_id"] = user["user_id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    session["org_id"] = user["org_id"]


def current_user():
    """Convenience accessor for the logged-in user's session info, or None."""
    if not session.get("user_id"):
        return None
    return {
        "user_id": session["user_id"],
        "username": session["username"],
        "role": session["role"],
        "org_id": session["org_id"]
    }


def login_required(view_func):
    """Any logged-in user (any role) can access - for PAGE routes."""
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("home"))
        return view_func(*args, **kwargs)
    return wrapped


def role_required(*allowed_roles):
    """
    Restricts a PAGE route to specific roles, e.g. @role_required('administrator').
    Not logged in -> sent to the portal selection page (there's no single
    unified login anymore, so we can't guess which portal they wanted).
    Logged in with the WRONG role -> sent to their own dashboard instead
    of a raw 403 - friendlier, and avoids leaking that the page exists at
    all to roles that shouldn't know about it.
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user:
                return redirect(url_for("home"))
            if user["role"] not in allowed_roles:
                return redirect(url_for("role_home", role=user["role"]))
            return view_func(*args, **kwargs)
        return wrapped
    return decorator


def api_login_required(view_func):
    """Any logged-in user - for API/JSON routes. Returns 401 JSON, not a redirect."""
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"error": "unauthorized", "message": "Please log in."}), 401
        return view_func(*args, **kwargs)
    return wrapped


def api_role_required(*allowed_roles):
    """Role-restricted API routes - 403 JSON if logged in but wrong role."""
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user:
                return jsonify({"error": "unauthorized", "message": "Please log in."}), 401
            if user["role"] not in allowed_roles:
                return jsonify({"error": "forbidden", "message": "Not permitted for your role."}), 403
            return view_func(*args, **kwargs)
        return wrapped
    return decorator
