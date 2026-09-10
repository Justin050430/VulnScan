"""Authorization helpers (RBAC) built on Flask-JWT-Extended."""
import functools

from flask import jsonify
from flask_jwt_extended import current_user, jwt_required

from app.utils.constants import ROLE_ADMINISTRATOR, ROLE_DEVELOPER


def get_current_user():
    return current_user


def roles_required(*roles):
    """
    Decorator that requires authentication and one of the given roles.
    Usage: @roles_required('Administrator')  or  @roles_required('Administrator', 'Developer')
    """

    def decorator(fn):
        @functools.wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            user = current_user
            if user is None:
                return (
                    jsonify(
                        {
                            "message": "Authentication required.",
                            "code": "token_invalid",
                        }
                    ),
                    401,
                )
            if user.Role not in roles:
                return (
                    jsonify(
                        {
                            "message": "You do not have permission to perform this action.",
                            "code": "forbidden",
                        }
                    ),
                    403,
                )
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def admin_required(fn):
    return roles_required(ROLE_ADMINISTRATOR)(fn)


def any_authenticated(fn):
    return roles_required(ROLE_ADMINISTRATOR, ROLE_DEVELOPER)(fn)
