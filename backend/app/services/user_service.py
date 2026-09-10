"""User management service (Administrator only)."""
import logging

from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import User
from app.utils.constants import AUDIT_CATEGORY_USER_MANAGEMENT
from app.utils.validators import (
    ValidationError,
    validate_email_address,
    validate_password,
    validate_role,
    validate_username,
)

logger = logging.getLogger("vulnscan.users")


class UserServiceError(Exception):
    pass


def _conflict(field):
    raise UserServiceError(f"A user with this {field} already exists.")


def list_users(search=None, include_inactive=True):
    query = User.query
    if search:
        like = f"%{search.strip()}%"
        query = query.filter(
            db.or_(
                User.Username.ilike(like),
                User.Email.ilike(like),
            )
        )
    return query.order_by(User.CreatedAt.desc()).all()


def get_user(user_id):
    return db.session.get(User, int(user_id))


def create_user(username, email, password, role):
    username = validate_username(username)
    email = validate_email_address(email)
    password = validate_password(password)
    role = validate_role(role)

    if User.query.filter_by(Username=username).first():
        _conflict("username")
    if User.query.filter_by(Email=email).first():
        _conflict("email")

    user = User(Username=username, Email=email, Role=role, IsActive=True)
    user.set_password(password)
    db.session.add(user)
    try:
        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        _conflict("username or email")
    return user


def update_user(user_id, *, username=None, email=None, role=None,
                password=None, is_active=None):
    user = get_user(user_id)
    if user is None:
        raise UserServiceError("User not found.")

    if username is not None:
        username = validate_username(username)
        existing = User.query.filter(User.Username == username,
                                     User.UserID != user.UserID).first()
        if existing:
            _conflict("username")
        user.Username = username

    if email is not None:
        email = validate_email_address(email)
        existing = User.query.filter(User.Email == email,
                                     User.UserID != user.UserID).first()
        if existing:
            _conflict("email")
        user.Email = email

    if role is not None:
        user.Role = validate_role(role)

    if password:
        validate_password(password)
        user.set_password(password)

    if is_active is not None:
        user.IsActive = bool(is_active)

    try:
        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        _conflict("username or email")
    return user


def disable_user(user_id):
    """
    Soft-delete: disables the account (documented behaviour of DELETE on users)
    so scan history and audit records remain intact.
    """
    user = get_user(user_id)
    if user is None:
        raise UserServiceError("User not found.")
    if user.Role == "Administrator" and user.IsActive:
        # Prevent locking out the last active administrator.
        active_admins = User.query.filter_by(
            Role="Administrator", IsActive=True
        ).count()
        if active_admins <= 1:
            raise UserServiceError(
                "Cannot disable the last active administrator account."
            )
    user.IsActive = False
    db.session.commit()
    return user
