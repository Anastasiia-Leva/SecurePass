

from . import db
from datetime import datetime

class User(db.Model):
    __tablename__ = 'user'
    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_2fa_enabled = db.Column(db.Boolean, default=True, nullable=False)
    is_email_verified = db.Column(db.Boolean, default=False, nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    lockout_until = db.Column(db.DateTime, nullable=True)
    auto_logout_enabled = db.Column(db.Boolean, default=True, nullable=False) 
    night_mode_enabled = db.Column(db.Boolean, default=True, nullable=False)

    google_id = db.Column(db.String(255), unique=True, nullable=True)

    password_entries = db.relationship(
        'PasswordEntry',
        backref='author',
        lazy=True,
        cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"User('{self.email}')"