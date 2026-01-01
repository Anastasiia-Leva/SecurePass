

from domain.user import User
from domain import db
from datetime import datetime

class UserRepository:
    def get_by_id(self, user_id: int) -> User | None:
        return db.session.get(User, user_id)

    def get_by_email(self, email: str) -> User | None:
        return User.query.filter_by(email=email.strip().lower()).first()

    def get_by_google_id(self, google_id_str: str) -> User | None:
        if not google_id_str:
            return None
        return User.query.filter_by(google_id=google_id_str).first()

    def add_user(self, name: str, email: str, password_hash: str, 
                 google_id: str | None = None, 
                 is_email_verified_on_creation: bool = False) -> User:
        new_user = User(
            name=name.strip(),
            email=email.strip().lower(),
            password_hash=password_hash,
            is_email_verified=is_email_verified_on_creation,
            google_id=google_id

        )
        db.session.add(new_user)
        db.session.commit()
        return new_user

    def update_user(self, user: User, **kwargs) -> User:
        for key, value in kwargs.items():
            if hasattr(user, key):
                setattr(user, key, value)
        db.session.commit()
        return user

    def delete_user(self, user: User) -> None:
        db.session.delete(user)
        db.session.commit()

    def increment_failed_attempts(self, user: User) -> None:
        user.failed_login_attempts += 1
        db.session.commit()

    def reset_failed_attempts(self, user: User) -> None:
        user.failed_login_attempts = 0
        db.session.commit()

    def set_lockout_time(self, user: User, lockout_until: datetime | None) -> None:
        user.lockout_until = lockout_until
        db.session.commit()