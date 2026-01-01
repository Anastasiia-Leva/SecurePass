

from werkzeug.security import generate_password_hash, check_password_hash

class HashingUtility:
    @staticmethod
    def hash_password(password: str) -> str:
        """
        хеш для наданого пароля.
         метод  з werkzeug.security
        ( pbkdf2:sha256).
        """
        return generate_password_hash(password)

    @staticmethod
    def verify_password(hashed_password: str, password_to_check: str) -> bool:
        """
        чи наданий пароль відповідає збереженому хешу.
        """
        return check_password_hash(hashed_password, password_to_check)

