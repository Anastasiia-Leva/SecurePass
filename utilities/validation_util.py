import re

class ValidationUtility:
    @staticmethod
    def is_valid_email(email: str) -> bool:
        """
        Перевірка базової валідність формату email.
        """
        if not email:
            return False
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return re.match(pattern, email) is not None

    @staticmethod
    def is_password_strong_enough(password: str, min_length: int = 8) -> bool:
        """
        Перевірка базових критерії складності пароля.
        """
        if not password or len(password) < min_length:
            return False
        return True