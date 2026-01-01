import random
import string
import logging

logger = logging.getLogger(__name__)

class PasswordGeneratorService:
    @staticmethod
    def generate_password(
        length: int = 16,
        use_uppercase: bool = True,
        use_lowercase: bool = True,
        use_digits: bool = True,
        use_special_chars: bool = True,
        special_chars_set: str = "!@#$%^&*()-_=+[]{};:,.<>/?"
    ) -> str | None:
        """
        Генерує пароль на основі заданих критеріїв.
        """

        if not (use_uppercase or use_lowercase or use_digits or use_special_chars):
            logger.warning("generate_password: Не обрано жодного типу символів. Повертається None.")
            return None

        character_pool = []
        if use_lowercase:
            character_pool.extend(string.ascii_lowercase)
        if use_uppercase:
            character_pool.extend(string.ascii_uppercase)
        if use_digits:
            character_pool.extend(string.digits)
        if use_special_chars:
            character_pool.extend(list(special_chars_set))

        if not character_pool or length <= 0:
            logger.warning(
                f"generate_password: character_pool порожній або length <= 0. "
                f"Pool empty: {not character_pool}, Length: {length}. Повертається None."
            )
            return None

        password_chars = []
        if use_lowercase:
            if not string.ascii_lowercase: logger.error("Константа string.ascii_lowercase порожня!"); return None
            password_chars.append(random.choice(string.ascii_lowercase))
        if use_uppercase:
            if not string.ascii_uppercase: logger.error("Константа string.ascii_uppercase порожня!"); return None
            password_chars.append(random.choice(string.ascii_uppercase))
        if use_digits:
            if not string.digits: logger.error("Константа string.digits порожня!"); return None
            password_chars.append(random.choice(string.digits))
        if use_special_chars:
            if not special_chars_set: logger.error("Набір special_chars_set порожній!"); return None
            password_chars.append(random.choice(list(special_chars_set)))
        
        current_length = len(password_chars)

        if length < current_length:
            try:
                sampled_chars = random.sample(password_chars, length)
                return "".join(sampled_chars)
            except ValueError as e:
                logger.error(f"generate_password: Помилка при random.sample: {e}. password_chars: {password_chars}, length: {length}")
                return None


        remaining_length = length - current_length

        if remaining_length > 0:
            if not character_pool:
                logger.error("generate_password: character_pool неочікувано порожній перед додаванням решти символів. Повертається None.")
                return None
            try:
                password_chars.extend(random.choices(character_pool, k=remaining_length))
            except Exception as e:
                logger.error(f"generate_password: Помилка при random.choices: {e}. character_pool size: {len(character_pool)}, k: {remaining_length}")
                return None


        random.shuffle(password_chars)
        final_password = "".join(password_chars)
        logger.info(
            f"generate_password: Успішно згенеровано пароль довжиною {len(final_password)}."
            f" (Запитана довжина: {length})"
        )
        return final_password

    @staticmethod
    def generate_memorable_password(num_words: int = 4, separator: str = "-") -> str | None:
        """
        Генерує пароль, що складається з випадкових слів (парольна фраза).
        Потребує списку слів.
        """
        common_words = [
            "apple", "banana", "orange", "grape", "melon", "lemon", "peach", "berry",
            "table", "chair", "house", "light", "mouse", "dream", "green", "happy",
            "cloud", "river", "ocean", "sunny", "stone", "paper", "music", "smile"
        ]
        if num_words <= 0 or not common_words:
            logger.warning(
                f"generate_memorable_password: num_words <= 0 або common_words порожній. "
                f"num_words: {num_words}, common_words empty: {not common_words}. Повертається None."
            )
            return None
        
        try:
            chosen_words = random.choices(common_words, k=num_words)
            final_passphrase = separator.join(chosen_words)
            logger.info(f"generate_memorable_password: Успішно згенеровано парольну фразу: '{final_passphrase}'")
            return final_passphrase
        except Exception as e:
            logger.error(f"generate_memorable_password: Помилка під час генерації: {e}", exc_info=True)
            return None

    @staticmethod
    def generate_pin_code(length: int = 6) -> str | None:
        """
        Генерує числовий PIN-код.
        """
        if length <= 0:
            logger.warning(f"generate_pin_code: length <= 0 ({length}). Повертається None.")
            return None
        try:
            pin_code = "".join([str(random.randint(0, 9)) for _ in range(length)])
            logger.info(f"generate_pin_code: Успішно згенеровано PIN-код довжиною {len(pin_code)}.")
            return pin_code
        except Exception as e:
            logger.error(f"generate_pin_code: Помилка під час генерації PIN-коду: {e}", exc_info=True)
            return None