
import time
from datetime import datetime, timedelta
import logging
from typing import Any 

logger = logging.getLogger(__name__)


_cache_storage = {} 
                    


class CacheService:
    DEFAULT_ATTEMPTS_FOR_OTP = 3

    @staticmethod
    def _generate_key(identifier: str, purpose: str) -> str:
        return f"{identifier.strip().lower()}_{purpose}"


    @staticmethod
    def set_value(key: str, value: Any, expires_in_seconds: int) -> None:
        """
        Зберігає будь-яке значення в кеші за ключем.
        key: Унікальний ключ.
        value: Значення для зберігання.
        expires_in_seconds: Час життя запису в секундах.
        """
        expires_at = datetime.now() + timedelta(seconds=expires_in_seconds)
        _cache_storage[key] = {
            'value': value,
            'expires_at': expires_at.timestamp()
        }
        logger.debug(f"CACHE: Збережено значення для ключа '{key}'. Дійсне до: {expires_at}")

    @staticmethod
    def get_value(key: str) -> Any | None:
        """
        Отримує значення з кешу за ключем.
        Повертає значення, якщо воно існує і не прострочене, інакше None.
        Автоматично видаляє прострочені записи при спробі доступу.
        """
        cached_entry = _cache_storage.get(key)
        if not cached_entry:
            logger.debug(f"CACHE: Ключ '{key}' не знайдено.")
            return None

        if time.time() > cached_entry['expires_at']:
            logger.debug(f"CACHE: Ключ '{key}' прострочено. Видалення.")
            if key in _cache_storage: del _cache_storage[key]
            return None
        
        logger.debug(f"CACHE: Отримано значення для ключа '{key}'.")
        return cached_entry.get('value')

    @staticmethod
    def delete_value(key: str) -> bool:
        """
        Видаляє запис з кешу за ключем.
        Повертає True, якщо ключ був знайдений та видалений, інакше False.
        """
        if key in _cache_storage:
            del _cache_storage[key]
            logger.debug(f"CACHE: Ключ '{key}' видалено.")
            return True
        logger.debug(f"CACHE: Ключ '{key}' не знайдено для видалення.")
        return False

  
    @staticmethod
    def save_otp_data(
        identifier: str, 
        purpose: str, 
        code: str, 
        expires_in_minutes: int, 
        attempts: int = DEFAULT_ATTEMPTS_FOR_OTP
    ) -> None:
        key = CacheService._generate_key(identifier, purpose)
        expires_at = datetime.now() + timedelta(minutes=expires_in_minutes)
       
        _cache_storage[key] = {
            'data': code, 
            'expires_at': expires_at.timestamp(),
            'attempts_left': attempts
        }
        logger.debug(f"CACHE (OTP): Збережено OTP для '{key}'. Код: '{code}', дійсний до: {expires_at}, спроб: {attempts}")

    @staticmethod
    def verify_otp_and_consume(identifier: str, purpose: str, code_to_check: str) -> str:
        key = CacheService._generate_key(identifier, purpose)
        cached_entry = _cache_storage.get(key)

        if not cached_entry:
            logger.debug(f"CACHE (OTP): OTP для ключа '{key}' не знайдено.")
            return "not_found"
        

        if 'data' not in cached_entry or 'expires_at' not in cached_entry or 'attempts_left' not in cached_entry:
            logger.warning(f"CACHE (OTP): Неправильний формат кешованих даних для OTP ключа '{key}'.")
            return "not_found" 

        if time.time() > cached_entry['expires_at']:
            logger.debug(f"CACHE (OTP): OTP для ключа '{key}' прострочено. Видалення.")
            if key in _cache_storage: del _cache_storage[key]
            return "expired"

        if cached_entry['attempts_left'] <= 0:
            logger.debug(f"CACHE (OTP): Для ключа '{key}' вичерпано спроби. Видалення.")
            if key in _cache_storage: del _cache_storage[key]
            return "no_attempts_left"

        if cached_entry['data'] == code_to_check:
            logger.debug(f"CACHE (OTP): Код '{code_to_check}' для ключа '{key}' вірний. Видалення.")
            if key in _cache_storage: del _cache_storage[key]
            return "valid"
        else:
            cached_entry['attempts_left'] -= 1
            logger.debug(f"CACHE (OTP): Код '{code_to_check}' для ключа '{key}' невірний. Спроб: {cached_entry['attempts_left']}.")
            if cached_entry['attempts_left'] <= 0:
                logger.debug(f"CACHE (OTP): Для ключа '{key}' вичерпано спроби після невірного введення. Видалення.")
                if key in _cache_storage: del _cache_storage[key]
                return "no_attempts_left"
            return "invalid_code"

    @staticmethod
    def clear_expired_entries() -> None:
        current_time = time.time()
       
        keys_to_delete = [
            key for key, entry in list(_cache_storage.items())
            if isinstance(entry, dict) and entry.get('expires_at') and current_time > entry['expires_at']
        ]
        for key in keys_to_delete:
            if key in _cache_storage:
                del _cache_storage[key]
                logger.debug(f"CACHE: Видалено прострочений запис '{key}'")

    @staticmethod
    def save_2fa_code(user_identifier: str, code: str, expires_in_minutes: int = 5) -> None:
        logger.warning("CACHE: Метод save_2fa_code є застарілим. Використовуйте save_otp_data.")
        CacheService.save_otp_data(user_identifier, "2fa_legacy", code, expires_in_minutes, CacheService.DEFAULT_ATTEMPTS_FOR_OTP)

    @staticmethod
    def verify_2fa_code(user_identifier: str, code_to_check: str) -> bool:
        logger.warning("CACHE: Метод verify_2fa_code є застарілим. Використовуйте verify_otp_and_consume.")
        status = CacheService.verify_otp_and_consume(user_identifier, "2fa_legacy", code_to_check)
        return status == "valid"