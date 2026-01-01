from repositories.user_repository import UserRepository
from utilities.hashing_util import HashingUtility
from cache.cache_service import CacheService
from external.email_service import EmailService
from domain.user import User

import random
from datetime import datetime, timedelta
import logging
import time

logger = logging.getLogger(__name__)

class AuthService:
    MAX_LOGIN_ATTEMPTS = 3
    LOCKOUT_DURATION_MINUTES = 10
    VERIFICATION_CODE_EXPIRY_MINUTES = 10
    TWO_FA_CODE_EXPIRY_MINUTES = 3
    PASSWORD_CHANGE_OTP_EXPIRY_MINUTES = 5
    OTP_CODE_ATTEMPTS = 3

    def __init__(
        self,
        user_repository: UserRepository,
        hashing_utility: HashingUtility,
        cache_service: CacheService,
        email_service: EmailService
    ):
        self.user_repository = user_repository
        self.hashing_utility = hashing_utility
        self.cache_service = cache_service
        self.email_service = email_service

    def _generate_short_code(self, length: int = 6) -> str:
        return "".join([str(random.randint(0, 9)) for _ in range(length)])

    def register_user(self, name: str, email: str, plain_password: str) -> tuple[User | None, str | None]:
        email_cleaned = email.strip().lower()
        if self.user_repository.get_by_email(email_cleaned):
            return None, "Користувач з таким email вже існує."
        if len(plain_password) < 8:
            return None, "Пароль має містити щонайменше 8 символів."
        hashed_password = self.hashing_utility.hash_password(plain_password)
        verification_code_for_email = self._generate_short_code()
        try:
            new_user = self.user_repository.add_user(
                name=name, email=email_cleaned, password_hash=hashed_password,
                is_email_verified_on_creation=False
            )
            self.cache_service.save_otp_data(
                identifier=email_cleaned, purpose="email_verification", code=verification_code_for_email,
                expires_in_minutes=AuthService.VERIFICATION_CODE_EXPIRY_MINUTES,
                attempts=AuthService.OTP_CODE_ATTEMPTS
            )
            if not self.email_service.send_verification_code_email(email_cleaned, verification_code_for_email):
                logger.error(f"Не вдалося надіслати код верифікації на {email_cleaned}")
            return new_user, "Реєстрація успішна! Код підтвердження надіслано."
        except Exception as e:
            logger.error(f"Помилка реєстрації {email_cleaned}: {e}", exc_info=True)
            return None, "Внутрішня помилка реєстрації."

    def verify_email_address(self, email: str, code_from_user: str) -> tuple[User | None, str]:
        email_cleaned = email.strip().lower()
        status = self.cache_service.verify_otp_and_consume(email_cleaned, "email_verification", code_from_user)
        message_map = {
            "invalid_code": "Невірний код.", "no_attempts_left": "Вичерпано спроби.",
            "expired": "Код прострочений.", "not_found": "Код не знайдено або час дії вийшов."
        }
        if status == "valid":
            user = self.user_repository.get_by_email(email_cleaned)
            if user:
                try:
                    if not user.is_email_verified:
                        self.user_repository.update_user(user, is_email_verified=True)
                    return user, "Email успішно підтверджено!"
                except Exception as e:
                    logger.error(f"Помилка оновлення is_email_verified для {email_cleaned}: {e}", exc_info=True)
                    return None, "Помилка підтвердження email."
            logger.error(f"Користувача {email_cleaned} не знайдено після валідного OTP.")
            return None, "Помилка системи: користувача не знайдено."
        return None, message_map.get(status, "Невідома помилка коду.")

    def resend_verification_email(self, email: str) -> tuple[bool, str]:
        email_cleaned = email.strip().lower()
        user = self.user_repository.get_by_email(email_cleaned)
        if not user: return False, "Користувача не знайдено."
        if user.is_email_verified: return False, "Email вже підтверджено."
        
        new_code = self._generate_short_code()
        try:
            self.cache_service.save_otp_data(
                identifier=email_cleaned, purpose="email_verification", code=new_code,
                expires_in_minutes=AuthService.VERIFICATION_CODE_EXPIRY_MINUTES,
                attempts=AuthService.OTP_CODE_ATTEMPTS
            )
            if self.email_service.send_verification_code_email(email_cleaned, new_code):
                return True, "Новий код надіслано."
            return False, "Не вдалося надіслати новий код."
        except Exception as e:
            logger.error(f"Помилка повторного надсилання коду для {email_cleaned}: {e}", exc_info=True)
            return False, "Виникла помилка при повторному надсиланні коду."

    def login_user(self, email: str, plain_password: str) -> tuple[User | None, str, bool]:
        email_cleaned = email.strip().lower()
        user = self.user_repository.get_by_email(email_cleaned)

        if not user:
            logger.warning(f"Невдала спроба входу для неіснуючого email: {email_cleaned}.")
            return None, "Невірний email або пароль.", False

        if user.lockout_until and user.lockout_until > datetime.now():
            remaining_time = user.lockout_until - datetime.now()
            minutes_remaining = max(0, int(remaining_time.total_seconds() / 60) + (1 if remaining_time.seconds % 60 > 0 else 0))
            logger.warning(f"Спроба входу для заблокованого акаунту: {email_cleaned}. Залишилось блокування: {minutes_remaining} хв.")
            return None, f"Акаунт тимчасово заблоковано. Спробуйте через {minutes_remaining} хв.", False
        
        if not self.hashing_utility.verify_password(user.password_hash, plain_password):
            logger.warning(f"Невдала спроба входу (невірний пароль) для: {email_cleaned}.")
            try:
                self.user_repository.increment_failed_attempts(user)
                user_refreshed = self.user_repository.get_by_id(user.user_id)
                if user_refreshed and user_refreshed.failed_login_attempts >= AuthService.MAX_LOGIN_ATTEMPTS:
                    lock_until = datetime.now() + timedelta(minutes=AuthService.LOCKOUT_DURATION_MINUTES)
                    self.user_repository.set_lockout_time(user_refreshed, lock_until)
                    self.user_repository.reset_failed_attempts(user_refreshed)
                    logger.warning(f"Акаунт {email_cleaned} заблоковано на {AuthService.LOCKOUT_DURATION_MINUTES} хв через перевищення спроб входу.")
                    return None, f"Акаунт заблоковано на {AuthService.LOCKOUT_DURATION_MINUTES} хв через велику кількість невдалих спроб. Спробуйте пізніше.", False
            except Exception as e:
                logger.error(f"Помилка обробки невдалого входу для {email_cleaned}: {e}", exc_info=True)
            return None, "Невірний email або пароль.", False

        try:
            if user.failed_login_attempts > 0 or user.lockout_until:
                self.user_repository.reset_failed_attempts(user)
                if user.lockout_until:
                    self.user_repository.set_lockout_time(user, None)
        except Exception as e:
            logger.error(f"Помилка скидання лічильника/блокування для {email_cleaned} при успішному вході: {e}", exc_info=True)

        if not user.is_email_verified:
            logger.info(f"Спроба входу для {email_cleaned}, але email не підтверджено.")
            return None, "Будь ласка, спочатку підтвердіть вашу email-адресу.", False

        if user.is_2fa_enabled:
            two_fa_code = self._generate_short_code()
            try:
                self.cache_service.save_otp_data(
                    identifier=user.email, purpose="2fa_login", code=two_fa_code,
                    expires_in_minutes=AuthService.TWO_FA_CODE_EXPIRY_MINUTES,
                    attempts=AuthService.OTP_CODE_ATTEMPTS
                )
                if self.email_service.send_2fa_code_email(user.email, two_fa_code):
                    logger.info(f"2FA код надіслано для {user.email} при вході.")
                    return user, "Потрібна двофакторна автентифікація. Код надіслано на ваш email.", True
                else:
                    logger.error(f"Не вдалося надіслати 2FA код для {user.email} при вході.")
                    return None, "Не вдалося надіслати код двофакторної автентифікації. Спробуйте ще раз.", False
            except Exception as e:
                logger.error(f"Помилка генерації/надсилання 2FA коду для {user.email}: {e}", exc_info=True)
                return None, "Помилка системи при обробці 2FA. Спробуйте ще раз.", False
        
        logger.info(f"Успішний вхід для {user.email} (2FA вимкнено).")
        return user, "Вхід успішний!", False
        
    def verify_2fa_for_login_and_get_user(self, user_email: str, code_from_user: str) -> tuple[bool, User | None, str]:
        email_cleaned = user_email.strip().lower()
        status = self.cache_service.verify_otp_and_consume(email_cleaned, "2fa_login", code_from_user)
        
        message_map = {
            "invalid_code": "Невірний 2FA код.",
            "no_attempts_left": "Вичерпано спроби введення 2FA коду. Спробуйте увійти знову.",
            "expired": "Час дії 2FA коду вийшов. Спробуйте увійти знову.",
            "not_found": "Дані для 2FA не знайдено або час дії вийшов. Спробуйте увійти знову."
        }

        if status == "valid":
            user = self.user_repository.get_by_email(email_cleaned)
            if user:
                logger.info(f"2FA успішно пройдено для {email_cleaned}.")
                return True, user, "Двофакторну автентифікацію успішно пройдено."
            else:
                logger.error(f"Користувача {email_cleaned} не знайдено після валідного 2FA OTP.")
                return False, None, "Помилка системи: користувача не знайдено після перевірки 2FA."
        else:
            logger.warning(f"Невдала спроба 2FA для {email_cleaned}. Статус: {status}, наданий код: {code_from_user}")
            return False, None, message_map.get(status, "Невідома помилка при перевірці 2FA коду.")

    def toggle_2fa_status(self, user_id: int, enable: bool) -> tuple[bool, str]:
        user = self.user_repository.get_by_id(user_id)
        if not user:
            logger.warning(f"Користувача {user_id} не знайдено при спробі змінити статус 2FA.")
            return False, "Користувача не знайдено."

        if enable:
            if not user.is_email_verified:
                logger.info(f"Спроба увімкнути 2FA для user_id {user_id}, але email не підтверджено.")
                return False, "Будь ласка, спочатку підтвердіть вашу email-адресу, перш ніж вмикати 2FA."
            if user.is_2fa_enabled:
                logger.info(f"2FA вже увімкнено для user_id {user_id}.")
                return False, "Двофакторна автентифікація вже увімкнена."
            try:
                self.user_repository.update_user(user, is_2fa_enabled=True)
                logger.info(f"2FA успішно увімкнено для user_id {user_id}.")
                return True, "Двофакторну автентифікацію успішно увімкнено."
            except Exception as e:
                logger.error(f"Помилка БД при увімкненні 2FA для user_id {user_id}: {e}", exc_info=True)
                return False, "Виникла помилка сервера при спробі увімкнути 2FA."
        else:
            if not user.is_2fa_enabled:
                logger.info(f"2FA вже вимкнено для user_id {user_id}.")
                return False, "Двофакторна автентифікація вже вимкнена."
            try:
                self.user_repository.update_user(user, is_2fa_enabled=False)
                logger.info(f"2FA успішно вимкнено для user_id {user_id}.")
                return True, "Двофакторну автентифікацію успішно вимкнено."
            except Exception as e:
                logger.error(f"Помилка БД при вимкненні 2FA для user_id {user_id}: {e}", exc_info=True)
                return False, "Виникла помилка сервера при спробі вимкнути 2FA."
                
    def delete_account_with_confirmation(self, user_id: int, current_password: str) -> tuple[bool, str]:
        user = self.user_repository.get_by_id(user_id)
        if not user:
            logger.warning(f"Користувача {user_id} не знайдено при спробі видалення акаунту.")
            return False, "Користувача не знайдено."

        if not self.hashing_utility.verify_password(user.password_hash, current_password):
            logger.warning(f"Невірний пароль при спробі видалення акаунту user_id: {user_id}.")
            return False, "Невірний пароль для підтвердження видалення."
        
        try:
            email_for_log = user.email
            self.user_repository.delete_user(user)
            logger.info(f"Акаунт для user_id {user_id} (email: {email_for_log}) успішно видалено.")
            return True, "Ваш акаунт та всі пов'язані дані було успішно видалено."
        except Exception as e:
            logger.error(f"Помилка БД при видаленні акаунту user_id {user_id}: {e}", exc_info=True)
            return False, "Виникла помилка сервера при спробі видалити ваш акаунт."

    def process_google_login(self, google_user_info: dict) -> tuple[User | None, str | None]:
        if not google_user_info or not google_user_info.get('email'):
            logger.warning("Google Login: Не вдалося отримати email від Google.")
            return None, "Не вдалося отримати email від Google."

        email = google_user_info['email'].strip().lower()
        google_id = google_user_info.get('sub')
        name_from_google = google_user_info.get('name', email.split('@')[0])

        if not google_id:
            logger.warning(f"Google Login: Не вдалося отримати Google ID (sub) для email: {email}.")
            return None, "Не вдалося отримати унікальний ідентифікатор від Google."

        user = self.user_repository.get_by_google_id(google_id)

        if user:
            logger.info(f"Google Login: Існуючий користувач увійшов через Google: {user.email} (Google ID: {google_id})")
            update_fields = {}
            if user.name != name_from_google and name_from_google:
                update_fields['name'] = name_from_google
            if not user.is_email_verified:
                update_fields['is_email_verified'] = True
            if user.email != email:
                logger.warning(f"Google Login: Email для Google ID {google_id} змінився з {user.email} на {email}. Email не оновлено автоматично.")
                pass

            if update_fields:
                try:
                    self.user_repository.update_user(user, **update_fields)
                    logger.info(f"Google Login: Оновлено поля {list(update_fields.keys())} для користувача {user.email}.")
                except Exception as e:
                    logger.error(f"Google Login: Помилка оновлення даних для існуючого Google користувача {user.email}: {e}", exc_info=True)
            return user, None
        else:
            user_by_email = self.user_repository.get_by_email(email)
            if user_by_email:
                logger.info(f"Google Login: Користувач з email {email} вже існує. Прив'язка Google ID: {google_id}.")
                update_fields = {'google_id': google_id}
                if not user_by_email.is_email_verified:
                    update_fields['is_email_verified'] = True
                try:
                    self.user_repository.update_user(user_by_email, **update_fields)
                    return user_by_email, None
                except Exception as e:
                    logger.error(f"Google Login: Помилка прив'язки Google ID до існуючого користувача {email}: {e}", exc_info=True)
                    return None, "Не вдалося прив'язати ваш Google акаунт. Можливо, цей email вже використовується."
            else:
                logger.info(f"Google Login: Створення нового користувача через Google: {email} (Google ID: {google_id}).")
                placeholder_password_hash = self.hashing_utility.hash_password(
                    self._generate_short_code(32) + email + google_id
                )
                try:
                    new_user = self.user_repository.add_user(
                        name=name_from_google,
                        email=email,
                        password_hash=placeholder_password_hash,
                        google_id=google_id,
                        is_email_verified_on_creation=True
                    )
                    logger.info(f"Google Login: Нового користувача {email} успішно створено.")
                    return new_user, None
                except Exception as e:
                    logger.error(f"Google Login: Помилка створення нового Google користувача {email}: {e}", exc_info=True)
                    existing_user_check = self.user_repository.get_by_email(email)
                    if existing_user_check:
                        logger.warning(f"Google Login: Користувач {email} був створений іншим процесом під час спроби реєстрації. Спроба прив'язки.")
                        return self.process_google_login(google_user_info)
                    return None, "Не вдалося зареєструвати ваш акаунт через Google. Спробуйте ще раз."

    def update_user_preference(self, user_id: int, preference_name: str, preference_value: bool) -> tuple[bool, str]:
        """
        Оновлює налаштування користувача (наприклад, night_mode_enabled, auto_logout_enabled).
        """
        user = self.user_repository.get_by_id(user_id)
        if not user:
            logger.warning(f"AUTH_SERVICE: Користувача {user_id} не знайдено для оновлення налаштування.")
            return False, "Користувача не знайдено."

        allowed_preferences = ['night_mode_enabled', 'auto_logout_enabled']
        
        if preference_name not in allowed_preferences:
            logger.warning(f"AUTH_SERVICE: Спроба оновити недозволене налаштування '{preference_name}' для user_id: {user_id}.")
            return False, "Це налаштування не може бути змінено таким чином."
        
        if not hasattr(user, preference_name):
            logger.error(f"AUTH_SERVICE: Атрибут '{preference_name}' не існує в моделі User для user_id: {user_id}.")
            return False, f"Внутрішня помилка: налаштування '{preference_name}' не знайдено в моделі користувача."

        if not isinstance(preference_value, bool):
            logger.warning(f"AUTH_SERVICE: Некоректний тип значення ({type(preference_value)}) для '{preference_name}' user_id: {user_id}. Очікується булеве значення.")
            return False, "Некоректний тип значення для цього налаштування."

        try:
            setattr(user, preference_name, preference_value)
            self.user_repository.update_user(user)
            
            logger.info(f"AUTH_SERVICE: Налаштування '{preference_name}' для user_id {user_id} успішно оновлено на '{preference_value}'.")
            return True, "Налаштування успішно оновлено."
        except Exception as e:
            logger.error(f"AUTH_SERVICE: Помилка БД при оновленні налаштування '{preference_name}' для user_id {user_id}: {e}", exc_info=True)
            return False, "Помилка бази даних при збереженні налаштування."

    def request_master_password_change(self, user_id: int, old_plain_password: str, new_plain_password: str) -> tuple[bool, str]:
        user = self.user_repository.get_by_id(user_id)
        if not user:
            logger.warning(f"AUTH_SERVICE: Користувача {user_id} не знайдено для зміни пароля.")
            return False, "Користувача не знайдено."

        if not self.hashing_utility.verify_password(user.password_hash, old_plain_password):
            logger.warning(f"AUTH_SERVICE: Невірний поточний пароль для user_id: {user_id}.")
            return False, "Невірний поточний пароль."

        if len(new_plain_password) < 8:
            logger.warning(f"AUTH_SERVICE: Новий пароль для user_id: {user_id} занадто короткий.")
            return False, "Новий пароль має містити щонайменше 8 символів."
        
        if self.hashing_utility.verify_password(user.password_hash, new_plain_password):
            logger.warning(f"AUTH_SERVICE: Новий пароль співпадає зі старим для user_id: {user_id}.")
            return False, "Новий пароль не може бути таким самим, як поточний."

        otp_purpose = "password_change_otp"
        otp_code = self._generate_short_code()
        new_password_hash = self.hashing_utility.hash_password(new_plain_password)
        
        cache_data_to_store = {
            'new_hash': new_password_hash,
            'code': otp_code,
            'attempts_left': AuthService.OTP_CODE_ATTEMPTS
        }
        cache_key = f"{otp_purpose}:{user.email}"

        try:
            self.cache_service.set_value(
                key=cache_key,
                value=cache_data_to_store,
                expires_in_seconds=AuthService.PASSWORD_CHANGE_OTP_EXPIRY_MINUTES * 60
            )
            logger.info(f"AUTH_SERVICE: Дані для зміни пароля (новий хеш, OTP) збережено в кеші для user_id: {user_id}.")
        except Exception as e:
            logger.error(f"AUTH_SERVICE: Помилка збереження даних зміни пароля в кеш для user_id {user_id}: {e}", exc_info=True)
            return False, "Помилка системи при підготовці до зміни пароля."

        if self.email_service.send_password_change_otp_email(user.email, otp_code):
            logger.info(f"AUTH_SERVICE: OTP для зміни пароля надіслано на {user.email} для user_id: {user_id}.")
            return True, "Код підтвердження надіслано на ваш email."
        else:
            logger.error(f"AUTH_SERVICE: Не вдалося надіслати OTP для зміни пароля на {user.email} (user_id: {user_id}).")
            self.cache_service.delete_value(key=cache_key)
            return False, "Не вдалося надіслати код підтвердження. Спробуйте пізніше."

    def confirm_master_password_change(self, user_id: int, otp_code_from_user: str) -> tuple[bool, str]:
        user = self.user_repository.get_by_id(user_id)
        if not user:
            logger.warning(f"AUTH_SERVICE: Користувача {user_id} не знайдено для підтвердження зміни пароля.")
            return False, "Користувача не знайдено."

        otp_purpose = "password_change_otp"
        cache_key = f"{otp_purpose}:{user.email}"
        
        cached_data = self.cache_service.get_value(cache_key)

        if not cached_data or not isinstance(cached_data, dict):
            logger.warning(f"AUTH_SERVICE: Дані для зміни пароля не знайдено в кеші або мають невірний формат для user_id: {user_id} (ключ: {cache_key}).")
            return False, "Код підтвердження не знайдено, час дії вийшов або сталася помилка. Спробуйте знову ініціювати зміну пароля."

        if cached_data.get('attempts_left', 0) <= 0:
            logger.warning(f"AUTH_SERVICE: Вичерпано спроби введення OTP для зміни пароля user_id: {user_id}.")
            self.cache_service.delete_value(cache_key)
            return False, "Вичерпано спроби введення коду. Спробуйте знову ініціювати зміну пароля."

        if cached_data.get('code') != otp_code_from_user:
            cached_data['attempts_left'] -= 1
            self.cache_service.set_value(cache_key, cached_data, AuthService.PASSWORD_CHANGE_OTP_EXPIRY_MINUTES * 60)
            logger.warning(f"AUTH_SERVICE: Невірний OTP для зміни пароля user_id: {user_id}. Залишилось спроб: {cached_data['attempts_left']}.")
            if cached_data['attempts_left'] <= 0:
                self.cache_service.delete_value(cache_key)
                return False, "Невірний код підтвердження. Вичерпано спроби. Спробуйте знову ініціювати зміну пароля."
            return False, f"Невірний код підтвердження. Залишилось спроб: {cached_data['attempts_left']}."

        new_password_hash = cached_data.get('new_hash')
        if not new_password_hash:
            logger.error(f"AUTH_SERVICE: Новий хеш пароля не знайдено в кеші після валідного OTP для user_id: {user_id}.")
            self.cache_service.delete_value(cache_key)
            return False, "Помилка системи: не вдалося знайти новий пароль. Спробуйте знову."

        try:
            self.user_repository.update_user(user, password_hash=new_password_hash)
            self.cache_service.delete_value(cache_key)
            logger.info(f"AUTH_SERVICE: Пароль успішно змінено для user_id: {user_id}.")
            email_body_html = (
                "<p>Майстер-пароль для вашого акаунту SecurePass було успішно змінено.</p>"
                "<p>Якщо це були не ви, будь ласка, негайно зв'яжіться з нашою підтримкою або спробуйте відновити доступ.</p>"
            )
            email_body_text = (
                "Майстер-пароль для вашого акаунту SecurePass було успішно змінено.\n\n"
                "Якщо це були не ви, будь ласка, негайно зв'яжіться з нашою підтримкою або спробуйте відновити доступ."
            )
            self.email_service.send_generic_notification(
                user.email,
                "Ваш майстер-пароль SecurePass було змінено",
                body_html=email_body_html,
                body_text=email_body_text
            )
            return True, "Майстер-пароль успішно змінено."
        except Exception as e:
            logger.error(f"AUTH_SERVICE: Помилка оновлення пароля в БД для user_id {user_id}: {e}", exc_info=True)
            return False, "Виникла помилка при оновленні пароля в базі даних. Спробуйте ще раз."