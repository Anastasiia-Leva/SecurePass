from dotenv import load_dotenv

load_dotenv()

import os
from flask import Flask, session, current_app
from base64 import urlsafe_b64decode
import logging
from datetime import timedelta

from domain import db
from authlib.integrations.flask_client import OAuth

from utilities.hashing_util import HashingUtility
from utilities.encryption_util import EncryptionUtility

from cache.cache_service import CacheService
from external.email_service import EmailService
from external.google_auth_service import GoogleAuthService

from repositories.user_repository import UserRepository
from repositories.password_repository import PasswordRepository

from services.auth_service import AuthService
from services.entry_service import EntryService
from services.password_generator_service import PasswordGeneratorService

oauth = OAuth()
APP_NAME = "SecurePass"

def create_app(config_object_name=None):
    app = Flask(__name__, instance_relative_config=True)

    is_development = os.environ.get("FLASK_ENV", "production").lower() == "development" or app.debug
    log_level = logging.DEBUG if is_development else logging.INFO
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s %(levelname)-8s [%(name)-20s] %(filename)s:%(lineno)d %(funcName)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        force=True
    )
    
    app.logger.setLevel(log_level)

    app.logger.info(f"Запуск створення екземпляра Flask додатку '{APP_NAME}'...")

    app.config.update(
        SECRET_KEY=os.getenv('SECRET_KEY', 'fallback_dev_secret_key_!@#$_SHOULD_BE_CHANGED_IN_PROD'),
        SQLALCHEMY_DATABASE_URI=os.getenv('DATABASE_URL', f'sqlite:///{os.path.join(app.instance_path, "dev_db.sqlite3")}'),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=int(os.getenv('SESSION_LIFETIME_MINUTES', '60'))),
        SESSION_COOKIE_SECURE= not is_development,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        SESSION_REFRESH_EACH_REQUEST=True,
        GOOGLE_CLIENT_ID=os.getenv('GOOGLE_CLIENT_ID'),
        GOOGLE_CLIENT_SECRET=os.getenv('GOOGLE_CLIENT_SECRET'),
        GOOGLE_DISCOVERY_URL=os.getenv('GOOGLE_DISCOVERY_URL', "https://accounts.google.com/.well-known/openid-configuration")
    )
    
    if 'sqlite' in app.config['SQLALCHEMY_DATABASE_URI'] and not os.path.exists(app.instance_path):
        try:
            os.makedirs(app.instance_path)
            app.logger.info(f"Створено директорію екземпляра: {app.instance_path}")
        except OSError as e:
            app.logger.error(f"Не вдалося створити директорію екземпляра {app.instance_path}: {e}")

    app.logger.info(f"SECRET_KEY {'завантажено з .env' if os.getenv('SECRET_KEY') else 'встановлено за замовчуванням (НЕБЕЗПЕЧНО ДЛЯ PROD!)'}.")
    app.logger.info(f"Використовується SQLALCHEMY_DATABASE_URI: '{app.config['SQLALCHEMY_DATABASE_URI']}'")
    app.logger.info(f"PERMANENT_SESSION_LIFETIME встановлено на {app.config['PERMANENT_SESSION_LIFETIME'].total_seconds() / 60:.0f} хвилин.")
    
    try:
        db.init_app(app)
        oauth.init_app(app)
        app.logger.info("Flask розширення успішно ініціалізовані.")
    except Exception as e:
        app.logger.critical(f"Помилка ініціалізації Flask розширень. SQLALCHEMY_DATABASE_URI: '{app.config.get('SQLALCHEMY_DATABASE_URI')}'. Помилка: {e}", exc_info=True)
        raise RuntimeError(f"Не вдалося ініціалізувати Flask розширення: {e}")

    google_client_id_from_config = app.config.get('GOOGLE_CLIENT_ID')
    google_client_secret_from_config = app.config.get('GOOGLE_CLIENT_SECRET')

    if not google_client_id_from_config or not google_client_secret_from_config:
        app.logger.warning("GOOGLE_CLIENT_ID або GOOGLE_CLIENT_SECRET не налаштовані. Авторизація через Google може не працювати.")
    else:
        app.logger.info("Облікові дані Google OAuth завантажено.")
        try:
            oauth.register(
                name='google',
                client_id=google_client_id_from_config,
                client_secret=google_client_secret_from_config,
                server_metadata_url=app.config.get('GOOGLE_DISCOVERY_URL'),
                client_kwargs={'scope': 'openid email profile'}
            )
            app.logger.info("Клієнт Google OAuth успішно зареєстрований в Authlib.")
        except Exception as e:
            app.logger.error(f"Помилка реєстрації клієнта Google OAuth в Authlib: {e}", exc_info=True)
            
    app.logger.info("Ініціалізація утиліт та сервісів...")
    try:
        hashing_util = HashingUtility()
        
        encryption_key_b64 = os.getenv('ENCRYPTION_KEY_BASE64')
        if not encryption_key_b64:
            app.logger.critical("Критична помилка: ENCRYPTION_KEY_BASE64 не встановлено!")
            raise ValueError("Змінна середовища ENCRYPTION_KEY_BASE64 не встановлена!")
        
        encryption_key_bytes = urlsafe_b64decode(encryption_key_b64.encode('utf-8'))
        if len(encryption_key_bytes) != 32:
            app.logger.error(f"Помилка конфігурації: Декодований ключ шифрування має бути 32 байти (отримано {len(encryption_key_bytes)}).")
            raise ValueError(f"Декодований ключ шифрування має бути 32 байти (отримано {len(encryption_key_bytes)}).")
        encryption_utility = EncryptionUtility(encryption_key_bytes)
        
        email_service = EmailService()
        cache_service = CacheService()
        
        google_oauth_client_instance = oauth.google if hasattr(oauth, 'google') and oauth.google else None
        if google_oauth_client_instance:
            app.logger.info("Екземпляр клієнта oauth.google знайдено для GoogleAuthService.")
        else:
            app.logger.warning("Екземпляр клієнта oauth.google НЕ знайдено. GoogleAuthService може не працювати належним чином.")
        
        google_auth_service = GoogleAuthService(oauth_google_client=google_oauth_client_instance)
        
        user_repository = UserRepository()
        password_repository = PasswordRepository()
        
        auth_service = AuthService(
            user_repository=user_repository,
            hashing_utility=hashing_util,
            cache_service=cache_service,
            email_service=email_service
        )
        entry_service = EntryService(
            password_repository=password_repository,
            encryption_utility=encryption_utility
        )
        password_generator_service = PasswordGeneratorService()
        
        app.logger.info("Усі утиліти та сервіси успішно ініціалізовані.")
    except ValueError as ve:
        app.logger.critical(f"Критична помилка конфігурації при ініціалізації: {ve}", exc_info=True)
        raise
    except Exception as e:
        app.logger.critical(f"Критична помилка при ініціалізації утиліт або сервісів: {e}", exc_info=True)
        raise RuntimeError(f"Не вдалося ініціалізувати утиліти або сервіси: {e}")

    if not hasattr(app, 'extensions'):
        app.extensions = {}
    app.extensions['auth_service'] = auth_service
    app.extensions['entry_service'] = entry_service
    app.extensions['password_generator_service'] = password_generator_service
    app.extensions['google_auth_service'] = google_auth_service
    app.extensions['email_service'] = email_service
    app.extensions['cache_service'] = cache_service
    app.extensions['hashing_utility'] = hashing_util
    app.extensions['encryption_utility'] = encryption_utility
    app.logger.info("Сервіси та утиліти успішно додано до app.extensions.")

    try:
        from .routes_main import main_bp
        from .routes_auth import auth_bp
        from .routes_entries import entries_bp
        
        app.register_blueprint(main_bp)
        app.register_blueprint(auth_bp, url_prefix='/auth')
        app.register_blueprint(entries_bp, url_prefix='/entries')
        app.logger.info("Blueprints (маршрути) успішно зареєстровано.")
    except ImportError as e:
        app.logger.critical(f"Помилка імпорту або реєстрації блюпринтів: {e}.", exc_info=True)
        raise RuntimeError(f"Не вдалося зареєструвати блюпринти: {e}")
    
    @app.before_request
    def before_request_session_handling():
        if session:
            session.modified = True
    
    @app.context_processor
    def inject_user_settings():
        if 'user_id' in session:
            auth_service_instance = current_app.extensions.get('auth_service')
            if auth_service_instance:
                user = auth_service_instance.user_repository.get_by_id(session['user_id'])
                if user:
                    return dict(
                        user_settings_global={
                            'night_mode_enabled': user.night_mode_enabled,
                            'auto_logout_enabled': user.auto_logout_enabled,
                        }
                    )
        return dict(user_settings_global=None)

    @app.route('/health_check')
    def health_check():
        app.logger.info("Запит на /health_check отримано. Додаток працює.")
        return "SecurePass Application is Alive and Healthy!", 200

    app.logger.info(f"Створення екземпляра Flask додатку '{APP_NAME}' успішно завершено.")
    return app