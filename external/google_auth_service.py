from flask import current_app

class GoogleAuthService:
    def __init__(self, oauth_google_client):
        """
        Ініціалізація сервісу Google Auth.
        :param oauth_google_client: Екземпляр клієнта Authlib для Google (наприклад, oauth.google),
                                    який вже зареєстрований та ініціалізований з Flask app.
        """
        if oauth_google_client is None:
            current_app.logger.critical("Клієнт Authlib для Google не було передано до GoogleAuthService або він None.")
            raise ValueError("Клієнт Authlib для Google не було передано або він None.")
        self.client = oauth_google_client

    def get_authorization_url(self, redirect_uri: str) -> str | None:
        """
        Генерує URL для перенаправлення користувача на сторінку авторизації Google.
        :param redirect_uri: Повний URI, на який Google має перенаправити після авторизації.
                             Цей URI має бути зареєстрований в Google Cloud Console.
        :return: Об'єкт Flask Response (редирект) або None у випадку помилки.
        """
        if not self.client:
            current_app.logger.error("GoogleAuthService: Спроба отримати URL авторизації без ініціалізованого клієнта.")
            return None
        try:
            auth_redirect_response = self.client.authorize_redirect(redirect_uri)
            return auth_redirect_response
        except Exception as e:
            current_app.logger.error(f"GoogleAuthService: Помилка генерації URL авторизації: {e}", exc_info=True)
            return None

    def exchange_code_for_token_and_userinfo(self) -> dict | None:
        """
        Обмінює авторизаційний код (отриманий від Google після редиректу) на токени
        та отримує інформацію про користувача (userinfo).
        Authlib автоматично отримує код з поточного запиту Flask.
        :return: Словник, що містить 'access_token', 'id_token', 'userinfo' (словник), 'expires_at',
                 або None у випадку помилки.
        """
        if not self.client:
            print("ПОМИЛКА GoogleAuthService: Клієнт Authlib не ініціалізований належним чином для обміну токена.")
            current_app.logger.error("GoogleAuthService: Спроба обміняти код без ініціалізованого клієнта.")
            return None
        try:
            token = self.client.authorize_access_token()

            if not token:
                print("ПОМИЛКА GoogleAuthService: Не вдалося отримати токен від Google (authorize_access_token повернув None).")
                current_app.logger.warning("Google OAuth: authorize_access_token() повернув None (можливо, помилка або користувач скасував).")
                return None

            user_info_payload = token.get('userinfo')

            if not user_info_payload:
                try:
                    userinfo_resp = self.client.get('openid/userinfo', token=token)
                    userinfo_resp.raise_for_status()
                    user_info_payload = userinfo_resp.json()
                except Exception as userinfo_e:
                    current_app.logger.error(
                        f"GoogleAuthService: Помилка при окремому запиті userinfo. Тип: {type(userinfo_e).__name__}. Повідомлення: {str(userinfo_e)}",
                        exc_info=True
                    )
                    try:
                        print(f"ПОМИЛКА GoogleAuthService (userinfo_e raw): Тип - {type(userinfo_e).__name__}, Повідомлення - {str(userinfo_e)}")
                    except UnicodeEncodeError:
                        print(f"ПОМИЛКА GoogleAuthService (userinfo_e raw): Тип - {type(userinfo_e).__name__}. Неможливо вивести повідомлення userinfo_e через кодування.")
                    return None

            if user_info_payload:
                return {
                    'access_token': token.get('access_token'),
                    'id_token': token.get('id_token'),
                    'userinfo': user_info_payload,
                    'expires_at': token.get('expires_at')
                }
            else:
                print("ПОМИЛКА GoogleAuthService: Не вдалося отримати userinfo від Google.")
                current_app.logger.warning("Google OAuth: Не вдалося отримати userinfo навіть після окремого запиту.")
                return None

        except Exception as e:
            current_app.logger.error(
                f"GoogleAuthService: Помилка обміну коду на токен або отримання userinfo. Тип: {type(e).__name__}. Повідомлення: {str(e)}",
                exc_info=True
            )
            try:
                print(f"ПОМИЛКА GoogleAuthService (raw main exc): Тип помилки - {type(e).__name__}, Повідомлення - {str(e)}")
            except UnicodeEncodeError:
                print(f"ПОМИЛКА GoogleAuthService (raw main exc): Тип помилки - {type(e).__name__}. Неможливо вивести повідомлення через кодування.")
            return None