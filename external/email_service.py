
import smtplib
import ssl
from email.message import EmailMessage
import os
import logging

logger = logging.getLogger(__name__)

class EmailService:
    def __init__(self):
        self.smtp_server = os.getenv('EMAIL_HOST', 'smtp.gmail.com')
        try:
            self.smtp_port = int(os.getenv('EMAIL_PORT', 465))
        except ValueError:
            self.smtp_port = 465 
        self.sender_email = os.getenv('EMAIL_USER')
        self.sender_password = os.getenv('EMAIL_PASS')
        
    def send_email(self, to_email: str, subject: str, body_html: str | None = None, body_text: str | None = None) -> bool:
        if not self.sender_email or not self.sender_password:
            logger.error("EMAIL_SERVICE: EMAIL_USER або EMAIL_PASS не налаштовані в .env.")
            return False

        if not body_html and not body_text:
            logger.error("EMAIL_SERVICE: Потрібно надати тіло листа (HTML або текстове).")
            return False

        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = self.sender_email
        msg['To'] = to_email

        if body_text:
            msg.set_content(body_text)
        if body_html:
            if body_text: 
                msg.add_alternative(body_html, subtype='html')
            else: 
                msg.set_content(body_html, subtype='html')

        try:
           
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port, context=context) as smtp:
                smtp.login(self.sender_email, self.sender_password)
                smtp.send_message(msg)
            logger.info(f"EMAIL_SERVICE: Email успішно надіслано на {to_email} з темою '{subject}'")
            return True
        except smtplib.SMTPAuthenticationError:
            logger.error(f"EMAIL_SERVICE: Помилка автентифікації SMTP для {self.sender_email}.")
            return False
        except Exception as e:
            logger.error(f"EMAIL_SERVICE: Загальна помилка при надсиланні email на {to_email}: {e}", exc_info=True)
            return False

    def send_verification_code_email(self, to_email: str, code: str) -> bool:
        subject = "SecurePass — Код підтвердження Email"
        body_text = f"Ваш код для підтвердження email-адреси: {code}\n\nЯкщо ви не запитували цей код, просто проігноруйте цей лист."
        body_html = f"""
        <html>
            <body>
                <h2>SecurePass — Підтвердження Email</h2>
                <p>Ваш код для підтвердження email-адреси: <strong>{code}</strong></p>
            </body>
        </html>
        """
        return self.send_email(to_email, subject, body_html=body_html, body_text=body_text)

    def send_2fa_code_email(self, to_email: str, code: str) -> bool:
        subject = "SecurePass — Ваш код двофакторної автентифікації"
        body_text = f"Ваш одноразовий код для входу в SecurePass: {code}\n\nЦей код дійсний протягом короткого часу."
        body_html = f"""
        <html>
            <body>
                <h2>SecurePass — Код 2FA</h2>
                <p>Ваш одноразовий код для входу в SecurePass: <strong>{code}</strong></p>

            </body>
        </html>
        """
        return self.send_email(to_email, subject, body_html=body_html, body_text=body_text)

    def send_password_reset_email(self, to_email: str, reset_token: str, reset_url: str) -> bool:
        subject = "SecurePass — Запит на скидання пароля"
        body_text = f"""
        Ви отримали цей лист, тому що було зроблено запит на скидання пароля для вашого акаунту SecurePass.
        {reset_url}

        Посилання для скидання пароля дійсне протягом обмеженого часу.
        """
        body_html = f"""
        <html>
            <body>
                <h2>SecurePass — Скидання Пароля</h2>
                <p>Ви отримали цей лист, тому що було зроблено запит на скидання пароля для вашого акаунту SecurePass.</p>
                <p><a href="{reset_url}">Скинути мій пароль</a></p>
                <p>{reset_url}</p>
                <p>Посилання для скидання пароля дійсне протягом обмеженого часу.</p>
            </body>
        </html>
        """
        return self.send_email(to_email, subject, body_html=body_html, body_text=body_text)


    def send_password_change_otp_email(self, to_email: str, otp_code: str) -> bool:
        subject = "SecurePass — Код підтвердження зміни пароля"
        body_text = f"Ваш одноразовий код для підтвердження зміни майстер-пароля SecurePass: {otp_code}\n\nЦей код дійсний протягом короткого часу. Якщо ви не запитували зміну пароля, негайно зв'яжіться з підтримкою."
        body_html = f"""
        <html>
            <body>
                <h2>SecurePass — Код підтвердження зміни пароля</h2>
                <p>Ваш одноразовий код для підтвердження зміни майстер-пароля SecurePass: <strong>{otp_code}</strong></p>
                <p>Цей код дійсний протягом короткого часу. Нікому його не передавайте.</p>
            </body>
        </html>
        """
        return self.send_email(to_email, subject, body_html=body_html, body_text=body_text)


    def send_generic_notification(self, to_email: str, subject: str, body_html: str, body_text: str | None = None) -> bool:
        """
        Надсилає загальне повідомлення користувачу.
        """
 
        if not body_html and not body_text:
            logger.error("EMAIL_SERVICE (send_generic_notification): Потрібно надати тіло листа.")
            return False
        
        logger.info(f"EMAIL_SERVICE: Надсилання загального повідомлення на {to_email} з темою '{subject}'")
        return self.send_email(to_email, subject, body_html=body_html, body_text=body_text)