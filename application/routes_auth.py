from flask import (Blueprint, render_template, request, redirect,
                   url_for, flash, session, current_app, jsonify, Response)
from .decorators import login_required, guest_required
import io
import csv

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
@guest_required
def register():
    auth_service = current_app.extensions['auth_service']
    form_data = {}
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        form_data = {'name': name, 'email': email}

        if not all([name, email, password, confirm_password]):
            flash("Будь ласка, заповніть усі поля.", "danger")
        elif password != confirm_password:
            flash("Паролі не співпадають.", "danger")
        elif len(password) < 8:
            flash("Пароль має містити щонайменше 8 символів.", "danger")
        else:
            user, message = auth_service.register_user(name, email, password)
            if user:
                session['email_to_verify'] = user.email
                flash(message or "Реєстрація успішна! Код підтвердження надіслано на ваш email.", "success")
                return redirect(url_for('auth.verify_email'))
            else:
                flash(message or "Помилка реєстрації.", "danger")
        return render_template('register.html', form_data=form_data)
    return render_template('register.html', form_data={})


@auth_bp.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    auth_service = current_app.extensions['auth_service']
    email_to_verify = session.get('email_to_verify')

    if not email_to_verify:
        flash("Немає email для верифікації. Спробуйте зареєструватися знову.", "warning")
        return redirect(url_for('auth.register'))

    if request.method == 'POST':
        code = request.form.get('code')
        if not code:
            flash("Будь ласка, введіть код підтвердження.", "danger")
        else:
            user_object, message = auth_service.verify_email_address(email_to_verify, code)
            if user_object:
                session.pop('email_to_verify', None)
                session.clear()
                session['user_id'] = user_object.user_id
                session['user_name'] = user_object.name
                session['user_email'] = user_object.email
                session.permanent = True
                flash(f"Ласкаво просимо, {user_object.name}! Ваш email підтверджено.", "success")
                return redirect(url_for('entries.welcome_page'))
            else:
                flash(message or "Помилка верифікації коду.", "danger")
        return render_template('verify_email.html', email=email_to_verify)
    return render_template('verify_email.html', email=email_to_verify)


@auth_bp.route('/resend-verification-code', methods=['POST'])
def resend_verification_code():
    auth_service = current_app.extensions['auth_service']
    email_to_verify = session.get('email_to_verify')
    if not email_to_verify:
        flash("Немає email для повторного надсилання коду.", "warning")
        return redirect(request.referrer or url_for('auth.register'))
    sent, message = auth_service.resend_verification_email(email_to_verify)
    flash(message, "success" if sent else "danger")
    return redirect(url_for('auth.verify_email'))


@auth_bp.route('/login', methods=['GET', 'POST'])
@guest_required
def login():
    auth_service = current_app.extensions['auth_service']
    form_data = {}
    lockout_info = {}

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        form_data = {'email': email}

        if not email or not password:
            flash("Будь ласка, введіть email та пароль.", "danger")
        else:
            user, message, needs_2fa = auth_service.login_user(email, password)
            if user and needs_2fa:
                session['user_email_for_2fa'] = user.email
                flash(message or "Потрібна двофакторна автентифікація.", "info")
                return redirect(url_for('auth.enter_2fa_code'))
            elif user:
                session.clear()
                session['user_id'] = user.user_id
                session['user_name'] = user.name
                session['user_email'] = user.email
                session.permanent = True
                flash(message or f"Вітаємо з поверненням, {user.name}!", "success")
                next_page = request.args.get('next')
                return redirect(next_page or url_for('entries.welcome_page'))
            else:
                if "Акаунт тимчасово заблоковано" in (message or ""):
                    lockout_info['locked_message'] = message
                    flash(message, "warning")
                elif "Будь ласка, спочатку підтвердіть вашу email-адресу." in (message or ""):
                    session['email_to_verify'] = email
                    flash(message, "warning")
                    return redirect(url_for('auth.verify_email'))
                else:
                    flash(message or "Невірний email або пароль.", "danger")
        return render_template('login.html', form_data=form_data, **lockout_info)
    return render_template('login.html', form_data={}, **lockout_info)


@auth_bp.route('/enter-2fa-code', methods=['GET', 'POST'])
def enter_2fa_code():
    auth_service = current_app.extensions['auth_service']
    user_email_for_2fa = session.get('user_email_for_2fa')

    if not user_email_for_2fa:
        flash("Сесія для 2FA не знайдена або час дії вийшов. Будь ласка, увійдіть знову.", "warning")
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        code = request.form.get('code')
        if not code:
            flash("Будь ласка, введіть 2FA код.", "danger")
        else:
            is_valid_2fa, user_after_2fa, message = auth_service.verify_2fa_for_login_and_get_user(user_email_for_2fa, code)
            if is_valid_2fa and user_after_2fa:
                session.pop('user_email_for_2fa', None)
                session.pop('pending_google_user_id', None)
                session.clear()
                session['user_id'] = user_after_2fa.user_id
                session['user_name'] = user_after_2fa.name
                session['user_email'] = user_after_2fa.email
                session.permanent = True
                flash(message or "Вхід успішний!", "success")
                
                next_url_after_google = session.pop('google_oauth_next_url', None)
                next_page_from_query = request.args.get('next')
                
                final_redirect_url = next_page_from_query or next_url_after_google or url_for('entries.welcome_page')
                
                return redirect(final_redirect_url)
            else:
                flash(message or "Помилка 2FA.", "danger")
                if "Спробуйте увійти знову" in (message or ""):
                    session.pop('user_email_for_2fa', None)
                    return redirect(url_for('auth.login'))
        return render_template('enter_2fa_code.html', email=user_email_for_2fa)
    return render_template('enter_2fa_code.html', email=user_email_for_2fa)

    
@auth_bp.route('/resend-2fa-code', methods=['POST'])
def resend_2fa_code():
    auth_service = current_app.extensions['auth_service']
    email_for_2fa = session.get('user_email_for_2fa')

    if not email_for_2fa:
        flash("Немає email для повторного надсилання 2FA коду. Спробуйте увійти знову.", "warning")
        return redirect(request.referrer or url_for('auth.login'))
    
    user_repo = auth_service.user_repository
    user = user_repo.get_by_email(email_for_2fa)

    if user and user.is_2fa_enabled:
        new_2fa_code = auth_service._generate_short_code()
        try:
            auth_service.cache_service.save_otp_data(
                identifier=user.email, purpose="2fa_login", code=new_2fa_code,
                expires_in_minutes=auth_service.TWO_FA_CODE_EXPIRY_MINUTES,
                attempts=auth_service.OTP_CODE_ATTEMPTS
            )
            if auth_service.email_service.send_2fa_code_email(user.email, new_2fa_code):
                flash("Новий 2FA код надіслано на ваш email.", "success")
            else:
                flash("Не вдалося надіслати новий 2FA код. Спробуйте пізніше.", "danger")
        except Exception as e:
            current_app.logger.error(f"Помилка при повторному надсиланні 2FA коду для {email_for_2fa}: {e}", exc_info=True)
            flash("Виникла системна помилка при надсиланні коду.", "danger")
    elif user and not user.is_2fa_enabled:
        flash("2FA не активовано для вашого акаунту.", "warning")
        session.pop('user_email_for_2fa', None)
        return redirect(url_for('auth.login'))
    else:
        flash("Помилка: користувача не знайдено.", "danger")
        session.pop('user_email_for_2fa', None)
        return redirect(url_for('auth.login'))
    return redirect(url_for('auth.enter_2fa_code'))


@auth_bp.route('/logout')
@login_required
def logout():
    session.clear()
    flash("Ви успішно вийшли з системи.", "success")
    return redirect(url_for('auth.login'))

@auth_bp.route('/settings', methods=['GET'])
@login_required
def manage_settings():
    user_id = session['user_id']
    auth_service = current_app.extensions['auth_service']
    current_user = auth_service.user_repository.get_by_id(user_id)

    if not current_user:
        flash("Помилка завантаження налаштувань: користувача не знайдено.", "danger")
        return redirect(url_for('entries.welcome_page'))

    user_settings_data = {
        'auto_logout_enabled': current_user.auto_logout_enabled,
        'night_mode_enabled': current_user.night_mode_enabled,
    }
    is_2fa_on = current_user.is_2fa_enabled
    
    csrf_token_value = ""

    return render_template(
        'manage_settings.html',
        is_2fa_enabled_on_page=is_2fa_on,
        user_settings=user_settings_data,
        csrf_token=csrf_token_value
    )

@auth_bp.route('/settings/toggle-2fa', methods=['POST'])
@login_required
def toggle_2fa_action():
    auth_service = current_app.extensions['auth_service']
    user_id = session['user_id']
    action = request.form.get('action')
    success, message = False, "Невідома дія або помилка."

    if action == 'enable':
        success, message = auth_service.toggle_2fa_status(user_id, enable=True)
    elif action == 'disable':
        success, message = auth_service.toggle_2fa_status(user_id, enable=False)
    else:
        message = "Некоректна дія для 2FA."
        current_app.logger.warning(f"Некоректна дія '{action}' для toggle_2fa_action, user_id {user_id}")
    
    flash(message, "success" if success else "danger")
    return redirect(url_for('auth.manage_settings'))

@auth_bp.route('/request-master-password-change', methods=['POST'])
@login_required
def request_master_password_change():
    auth_service = current_app.extensions['auth_service']
    user_id = session['user_id']
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')

    if not all([current_password, new_password]):
        return jsonify(success=False, error="Будь ласка, заповніть усі поля."), 400
    if len(new_password) < 8:
        return jsonify(success=False, error="Новий пароль має містити щонайменше 8 символів."), 400
    
    success, message_or_error = auth_service.request_master_password_change(
        user_id, current_password, new_password
    )
    if success:
        return jsonify(success=True, message=message_or_error)
    else:
        return jsonify(success=False, error=message_or_error), 400


@auth_bp.route('/confirm-master-password-change', methods=['POST'])
@login_required
def confirm_master_password_change():
    auth_service = current_app.extensions['auth_service']
    user_id = session['user_id']
    otp_code = request.form.get('otp_code')

    if not otp_code or not otp_code.isdigit() or len(otp_code) != 6 :
        return jsonify(success=False, error="Невірний формат коду підтвердження (потрібно 6 цифр)."), 400

    success, message_or_error = auth_service.confirm_master_password_change(user_id, otp_code)
    if success:
        return jsonify(success=True, message=message_or_error)
    else:
        status_code = 400 if "Невірний код" in message_or_error or "Вичерпано спроби" in message_or_error or "час дії вийшов" in message_or_error else 500
        return jsonify(success=False, error=message_or_error), status_code

@auth_bp.route('/settings/update-preference', methods=['POST'])
@login_required
def update_user_preference():
    auth_service = current_app.extensions['auth_service']
    user_id = session['user_id']
    data = request.get_json()

    if not data or 'preference_name' not in data or 'preference_value' not in data:
        current_app.logger.warning(f"UPDATE_PREFERENCE: Некоректні дані від user_id {user_id}: {data}")
        return jsonify(success=False, error="Некоректний запит: відсутні необхідні дані."), 400

    preference_name = data.get('preference_name')
    preference_value = data.get('preference_value')

    allowed_preferences = {
        'auto_logout_enabled': bool,
        'night_mode_enabled': bool
    }
    if preference_name not in allowed_preferences:
        current_app.logger.warning(f"UPDATE_PREFERENCE: Недозволене ім'я налаштування '{preference_name}' від user_id {user_id}.")
        return jsonify(success=False, error=f"Недозволене налаштування: {preference_name}."), 400
    
    expected_type = allowed_preferences[preference_name]
    if not isinstance(preference_value, expected_type):
        current_app.logger.warning(f"UPDATE_PREFERENCE: Некоректний тип значення для '{preference_name}' (отримано {type(preference_value)}, очікується {expected_type}) від user_id {user_id}.")
        return jsonify(success=False, error=f"Некоректний тип значення для налаштування '{preference_name}'. Очікується {expected_type.__name__}."), 400

    success, message = auth_service.update_user_preference(user_id, preference_name, preference_value)

    if success:
        current_app.logger.info(f"UPDATE_PREFERENCE: Налаштування '{preference_name}' оновлено на '{preference_value}' для user_id {user_id}.")
        return jsonify(success=True, message=message or "Налаштування оновлено.")
    else:
        current_app.logger.error(f"UPDATE_PREFERENCE: Помилка оновлення '{preference_name}' для user_id {user_id}: {message}")
        return jsonify(success=False, error=message or "Не вдалося оновити налаштування."), 500


@auth_bp.route('/settings/delete-account', methods=['POST'])
@login_required
def delete_account_route():
    auth_service = current_app.extensions['auth_service']
    user_id = session['user_id']
    password_for_delete = request.form.get('password')

    if not password_for_delete:
        flash("Будь ласка, введіть ваш пароль для підтвердження видалення.", "danger")
        return redirect(url_for('auth.manage_settings'))
    
    success, message = auth_service.delete_account_with_confirmation(user_id, password_for_delete)
    
    if success:
        session.clear()
        flash(message or "Акаунт успішно видалено.", "success")
        return redirect(url_for('auth.login'))
    else:
        flash(message or "Помилка видалення акаунту.", "danger")
    return redirect(url_for('auth.manage_settings'))


@auth_bp.route('/google/login', endpoint='google_login_initiate')
@guest_required
def google_login_initiate():
    google_auth_service = current_app.extensions.get('google_auth_service')
    if not google_auth_service or not hasattr(google_auth_service, 'client') or not google_auth_service.client:
        current_app.logger.error("AUTH_ROUTES: Google OAuth сервіс не налаштований (клієнт відсутній).")
        flash("Вхід через Google тимчасово недоступний. Будь ласка, спробуйте пізніше.", "warning")
        return redirect(url_for('auth.login'))
    try:
        redirect_uri = url_for('auth.google_authorize_callback', _external=True)
        next_url = request.args.get('next')
        if next_url:
            session['google_oauth_next_url'] = next_url
        
        auth_url_response = google_auth_service.get_authorization_url(redirect_uri)
        
        if auth_url_response:
            return auth_url_response
        else:
            flash("Не вдалося ініціювати вхід через Google. Помилка конфігурації.", "danger")
    except Exception as e:
        current_app.logger.error(f"AUTH_ROUTES: Помилка Google авторизації (get_authorization_url): {e}", exc_info=True)
        flash("Виникла непередбачена помилка при спробі входу через Google.", "danger")
    return redirect(url_for('auth.login'))

@auth_bp.route('/google/callback', endpoint='google_authorize_callback')
@guest_required
def google_authorize_callback():
    google_auth_service = current_app.extensions.get('google_auth_service')
    auth_service = current_app.extensions['auth_service']

    if not google_auth_service or not hasattr(google_auth_service, 'client') or not google_auth_service.client:
        flash("Помилка конфігурації Google входу. Сервіс недоступний.", "danger")
        return redirect(url_for('auth.login'))

    try:
        if request.args.get('error'):
            error_from_google = request.args.get('error')
            error_description = request.args.get('error_description', 'Невідома помилка від Google.')
            current_app.logger.warning(f"Google OAuth: отримано помилку від Google: {error_from_google} - {error_description}")
            flash(f"Помилка авторизації через Google: {error_description}", "danger")
            return redirect(url_for('auth.login'))
        
        token_payload = google_auth_service.exchange_code_for_token_and_userinfo()
    except Exception as e:
        current_app.logger.error(f"AUTH_ROUTES: Google OAuth: Помилка обміну коду на токен: {e}", exc_info=True)
        flash("Помилка авторизації через Google. Не вдалося отримати токен.", "danger")
        return redirect(url_for('auth.login'))

    if not token_payload or not token_payload.get('userinfo'):
        current_app.logger.warning("Google OAuth: Не вдалося отримати токен або userinfo від Google.")
        flash("Не вдалося авторизуватися через Google. Спробуйте ще раз.", "danger")
        return redirect(url_for('auth.login'))

    google_user_info_data = token_payload['userinfo']
    
    user, error_message = auth_service.process_google_login(google_user_info_data)
    
    next_url = session.pop('google_oauth_next_url', url_for('entries.welcome_page'))

    if user:
        session.clear()
        session['user_id'] = user.user_id
        session['user_name'] = user.name
        session['user_email'] = user.email
        session.permanent = True
        flash(f"Ви успішно увійшли через Google як {user.name}!", "success")
        return redirect(next_url)
    else:
        flash(error_message or "Помилка входу або реєстрації через Google. Спробуйте інший спосіб.", "danger")
        return redirect(url_for('auth.login'))

@auth_bp.route('/export-passwords-csv')
@login_required
def export_passwords_csv():
    user_id = session['user_id']
    entry_service = current_app.extensions.get('entry_service')
    
    if not entry_service:
        current_app.logger.error(f"EXPORT_CSV: EntryService не знайдено в розширеннях для user_id {user_id}.")
        flash("Сервіс експорту тимчасово недоступний. Спробуйте пізніше.", "danger")
        return redirect(url_for('auth.manage_settings'))

    current_app.logger.info(f"EXPORT_CSV: Запит на експорт CSV для user_id {user_id}")

    try:
        entries_data = entry_service.get_all_entries_for_export(user_id)
    except Exception as e:
        current_app.logger.error(f"EXPORT_CSV: Помилка отримання даних для експорту (user_id {user_id}): {e}", exc_info=True)
        flash("Не вдалося отримати дані для експорту. Спробуйте пізніше.", "danger")
        return redirect(url_for('auth.manage_settings'))

    if not entries_data:
        flash("У вас немає записів для експорту.", "info")
        return redirect(url_for('auth.manage_settings'))

    fieldnames = [
        'entry_id', 'user_id',
        'site_name', 'login', 'password', 'site_url', 'email', 'nickname',
        'custom_id', 'old_password', 'backup_email', 'password_hint',
        'phone_number', 'secret_word', 'date_added', 'date_updated'
    ]
    
    si = io.StringIO()
    writer = csv.DictWriter(si, fieldnames=fieldnames, extrasaction='ignore', quoting=csv.QUOTE_ALL, dialect='excel')

    writer.writeheader()
    for entry_row in entries_data:
        row_to_write = {field: entry_row.get(field, "") for field in fieldnames}
        writer.writerow(row_to_write)
    
    output_csv_data = si.getvalue()
    si.close()

    current_app.logger.info(f"EXPORT_CSV: CSV файл успішно згенеровано для user_id {user_id}. Розмір: {len(output_csv_data)} байт.")

    return Response(
        output_csv_data,
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=securepass_export.csv",
            "Content-Type": "text/csv; charset=utf-8"
        }
    )