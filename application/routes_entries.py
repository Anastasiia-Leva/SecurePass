from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app, jsonify
from .decorators import login_required

entries_bp = Blueprint('entries', __name__)

@entries_bp.route('/welcome')
@login_required
def welcome_page():
    user_name_to_render = session.get('user_name', 'Гість (сесія?)')
    if user_name_to_render == 'Гість (сесія?)':
        current_app.logger.warning(
            "ENTRIES_BP: welcome_page - Ключ 'user_name' не знайдено в сесії або він None. "
            "Перевірте логіку встановлення сесії в auth.py. Використовується 'Гість'."
        )
    try:
        current_app.logger.info(f"ENTRIES_BP: welcome_page - Рендеринг welcome.html для користувача: {user_name_to_render}")
        return render_template('welcome.html', user_name=str(user_name_to_render))
    except Exception as e:
        current_app.logger.error(f"ENTRIES_BP: welcome_page - КРИТИЧНА ПОМИЛКА при рендерингу welcome.html: {e}", exc_info=True)
        flash("Сталася непередбачена помилка при завантаженні сторінки привітання. Спробуйте увійти знову.", "danger")
        return redirect(url_for('auth.login'))


@entries_bp.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    entry_service = current_app.extensions['entry_service']
    
    sort_by = request.args.get('sort_by', 'date_added')
    order = request.args.get('order', 'desc')
    ascending = (order == 'asc')
    search_term = request.args.get('search', '').strip()
    page_title = "Мої паролі"
    
    selected_entry_id_from_url = request.args.get('view_entry_id', type=int)
    selected_entry_data = None
    form_mode = 'view'
    
    entries_list_data = []

    try:
        if search_term:
            current_app.logger.info(f"ENTRIES_BP: dashboard - Пошук для user_id {user_id}, термін: '{search_term}', сортування: {sort_by} {order}")
            entries_list_data = entry_service.search_user_entries(user_id, search_term)
            page_title = f"Результати пошуку: \"{search_term}\""
        else:
            current_app.logger.info(f"ENTRIES_BP: dashboard - Отримання всіх записів для user_id {user_id}, сортування: {sort_by} {order}")
            entries_list_data = entry_service.get_all_entries_for_user(user_id, sort_by, ascending)

        if selected_entry_id_from_url:
            current_app.logger.info(f"ENTRIES_BP: dashboard - Запит на перегляд запису ID {selected_entry_id_from_url} при завантаженні дашборду для user_id {user_id}")
            selected_entry_data = entry_service.get_entry_details(selected_entry_id_from_url, user_id)
            if not selected_entry_data:
                current_app.logger.warning(f"ENTRIES_BP: dashboard - Обраний запис ID {selected_entry_id_from_url} не знайдено або немає доступу для user_id {user_id}")
                flash("Обраний запис не знайдено або у вас немає доступу.", "warning")
                selected_entry_data = None
            
    except Exception as e:
        current_app.logger.error(f"ENTRIES_BP: dashboard - Помилка при отриманні даних для user_id {user_id}: {e}", exc_info=True)
        flash("Сталася помилка при завантаженні даних. Спробуйте оновити сторінку.", "danger")
        entries_list_data = []
        selected_entry_data = None

    return render_template('dashboard.html',
                           entries=entries_list_data,
                           user_name=session.get('user_name'),
                           page_title=page_title,
                           current_sort_by=sort_by,
                           current_order=order,
                           search_term=search_term,
                           selected_entry=selected_entry_data,
                           form_mode=form_mode
                           )

@entries_bp.route('/ajax/get_entries', methods=['GET'])
@login_required
def ajax_get_entries():
    user_id = session['user_id']
    entry_service = current_app.extensions['entry_service']
    
    sort_by = request.args.get('sort_by', 'date_added')
    order_str = request.args.get('order', 'desc')
    ascending = order_str == 'asc'
    search_term = request.args.get('search', '').strip()

    entries_data_from_service = []
    try:
        if search_term:
            current_app.logger.info(f"ENTRIES_BP: ajax_get_entries - Пошук для user_id {user_id}, термін: '{search_term}'")
            entries_data_from_service = entry_service.search_user_entries(user_id, search_term)
            if entries_data_from_service:
                is_reverse_sort = not ascending
                def sort_key_func(item):
                    val = item.get(sort_by)
                    if isinstance(val, str):
                        return val.lower()
                    return val
                try:
                    entries_data_from_service.sort(key=sort_key_func, reverse=is_reverse_sort)
                except TypeError:
                    current_app.logger.warning(f"ENTRIES_BP: ajax_get_entries - Помилка сортування результатів пошуку через TypeError. sort_by: {sort_by}")
        else:
            current_app.logger.info(f"ENTRIES_BP: ajax_get_entries - Отримання всіх записів для user_id {user_id}, сортування: {sort_by} {'ASC' if ascending else 'DESC'}")
            entries_data_from_service = entry_service.get_all_entries_for_user(user_id, sort_by, ascending)
        
        entries_with_view_url = []
        for entry_item_dict in entries_data_from_service:
            if 'entry_id' in entry_item_dict:
                entry_item_dict['view_url'] = url_for('entries.view_entry_ajax_content', entry_id=entry_item_dict['entry_id'])
                entries_with_view_url.append(entry_item_dict)
            else:
                current_app.logger.warning(f"ENTRIES_BP: ajax_get_entries - Запис без entry_id знайдено для user_id {user_id}. Дані запису: {entry_item_dict}")

        current_app.logger.info(f"ENTRIES_BP: ajax_get_entries - Успішно підготовлено {len(entries_with_view_url)} записів для JSON відповіді.")
        return jsonify(success=True, entries=entries_with_view_url, current_sort_by=sort_by, current_order=order_str)
    except Exception as e:
        current_app.logger.error(f"ENTRIES_BP: ajax_get_entries - Помилка при отриманні даних для user_id {user_id}: {e}", exc_info=True)
        return jsonify(success=False, error="Помилка завантаження списку записів."), 500


@entries_bp.route('/ajax/view_content/<int:entry_id>')
@login_required
def view_entry_ajax_content(entry_id):
    entry_service = current_app.extensions['entry_service']
    user_id = session['user_id']
    try:
        entry_details = entry_service.get_entry_details(entry_id, user_id)
        if not entry_details:
            current_app.logger.warning(f"ENTRIES_BP: view_entry_ajax_content - Запис ID {entry_id} не знайдено або немає доступу для user_id {user_id}.")
            return jsonify(success=False, html="<p>Запис не знайдено або немає доступу.</p>"), 404
        
        current_app.logger.info(f"ENTRIES_BP: view_entry_ajax_content - Деталі для запису ID {entry_id} успішно отримано. Рендеринг entry_details_form.html.")
        html_content = render_template('entry_details_form.html',
                                       entry=entry_details,
                                       form_mode='view')
        return jsonify(success=True, html=html_content)
    except Exception as e:
        current_app.logger.error(f"ENTRIES_BP: view_entry_ajax_content - Помилка при отриманні контенту для запису ID {entry_id}, user_id {user_id}: {e}", exc_info=True)
        return jsonify(success=False, html="<p>Сталася помилка на сервері при завантаженні деталей запису.</p>"), 500


@entries_bp.route('/ajax/edit_form/<int:entry_id>')
@login_required
def edit_entry_ajax_form(entry_id):
    entry_service = current_app.extensions['entry_service']
    user_id = session['user_id']
    try:
        entry_details = entry_service.get_entry_details(entry_id, user_id)
        if not entry_details:
            current_app.logger.warning(f"ENTRIES_BP: edit_entry_ajax_form - Запис ID {entry_id} не знайдено для редагування (user_id {user_id}).")
            return jsonify(success=False, html="<p>Запис для редагування не знайдено або немає доступу.</p>"), 404
        
        current_app.logger.info(f"ENTRIES_BP: edit_entry_ajax_form - Деталі для редагування запису ID {entry_id} отримано. Рендеринг entry_details_form.html.")
        html_content = render_template('entry_details_form.html',
                                       entry=entry_details,
                                       form_mode='edit')
        return jsonify(success=True, html=html_content)
    except Exception as e:
        current_app.logger.error(f"ENTRIES_BP: edit_entry_ajax_form - Помилка при отриманні форми редагування для ID {entry_id}, user_id {user_id}: {e}", exc_info=True)
        return jsonify(success=False, html="<p>Сталася помилка на сервері при завантаженні форми редагування.</p>"), 500


@entries_bp.route('/ajax/add_form')
@login_required
def add_entry_ajax_form():
    user_id = session['user_id']
    try:
        html_content = render_template('entry_details_form.html',
                                       entry={},
                                       form_mode='add')
        current_app.logger.info(f"ENTRIES_BP: add_entry_ajax_form - Форма додавання успішно зрендерена для user_id {user_id}.")
        return jsonify(success=True, html=html_content)
    except Exception as e:
        current_app.logger.error(f"ENTRIES_BP: add_entry_ajax_form - Помилка при отриманні форми додавання для user_id {user_id}: {e}", exc_info=True)
        return jsonify(success=False, html="<p>Сталася помилка на сервері при завантаженні форми додавання.</p>"), 500


@entries_bp.route('/password-generator')
@login_required
def password_generator_page():
    user_id = session['user_id']
    try:
        current_app.logger.info(f"ENTRIES_BP: password_generator_page - Рендеринг password_generator.html для user_id {user_id}")
        return render_template('password_generator.html')
    except Exception as e:
        current_app.logger.error(f"ENTRIES_BP: password_generator_page - Помилка рендерингу: {e}", exc_info=True)
        flash("Не вдалося завантажити сторінку генератора паролів.", "danger")
        return redirect(url_for('entries.dashboard'))

@entries_bp.route('/api/generate-password', methods=['GET'])
@login_required
def generate_password_api():
    password_generator = current_app.extensions['password_generator_service']
    user_id = session['user_id']

    gen_type = request.args.get('type', 'strong')
    length = 0
    words_str = ""
    pin_length_str = ""
    user_length_str = ""
    error_message = None

    try:
        if gen_type == 'pin':
            pin_length_str = request.args.get('length', '4')
            current_app.logger.info(f"ENTRIES_BP: generate_password_api - Тип: pin, запитана довжина: '{pin_length_str}'")
            try:
                length = int(pin_length_str)
                if not (4 <= length <= 10):
                    current_app.logger.warning(f"ENTRIES_BP: generate_password_api - Довжина PIN {length} поза діапазоном (4-10). Встановлено 4.")
                    length = 4
            except ValueError:
                current_app.logger.warning(f"ENTRIES_BP: generate_password_api - Некоректна довжина PIN '{pin_length_str}'. Встановлено 4.")
                length = 4
            pin = password_generator.generate_pin_code(length=length)
            if pin:
                current_app.logger.info(f"ENTRIES_BP: generate_password_api - PIN згенеровано успішно (довжина: {length}).")
                return jsonify(success=True, password=pin)
            else:
                current_app.logger.error(f"ENTRIES_BP: generate_password_api - Не вдалося згенерувати PIN-код (довжина: {length}).")
                return jsonify(success=False, error="Не вдалося згенерувати PIN-код.")
        
        elif gen_type == 'passphrase':
            words_str = request.args.get('words', '4')
            num_words = 0
            current_app.logger.info(f"ENTRIES_BP: generate_password_api - Тип: passphrase, запитана кількість слів: '{words_str}'")
            try:
                num_words = int(words_str)
                if not (2 <= num_words <= 10):
                    current_app.logger.warning(f"ENTRIES_BP: generate_password_api - Кількість слів {num_words} поза діапазоном (2-10). Встановлено 4.")
                    num_words = 4
            except ValueError:
                current_app.logger.warning(f"ENTRIES_BP: generate_password_api - Некоректна кількість слів '{words_str}'. Встановлено 4.")
                num_words = 4
            passphrase = password_generator.generate_memorable_password(num_words=num_words)
            if passphrase:
                current_app.logger.info(f"ENTRIES_BP: generate_password_api - Парольна фраза згенерована успішно (слів: {num_words}).")
                return jsonify(success=True, password=passphrase)
            else:
                current_app.logger.error(f"ENTRIES_BP: generate_password_api - Не вдалося згенерувати парольну фразу (слів: {num_words}).")
                return jsonify(success=False, error="Не вдалося згенерувати парольну фразу.")
        
        else:
            preset_configs = {
                "easy":   {"min_len": 8,  "def_len": 8,  "upper": False, "lower": True,  "digits": True,  "special": False},
                "medium": {"min_len": 12, "def_len": 12, "upper": True,  "lower": True,  "digits": True,  "special": False},
                "strong": {"min_len": 16, "def_len": 16, "upper": True,  "lower": True,  "digits": True,  "special": True},
            }
            MAX_LENGTH_OVERALL = 50
            config_key = gen_type if gen_type in preset_configs else "strong"
            config = preset_configs[config_key]
            current_app.logger.info(f"ENTRIES_BP: generate_password_api - Тип: {config_key}, конфігурація: {config}")

            min_length_for_preset = config["min_len"]
            default_length_for_preset = config["def_len"]
            user_length_str = request.args.get('length')
            
            try:
                length = default_length_for_preset if user_length_str is None else int(user_length_str)
                if not (min_length_for_preset <= length <= MAX_LENGTH_OVERALL):
                    error_message = f"Довжина пароля для '{config_key}' типу має бути від {min_length_for_preset} до {MAX_LENGTH_OVERALL}. Ви вказали: {length}."
                    current_app.logger.warning(f"ENTRIES_BP: generate_password_api - {error_message}")
                    return jsonify(success=False, error=error_message), 400
            except ValueError:
                error_message = f"Некоректне значення довжини ('{user_length_str}'). Введіть число від {min_length_for_preset} до {MAX_LENGTH_OVERALL}."
                current_app.logger.warning(f"ENTRIES_BP: generate_password_api - {error_message}")
                return jsonify(success=False, error=error_message), 400

            if not (config["upper"] or config["lower"] or config["digits"] or config["special"]):
                current_app.logger.error(f"ENTRIES_BP: generate_password_api - Помилка конфігурації генератора для типу '{config_key}': не обрано типів символів.")
                return jsonify(success=False, error="Помилка конфігурації генератора: не обрано типів символів."), 500

            generated_password = password_generator.generate_password(
                length=length, use_uppercase=config["upper"], use_lowercase=config["lower"],
                use_digits=config["digits"], use_special_chars=config["special"]
            )
            
            if generated_password:
                current_app.logger.info(f"ENTRIES_BP: generate_password_api - Пароль типу '{config_key}' згенеровано успішно (довжина: {length}).")
                return jsonify(success=True, password=generated_password)
            else:
                current_app.logger.error(f"ENTRIES_BP: generate_password_api - Не вдалося згенерувати пароль типу '{config_key}' (довжина: {length}). Сервіс повернув Falsy.")
                return jsonify(success=False, error="Не вдалося згенерувати пароль."), 400
    except Exception as e:
        current_app.logger.error(f"ENTRIES_BP: generate_password_api - Непередбачена помилка: {e}", exc_info=True)
        return jsonify(success=False, error="Внутрішня помилка сервера."), 500


@entries_bp.route('/add', methods=['GET', 'POST'])
@login_required
def add_entry():
    entry_service = current_app.extensions['entry_service']
    user_id = session['user_id']
    
    if request.method == 'POST':
        payload = {k: request.form.get(k) for k in request.form}
        payload['plain_password'] = request.form.get('password')
        payload['email'] = request.form.get('entry_email')
        
        if not payload.get('site_name') or not payload.get('login') or not payload.get('plain_password'):
            message = "Назва сайту, логін та пароль є обов'язковими полями."
            current_app.logger.warning(f"ENTRIES_BP: add_entry - Відсутні обов'язкові поля для user_id {user_id}. Повідомлення: {message}")
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify(success=False, error=message), 400
            flash(message, "danger")
            return redirect(url_for('entries.dashboard'))

        payload_cleaned = {k: v for k, v in payload.items() if v is not None and v != ''}
        
        new_entry_obj, message = entry_service.add_entry(user_id=user_id, **payload_cleaned)

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            if new_entry_obj:
                current_app.logger.info(f"ENTRIES_BP: add_entry (AJAX) - Запис ID {new_entry_obj.entry_id} успішно додано для user_id {user_id}.")
                return jsonify(success=True, message=message or "Запис успішно додано!",
                               entry={ 'entry_id': new_entry_obj.entry_id,
                                       'site_name': new_entry_obj.site_name,
                                       'login': new_entry_obj.login,
                                       'email': new_entry_obj.email,
                                       'view_url': url_for('entries.view_entry_ajax_content', entry_id=new_entry_obj.entry_id)
                                     })
            current_app.logger.error(f"ENTRIES_BP: add_entry (AJAX) - Помилка додавання запису для user_id {user_id}. Повідомлення: {message}")
            return jsonify(success=False, error=message or "Помилка додавання запису."), 400
        
        if new_entry_obj:
            current_app.logger.info(f"ENTRIES_BP: add_entry (POST) - Запис ID {new_entry_obj.entry_id} успішно додано для user_id {user_id}.")
            flash(message or "Новий запис успішно додано!", "success")
            return redirect(url_for('entries.dashboard', view_entry_id=new_entry_obj.entry_id))
        else:
            current_app.logger.error(f"ENTRIES_BP: add_entry (POST) - Помилка додавання запису для user_id {user_id}. Повідомлення: {message}")
            flash(message or "Помилка додавання запису.", "danger")
            return redirect(url_for('entries.dashboard'))
    
    return redirect(url_for('entries.dashboard'))


@entries_bp.route('/edit/<int:entry_id>', methods=['GET', 'POST'])
@login_required
def edit_entry(entry_id):
    entry_service = current_app.extensions['entry_service']
    user_id = session['user_id']
    
    if request.method == 'POST':
        update_payload = {k: request.form.get(k) for k in request.form}
        new_plain_password = request.form.get('password')
        if new_plain_password:
            update_payload['plain_password'] = new_plain_password
        else:
            update_payload.pop('password', None)
            update_payload.pop('plain_password', None)

        update_payload['email'] = request.form.get('entry_email')
        update_payload_cleaned = {k: v for k, v in update_payload.items() if v is not None}
                                     
        updated_entry_obj, message = entry_service.update_entry_details(
            entry_id=entry_id, user_id=user_id, **update_payload_cleaned
        )

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            if updated_entry_obj:
                current_app.logger.info(f"ENTRIES_BP: edit_entry (AJAX) - Запис ID {entry_id} успішно оновлено для user_id {user_id}.")
                return jsonify(success=True, message=message or "Запис успішно оновлено!",
                               entry={ 'entry_id': updated_entry_obj.entry_id,
                                       'site_name': updated_entry_obj.site_name,
                                       'login': updated_entry_obj.login,
                                       'email': updated_entry_obj.email,
                                       'view_url': url_for('entries.view_entry_ajax_content', entry_id=updated_entry_obj.entry_id)
                                     })
            current_app.logger.error(f"ENTRIES_BP: edit_entry (AJAX) - Помилка оновлення запису ID {entry_id} для user_id {user_id}. Повідомлення: {message}")
            return jsonify(success=False, error=message or "Помилка оновлення запису."), 400
        
        if updated_entry_obj:
            current_app.logger.info(f"ENTRIES_BP: edit_entry (POST) - Запис ID {entry_id} успішно оновлено для user_id {user_id}.")
            flash(message or "Запис успішно оновлено!", "success")
        else:
            current_app.logger.error(f"ENTRIES_BP: edit_entry (POST) - Помилка оновлення запису ID {entry_id} для user_id {user_id}. Повідомлення: {message}")
            flash(message or "Помилка оновлення запису.", "danger")
        return redirect(url_for('entries.dashboard', view_entry_id=entry_id))
    
    return redirect(url_for('entries.dashboard'))


@entries_bp.route('/delete/<int:entry_id>', methods=['POST'])
@login_required
def delete_entry(entry_id):
    entry_service = current_app.extensions['entry_service']
    user_id = session['user_id']
    
    success, message = entry_service.delete_entry_item(entry_id, user_id)
        
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        if success:
            current_app.logger.info(f"ENTRIES_BP: delete_entry (AJAX) - Запис ID {entry_id} успішно видалено для user_id {user_id}.")
            return jsonify(success=True, message=message or "Запис успішно видалено.", entry_id=entry_id)
        current_app.logger.error(f"ENTRIES_BP: delete_entry (AJAX) - Помилка видалення запису ID {entry_id} для user_id {user_id}. Повідомлення: {message}")
        return jsonify(success=False, error=message or "Помилка видалення запису."), 400
            
    if success:
        current_app.logger.info(f"ENTRIES_BP: delete_entry (POST) - Запис ID {entry_id} успішно видалено для user_id {user_id}.")
        flash(message or "Запис успішно видалено!", "success")
    else:
        current_app.logger.error(f"ENTRIES_BP: delete_entry (POST) - Помилка видалення запису ID {entry_id} для user_id {user_id}. Повідомлення: {message}")
        flash(message or "Помилка видалення запису.", "danger")
    return redirect(url_for('entries.dashboard'))