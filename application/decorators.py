
from functools import wraps
from flask import session, flash, redirect, url_for, request

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Будь ласка, увійдіть, щоб отримати доступ до цієї сторінки.", "warning")
            return redirect(url_for('auth.login', next=request.url)) 
        return f(*args, **kwargs)
    return decorated_function

def guest_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' in session:
            flash("Ви вже увійшли в систему.", "info")
       
            return redirect(url_for('entries.welcome_page')) 
        return f(*args, **kwargs)
    return decorated_function