
from flask import Blueprint, redirect, url_for, session


main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    """
    Головна сторінка.
    Якщо користувач залогінений, перенаправляє на вітальну сторінку (S3).
    Інакше показує сторінку входу.
    """
    if 'user_id' in session:
        
        return redirect(url_for('entries.welcome_page'))
    
    return redirect(url_for('auth.login'))

