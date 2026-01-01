

from . import db
from datetime import datetime

class PasswordEntry(db.Model):
    __tablename__ = 'entries'
    entry_id = db.Column(db.Integer, primary_key=True) 
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    
    site_name = db.Column(db.String(150), nullable=False)
    site_url = db.Column(db.String(250), nullable=True)
    login = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), nullable=True) 
    enc_password = db.Column(db.Text, nullable=False) 
    
    nickname = db.Column(db.String(150), nullable=True)
    custom_id = db.Column(db.String(100), nullable=True) 
    
    old_password = db.Column(db.Text, nullable=True) 
    backup_email = db.Column(db.String(150), nullable=True)
    password_hint = db.Column(db.Text, nullable=True) 
    
    phone_number = db.Column(db.String(50), nullable=True)
    secret_word = db.Column(db.Text, nullable=True) 
    
    date_added = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    date_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=True)

    def __repr__(self):
        return f"PasswordEntry(ID: {self.entry_id}, Site: '{self.site_name}', UserID: {self.user_id})"