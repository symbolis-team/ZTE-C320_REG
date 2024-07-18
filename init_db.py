from app import app, db
from models import User
from werkzeug.security import generate_password_hash

with app.app_context():
    db.create_all()  # Создание таблиц

    # Пример создания пользователей с хэшированными паролями
    admin = User(username='admin', password=generate_password_hash('admin'), role='admin')
  
    # Использование db.session.add_all для добавления нескольких объектов
    db.session.add_all([admin])
    db.session.commit()  # Сохранение пользователей в базе данных
