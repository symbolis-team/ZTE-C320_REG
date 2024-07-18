from app import app, db
from models import User
from werkzeug.security import generate_password_hash

with app.app_context():
    db.create_all()  # Создание таблиц

    # Пример создания пользователей с хэшированными паролями
    maestro = User(username='maestro', password=generate_password_hash('orchestra1306'), role='admin')
    valera = User(username='valera', password=generate_password_hash('0632901968'), role='admin')
    zahar = User(username='zahar', password=generate_password_hash('zahar1979'), role='admin')
    kdp = User(username='kdp', password=generate_password_hash('nikname1'), role='admin')
    gusev = User(username='gusev', password=generate_password_hash('gusev1gusev'), role='admin')
    pit = User(username='pit', password=generate_password_hash('09081988'), role='admin')
  
    # Использование db.session.add_all для добавления нескольких объектов
    db.session.add_all([maestro, valera, zahar, kdp, gusev, pit])
    db.session.commit()  # Сохранение пользователей в базе данных
