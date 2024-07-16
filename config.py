# имортируем YAML
import yaml
# имортируем OS
import os

def get_config():
# Загружаем конфиг YAML файл
    with open('config.yaml', 'r') as file:
        config = yaml.safe_load(file)
    return config    

class Config:
    SECRET_KEY = os.urandom(24)
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # Установка времени жизни сессии в секундах (например, 30 минут)
    PERMANENT_SESSION_LIFETIME = 7200  # 120 минут = 7200 секунд

