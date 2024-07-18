import os
import re
from flask import Flask, render_template, redirect, url_for, flash, request, session, jsonify, get_flashed_messages, g
from flask_socketio import SocketIO, emit
import subprocess
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_principal import Principal, Permission, RoleNeed, identity_loaded, UserNeed, Identity, AnonymousIdentity, identity_changed
from werkzeug.security import check_password_hash
import logging
from logging.handlers import RotatingFileHandler
from config import Config, get_config
from models import db, User
from main import free_onu as onu_id
from main import registr_onu as rg
from main import get_uncf_onu as uncf_onu

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")
# Define the directory where commands will be executed
WORKING_DIRECTORY = "/home/maestro/your/help2/shell"
app.config.from_object(Config)

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

principals = Principal(app)

admin_permission = Permission(RoleNeed('admin'))
master_permission = Permission(RoleNeed('master'))

# Создаем директорию для логов, если она не существует
log_directory = 'logs'
if not os.path.exists(log_directory):
    os.makedirs(log_directory)

# Указываем полный путь к файлу логов
log_file_path = os.path.join(log_directory, 'app.log')

# Настраиваем логирование
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file_path),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# ротация логов
file_handler = RotatingFileHandler(log_file_path, maxBytes=10240, backupCount=10)
logger.addHandler(file_handler)



def read_log(file_path):
    log_pattern = re.compile(
        r'(?P<level>INFO|WARNING|ERROR) - '
        r'(?P<ip>[\d\.]+)? - - '
        r'\[(?P<timestamp>.+?)\] "(?P<request>.*?)" (?P<status>\d{3}) -'
    )
    
    data = []
    with open(file_path, mode='r') as file:
        for line in file:
            match = log_pattern.match(line)
            if match:
                entry = match.groupdict()
                data.append(entry)
            else:
                # Handle user action logs or lines that do not match the pattern
                parts = line.strip().split(' - ')
                if len(parts) == 3:
                    level, ip, message = parts
                    data.append({
                        'level': level,
                        'ip': ip,
                        'timestamp': '',
                        'request': message,
                        'status': ''
                    })
                elif len(parts) == 2:
                    level, message = parts
                    data.append({
                        'level': level,
                        'ip': '',
                        'timestamp': '',
                        'request': message,
                        'status': ''
                    })
    return data



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    if current_user.is_authenticated:
        identity.provides.add(UserNeed(current_user.id))
        identity.provides.add(RoleNeed(current_user.role))

@app.context_processor
def inject_identity():
    return dict(current_identity=g.identity if hasattr(g, 'identity') else None)



@socketio.on('execute_command')
def handle_command(command):
    try:
        # Ensure the working directory exists and has the right permissions
        if not os.path.exists(WORKING_DIRECTORY):
            os.makedirs(WORKING_DIRECTORY)

        # Проверка команд на допустимость
        allowed_commands = ['ls', 'cat', 'echo','pwd','arp',
                            'ip','ping','traceroute','nslookup','dig','netstat','tracepath']  # Допустимые команды
        command_name = command.split()[0]
       
        if command_name not in allowed_commands:
            raise ValueError("Команда не разрешена")

        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True, cwd=WORKING_DIRECTORY)
    except subprocess.CalledProcessError as e:
        result = e.output
    except Exception as e:
        result = str(e)
    emit('command_result', result)
    


@app.route('/inconsole')
@login_required
def inconsole():
    return render_template('inconsole.html')


@app.route('/show-uncg-onu')
@login_required
def show_uncf_onu():

    return render_template('get_uncf_onu.html')

@app.route('/get-uncf-onu', methods=['POST'])
def get_uncf_onu():
    onu_uncf_list = uncf_onu()
   
    return jsonify({"data": onu_uncf_list})



@app.route('/logs')
@login_required
def logs():
    data = read_log(log_file_path)
    return render_template('logs.html', data=data)


@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            identity_changed.send(app, identity=Identity(user.id))
            logger.info(f"Користувач {username} успішно залогінився")
            return redirect(url_for('index'))
        else:
            flash("Хибна спроба. Будь ласка, перевірте ім'я користувача та пароль", "danger")
            logger.warning(f"Невдала спроба входу на ім'я користувача: {username}")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    username = current_user.username
    logout_user()
    for key in ('identity.name', 'identity.auth_type'):
        session.pop(key, None)
    identity_changed.send(app, identity=AnonymousIdentity())
    logger.info(f'Користувач {username} розлогінився')
    return redirect(url_for('login'))



conf = get_config()

@app.route('/reg-onu')
@login_required
@admin_permission.require(http_exception=403)
def reg_onu():
    device_name = conf["sw"]["name"]
    device_ip = conf["sw"]["ip"]
    interfaces = conf["sw"]["interfaces"]
    speed_profiles = conf["sw"]["speed_profiles"]
    line_profiles = conf["sw"]["line_profiles"]
    return render_template('register_onu.html', device_name=device_name,device_ip=device_ip,
                            interfaces=interfaces, speed_profiles=speed_profiles, 
                           line_profiles=line_profiles)

@app.route('/get-free-onu', methods=['POST'])
def run_script():
    data = request.get_json()
    interface = data['interface']
    free_onu_id = onu_id(interface)
    
    flash(f"Вільний ONU ID для інтерфейсу {interface}: {free_onu_id}", 'success')
    
    messages = get_flashed_messages(with_categories=True)
    return jsonify({"onuId": free_onu_id, "messages": messages})



@app.route('/register-onu', methods=['POST'])
def register_onu():
    try:
        data = request.get_json()
        interface = data.get('interface')
        onu_id = data.get('onuId')
        speed = data.get('speed')
        vlan = data.get('vlan')
        comment = data.get('comment')
        sn = data.get('sn')

        # Split the string by '+++'
        vlan_name_id = vlan.split('+++')
        vlan_name = vlan_name_id[0]
        vlan_id = vlan_name_id[1]
        

        reg_onu = rg(interface,onu_id,sn,speed,vlan_name,vlan_id,comment)
        
        
        flash(f"ONU SN:{sn} на місце: {interface}:{onu_id} успішно зареєстровано", 'success')
        messages = get_flashed_messages(with_categories=True)
        return jsonify({"messages": messages}), 200

    except Exception as e:
        response = {
            'status': 'error',
            'message': str(e)
        }

        flash(f"ПОМИЛКА {response}", 'danger')
        messages = get_flashed_messages(with_categories=True)
        return jsonify({"response": response, "messages": messages}), 400

if __name__ == '__main__':
    socketio.run(app, host='127.0.0.1', port=5000, debug=True)
    # app.run(debug=True)
