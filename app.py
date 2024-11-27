#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_session import Session
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
from celery import Celery
from celery.result import AsyncResult
from netmiko import ConnectHandler
import ipaddress
from functools import wraps
import socket
import uuid
from tacacs_plus.client import TACACSClient
from tacacs_plus.flags import TAC_PLUS_ACCT_FLAG_START, TAC_PLUS_ACCT_FLAG_WATCHDOG, TAC_PLUS_ACCT_FLAG_STOP
from datetime import timedelta, datetime
from cryptography.fernet import Fernet
import webaclchecker
import webaclcheckerdev
from modules import validate
from modules import config
from testyield import external_function

app = Flask(__name__)
app.config['SESSION_TYPE'] = 'filesystem'
app.secret_key = 'bb235a52f4a656b6fc68e94ded0cbb51'
app.permanent_session_lifetime = timedelta(minutes=15)  # Установите время таймаута (например, 15 минут)
app.config['CELERY_BROKER_URL'] = 'redis://localhost:6379/0'
app.config['CELERY_RESULT_BACKEND'] = 'redis://localhost:6379/0'
app.config.from_object(config)
cipher_suite = Fernet(app.config['SECRET_KEY'])
tacacs_key = cipher_suite.decrypt(app.config['TACACS_KEY']).decode()
Session(app)

cli = TACACSClient('194.247.148.131', 49, tacacs_key, timeout=10, family=socket.AF_INET)

CORS(app,resources={r"/*":{"origins":"*"}})
socketio = SocketIO(app, message_queue='redis://localhost:6379/0', async_mode='threading', cors_allowed_origins="*")

celery = Celery(app.name, broker=app.config['CELERY_BROKER_URL'])
celery.conf.update(app.config)

addr = ipaddress.ip_address # Слегка сократим имена функций
net = ipaddress.ip_network
now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")


inputString = '' # Строка с параметрами запроса в aclchecker


@app.before_request
def make_session_permanent():
    session.permanent = True  # Делаем сессию постоянной
    session.modified = True    # Обновляем сессию, чтобы продлить таймаут

@socketio.on('connect', namespace='/task')
def task_connect():
    print("Клиент подключился к пространству /task")

@app.route('/task')
def task_status():
    task_id = request.args.get('task_id')
    return render_template('result.html', task_id=task_id, inputString=inputString)

@socketio.on('join', namespace='/task')
def on_join(data):
    # Пользователь подключается к комнате, связанной с его task_id
    task_id = data['task_id']
    join_room(task_id)
    print(f"Пользователь подключился к комнате: {task_id}")

@celery.task
def run_webaclchecker(username, password, prot, src, dst, dst_port, gw, vrf, task_id):
    
    for data in webaclchecker.run(username, password,
                prot, addr(src), addr(dst), dst_port, gw, vrf):
        print(f"Отправка данных: {data}")  # Для отладки
        socketio.emit('task_update', data, to=task_id, namespace='/task')
    socketio.emit('task_complete', {"task_id": task_id}, to=task_id, namespace='/task')

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function            


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            username = request.form['username']
            password = request.form['password']
            auth = cli.authenticate(username, password)
        except:
            error = "Invalid login or password"
            return render_template('login.html', error = error)
        if auth.valid:
            session['username'] = username
            encrypted_password = cipher_suite.encrypt(password.encode())
            session['password'] = encrypted_password
            return redirect(url_for('index'))
        else:
            return jsonify({'message': 'Authentication failed!'}), 401
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    session.pop('password', None)
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/', methods=['POST', 'GET'])
@login_required
def aclchecker():
    task_id = str(uuid.uuid4())
    global inputString
    gw = ''
    src = ''
    dst = ''
    dst_port = ''
    prot = ''
    vrf = 'default'
    start = request.form['action'] == 'Start'
    if request.method == 'POST':
        inputResult = request.form
        gw = inputResult['gw']
        src = inputResult['src']
        dst = inputResult['dst']
        dst_port = inputResult['dport']
        prot = inputResult['protocol']
        vrf = inputResult['vrf']
    if start:
        errors = validate.validateAll(prot, src, dst, dst_port, gw, vrf='default')
        if len(errors) == 0:
            try:
                username = session['username']
                decrypted_password = cipher_suite.decrypt(session['password']).decode()
                inputString = f'Protocol: {prot}, Source: {src}, Destination: {dst}, Port: {dst_port}, First hop: {gw}, VRF: {vrf}'
                run_webaclchecker.apply_async(args=(username, decrypted_password, prot, src, dst, dst_port, gw, vrf, task_id))
                with open('ac.log', 'a') as f:
                    data = (str(now) + ' ' + session['username'] + ' ' + str(inputResult) + ' ' + '\n')
                    f.write(data)
                    return redirect(url_for('task_status', task_id=task_id))
            except KeyError:
                return redirect(url_for('login'))
    return render_template('index.html', errors = errors,
                           gw = gw,
                           src = src,
                           dst = dst,
                           dst_port = dst_port,
                           prot = prot,
                           vrf = vrf)

@app.route('/about', methods=['GET'])
@login_required
def about():
    return render_template('about.html')



if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, ssl_context=('ac.net.rts-cert.pem', 'ac.net.rts-key.pem'))