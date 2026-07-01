# -*- coding: utf-8 -*-
import os
import sys
import uuid
import time
import json
import random
import string
import threading
import sqlite3
import shutil
import secrets
import re
from datetime import datetime, timedelta
from urllib.parse import quote
from PIL import Image
import io

from flask import Flask, request, render_template_string, jsonify, session, redirect, url_for, send_file, abort
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

def get_base_path():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

BASE_DIR = get_base_path()
DATA_DIR = os.path.join(BASE_DIR, 'data')
UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')
DB_PATH = os.path.join(DATA_DIR, 'chatroom.db')

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['MAX_CONTENT_LENGTH'] = 60 * 1024 * 1024

socketio = SocketIO(app, cors_allowed_origins="*", ping_timeout=30, ping_interval=10)

db_lock = threading.Lock()
online_lock = threading.Lock()
online_users = {}
ip_error_count = {}
admin_ip_error_count = {}
msg_rate_limit = {}
room_max_users_cache = {}
user_last_active = {}

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=5, check_same_thread=False, isolation_level=None)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA busy_timeout=5000')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db_lock:
        conn = get_db()
        conn.execute('''
            CREATE TABLE IF NOT EXISTS admin (
                id INTEGER PRIMARY KEY,
                password_hash TEXT NOT NULL
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS rooms (
                room_id TEXT PRIMARY KEY,
                invite_code TEXT NOT NULL,
                max_users INTEGER DEFAULT 100,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                room_id TEXT NOT NULL,
                sender_sid TEXT,
                nickname TEXT NOT NULL,
                msg_type TEXT DEFAULT 'text',
                content TEXT,
                file_size INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (room_id) REFERENCES rooms(room_id) ON DELETE CASCADE
            )
        ''')
        cur = conn.execute('SELECT COUNT(*) FROM admin')
        if cur.fetchone()[0] == 0:
            init_pwd = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
            conn.execute('INSERT INTO admin (password_hash) VALUES (?)', (generate_password_hash(init_pwd),))
            conn.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', ('default_max_users', '100'))
            conn.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', ('msg_load_limit', '200'))
            conn.commit()
            return init_pwd
        return None

def get_setting(key, default='100'):
    with db_lock:
        conn = get_db()
        cur = conn.execute('SELECT value FROM settings WHERE key = ?', (key,))
        row = cur.fetchone()
        return row[0] if row else default

def set_setting(key, value):
    with db_lock:
        conn = get_db()
        conn.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (key, value))

def get_room_max_users(room_id):
    if room_id in room_max_users_cache:
        return room_max_users_cache[room_id]
    with db_lock:
        conn = get_db()
        cur = conn.execute('SELECT max_users FROM rooms WHERE room_id = ?', (room_id,))
        row = cur.fetchone()
        if row:
            room_max_users_cache[room_id] = row[0]
            return row[0]
        return int(get_setting('default_max_users', '100'))

def get_room_msg_limit():
    return int(get_setting('msg_load_limit', '200'))

def is_admin_logged_in():
    if not session.get('admin_logged_in', False):
        return False
    login_time = session.get('admin_login_time')
    if not login_time:
        return False
    if time.time() - login_time > 86400:
        session.pop('admin_logged_in', None)
        session.pop('admin_login_time', None)
        return False
    return True

def clean_uploads():
    if os.path.exists(UPLOAD_DIR):
        shutil.rmtree(UPLOAD_DIR)
        os.makedirs(UPLOAD_DIR, exist_ok=True)

def clean_room_uploads(room_id):
    room_upload_dir = os.path.join(UPLOAD_DIR, room_id)
    if os.path.exists(room_upload_dir):
        shutil.rmtree(room_upload_dir)

def validate_file_type(file_data, filename):
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    image_exts = {'jpg', 'jpeg', 'png', 'gif', 'webp'}
    video_exts = {'mp4', 'webm', 'mov'}
    if ext in image_exts:
        try:
            img = Image.open(io.BytesIO(file_data))
            if img.format and img.format.lower() in {'jpeg', 'png', 'gif', 'webp'}:
                return 'image', ext
        except Exception:
            pass
    if ext in video_exts:
        return 'video', ext
    return None, None

def get_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr or 'unknown'

def check_rate_limit(sid):
    now = time.time()
    if sid not in msg_rate_limit:
        msg_rate_limit[sid] = []
    msg_rate_limit[sid] = [t for t in msg_rate_limit[sid] if now - t < 1]
    if len(msg_rate_limit[sid]) >= 3:
        return False
    msg_rate_limit[sid].append(now)
    return True

def check_ip_ban(ip, room_id=None):
    key = f'{ip}:{room_id}' if room_id else f'admin:{ip}'
    if key not in ip_error_count:
        return False
    data = ip_error_count[key]
    if data.get('ban_until') and time.time() < data['ban_until']:
        return True
    if data.get('ban_until') and time.time() >= data['ban_until']:
        del ip_error_count[key]
        return False
    return False

def record_ip_error(ip, room_id=None):
    key = f'{ip}:{room_id}' if room_id else f'admin:{ip}'
    now = time.time()
    if key not in ip_error_count:
        ip_error_count[key] = {'count': 0, 'ban_until': None}
    data = ip_error_count[key]
    if data.get('ban_until') and now >= data['ban_until']:
        data['count'] = 0
        data['ban_until'] = None
    data['count'] += 1
    if data['count'] >= 6:
        data['ban_until'] = now + 600
        return True
    return False

def clear_ip_record(ip, room_id=None):
    key = f'{ip}:{room_id}' if room_id else f'admin:{ip}'
    if key in ip_error_count:
        del ip_error_count[key]

def update_user_active(sid):
    with online_lock:
        user_last_active[sid] = time.time()

USER_HTML = '''
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>匿名聊天室</title>
    <script src="https://cdn.socket.io/4.6.0/socket.io.min.js"></script>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a0f; color: #e0e0e0; height:100vh; display:flex; justify-content:center; align-items:center; }
        .container { width:100%; max-width:1200px; height:100vh; max-height:800px; display:flex; border-radius:16px; overflow:hidden; background: rgba(20,20,30,0.85); backdrop-filter:blur(20px); box-shadow:0 25px 60px rgba(0,0,0,0.8); border:1px solid rgba(255,255,255,0.06); }
        .sidebar { width:220px; background:rgba(15,15,25,0.6); border-right:1px solid rgba(255,255,255,0.05); display:flex; flex-direction:column; flex-shrink:0; }
        .sidebar-header { padding:20px 18px 14px; border-bottom:1px solid rgba(255,255,255,0.05); }
        .sidebar-header h3 { font-size:13px; font-weight:600; color:rgba(255,255,255,0.3); letter-spacing:1px; text-transform:uppercase; }
        .sidebar-header .count { font-size:20px; font-weight:700; color:#fff; margin-top:4px; }
        .sidebar-header .count span { font-size:13px; font-weight:400; color:rgba(255,255,255,0.4); }
        .user-list { flex:1; overflow-y:auto; padding:10px 12px; }
        .user-list::-webkit-scrollbar { width:3px; }
        .user-list::-webkit-scrollbar-thumb { background:rgba(255,255,255,0.15); border-radius:10px; }
        .user-item { padding:6px 10px; margin-bottom:2px; border-radius:6px; font-size:13px; color:rgba(255,255,255,0.75); transition:0.2s; display:flex; align-items:center; gap:8px; }
        .user-item:hover { background:rgba(255,255,255,0.04); }
        .user-item .dot { display:inline-block; width:6px; height:6px; border-radius:50%; background:#4ade80; flex-shrink:0; }
        .user-item .nick { word-break:break-all; }
        .user-item.self { color:#60a5fa; }
        .user-item.self .dot { background:#60a5fa; }
        .chat-area { flex:1; display:flex; flex-direction:column; min-width:0; }
        .chat-header { padding:14px 24px; border-bottom:1px solid rgba(255,255,255,0.06); display:flex; justify-content:space-between; align-items:center; }
        .chat-header .room-info { font-size:15px; font-weight:600; }
        .chat-header .room-info small { font-weight:400; color:rgba(255,255,255,0.35); font-size:12px; margin-left:8px; }
        .chat-header .status { font-size:12px; color:rgba(255,255,255,0.25); }
        .chat-header .status.online { color:#4ade80; }
        .chat-header .status.offline { color:#f87171; }
        .messages { flex:1; overflow-y:auto; padding:16px 24px; display:flex; flex-direction:column; gap:4px; }
        .messages::-webkit-scrollbar { width:4px; }
        .messages::-webkit-scrollbar-thumb { background:rgba(255,255,255,0.1); border-radius:10px; }
        .msg { display:flex; flex-direction:column; animation:fadeIn 0.2s ease; }
        .msg .meta { font-size:11px; color:rgba(255,255,255,0.3); margin-bottom:2px; display:flex; align-items:center; gap:8px; }
        .msg .meta .name { font-weight:600; color:rgba(255,255,255,0.6); max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
        .msg .meta .time { font-size:10px; color:rgba(255,255,255,0.2); flex-shrink:0; }
        .msg .bubble { background:rgba(255,255,255,0.06); padding:8px 14px; border-radius:12px; border-bottom-left-radius:4px; max-width:75%; word-wrap:break-word; word-break:break-word; white-space:pre-wrap; display:inline-block; font-size:14px; line-height:1.6; min-height:1px; }
        .msg .bubble img { max-width:100%; max-height:300px; border-radius:8px; display:block; margin:4px 0; cursor:pointer; }
        .msg .bubble video { max-width:100%; max-height:360px; border-radius:8px; display:block; margin:4px 0; }
        .msg .bubble .file-load { display:inline-block; padding:6px 16px; border-radius:6px; background:rgba(255,255,255,0.08); color:#60a5fa; font-size:13px; cursor:pointer; transition:0.2s; border:1px solid rgba(255,255,255,0.06); }
        .msg .bubble .file-load:hover { background:rgba(96,165,250,0.2); }
        .msg.system .bubble { background:rgba(255,255,255,0.03); color:rgba(255,255,255,0.3); font-size:12px; text-align:center; max-width:100%; border-radius:20px; padding:4px 16px; }
        .msg.system .meta { display:none; }
        .msg.error .bubble { background:rgba(248,113,113,0.08); color:#f87171; text-align:center; max-width:100%; border-radius:20px; padding:4px 16px; font-size:12px; }
        .msg.error .meta { display:none; }
        .msg .bubble .empty-placeholder { color:rgba(255,255,255,0.15); font-style:italic; font-size:12px; }
        @keyframes fadeIn { from { opacity:0; transform:translateY(6px); } to { opacity:1; transform:translateY(0); } }
        .input-area { padding:12px 24px 20px; border-top:1px solid rgba(255,255,255,0.05); display:flex; gap:10px; align-items:flex-end; background:rgba(0,0,0,0.2); }
        .input-area .input-wrap { flex:1; display:flex; flex-direction:column; gap:6px; }
        .input-area textarea { width:100%; padding:10px 14px; border-radius:12px; border:1px solid rgba(255,255,255,0.08); background:rgba(255,255,255,0.04); color:#e0e0e0; font-size:14px; resize:none; outline:none; transition:0.2s; font-family:inherit; min-height:42px; max-height:120px; }
        .input-area textarea:focus { border-color:rgba(96,165,250,0.4); background:rgba(255,255,255,0.06); }
        .input-area textarea::placeholder { color:rgba(255,255,255,0.2); }
        .input-area textarea:disabled { opacity:0.3; cursor:not-allowed; }
        .input-area .file-actions { display:flex; gap:6px; }
        .input-area .file-actions label { padding:6px 10px; border-radius:8px; background:rgba(255,255,255,0.05); color:rgba(255,255,255,0.4); cursor:pointer; font-size:18px; transition:0.2s; border:1px solid rgba(255,255,255,0.04); }
        .input-area .file-actions label:hover { background:rgba(255,255,255,0.1); color:rgba(255,255,255,0.7); }
        .input-area .file-actions label.disabled { opacity:0.3; cursor:not-allowed; }
        .input-area .file-actions input { display:none; }
        .input-area .send-btn { padding:8px 20px; border-radius:12px; border:none; background:linear-gradient(135deg,#60a5fa,#3b82f6); color:#fff; font-weight:600; font-size:14px; cursor:pointer; transition:0.2s; height:42px; flex-shrink:0; }
        .input-area .send-btn:hover { transform:scale(1.02); box-shadow:0 4px 20px rgba(96,165,250,0.25); }
        .input-area .send-btn:disabled { opacity:0.4; cursor:not-allowed; transform:none; }
        .login-overlay { position:fixed; inset:0; background:rgba(0,0,0,0.85); backdrop-filter:blur(30px); display:flex; justify-content:center; align-items:center; z-index:999; }
        .login-box { background:rgba(25,25,40,0.95); padding:44px 40px 36px; border-radius:20px; width:400px; max-width:90%; border:1px solid rgba(255,255,255,0.06); box-shadow:0 30px 80px rgba(0,0,0,0.6); }
        .login-box h2 { font-size:22px; font-weight:700; margin-bottom:6px; color:#fff; }
        .login-box .sub { color:rgba(255,255,255,0.3); font-size:13px; margin-bottom:28px; }
        .login-box label { display:block; font-size:12px; font-weight:600; color:rgba(255,255,255,0.35); margin-bottom:5px; letter-spacing:0.5px; }
        .login-box input { width:100%; padding:10px 14px; border-radius:10px; border:1px solid rgba(255,255,255,0.06); background:rgba(255,255,255,0.04); color:#e0e0e0; font-size:14px; outline:none; transition:0.2s; margin-bottom:16px; }
        .login-box input:focus { border-color:rgba(96,165,250,0.3); background:rgba(255,255,255,0.06); }
        .login-box input::placeholder { color:rgba(255,255,255,0.15); }
        .login-box .btn { width:100%; padding:11px; border-radius:10px; border:none; background:linear-gradient(135deg,#60a5fa,#3b82f6); color:#fff; font-weight:600; font-size:15px; cursor:pointer; transition:0.2s; margin-top:4px; }
        .login-box .btn:hover { transform:scale(1.01); box-shadow:0 4px 24px rgba(96,165,250,0.2); }
        .login-box .btn:disabled { opacity:0.4; cursor:not-allowed; transform:none; }
        .login-box .error { color:#f87171; font-size:13px; margin-top:8px; text-align:center; }
        .login-box .ban-info { color:#fbbf24; font-size:13px; margin-top:8px; text-align:center; }
        .login-box .file-note { color:rgba(255,255,255,0.2); font-size:11px; margin-top:14px; text-align:center; }
        .hidden { display:none !important; }
        @media (max-width:768px) { .sidebar { width:60px; } .sidebar-header h3 { display:none; } .sidebar-header .count span { display:none; } .sidebar-header .count { font-size:16px; text-align:center; } .user-item .nick { display:none; } .chat-header .status { display:none; } .login-box { padding:32px 24px; } .container { max-height:none; border-radius:0; } .msg .bubble { max-width:90%; } }
        .reconnecting-bar { display:none; background:rgba(251,191,36,0.15); border-bottom:1px solid rgba(251,191,36,0.2); padding:4px 24px; text-align:center; font-size:12px; color:#fbbf24; }
        .reconnecting-bar.active { display:block; }
    </style>
</head>
<body>
<div id="loginOverlay" class="login-overlay">
    <div class="login-box">
        <h2>💬 匿名聊天室</h2>
        <p class="sub">输入房间信息加入聊天</p>
        <label>房间号</label>
        <input id="roomInput" placeholder="2-20位字母数字" maxlength="20">
        <label>邀请码</label>
        <input id="codeInput" placeholder="4-12位字母数字" maxlength="12" type="password">
        <label>昵称</label>
        <input id="nickInput" placeholder="2-30字，支持中文和表情" maxlength="30">
        <button class="btn" id="joinBtn">加入房间</button>
        <div id="loginError" class="error"></div>
        <div id="loginBan" class="ban-info"></div>
        <div class="file-note">支持图片(10MB) 视频(50MB) · 内网部署</div>
    </div>
</div>

<div id="chatContainer" class="container hidden">
    <div class="sidebar">
        <div class="sidebar-header">
            <h3>在线用户</h3>
            <div class="count"><span id="onlineCount">0</span> <span>人</span></div>
        </div>
        <div class="user-list" id="userList"></div>
    </div>
    <div class="chat-area">
        <div class="chat-header">
            <div class="room-info">#<span id="roomTitle">房间</span> <small id="roomCodeDisplay"></small></div>
            <div class="status online" id="connStatus">● 已连接</div>
        </div>
        <div class="reconnecting-bar" id="reconnectingBar">⏳ 正在重连...</div>
        <div class="messages" id="messages"></div>
        <div class="input-area">
            <div class="input-wrap">
                <textarea id="msgInput" rows="1" placeholder="输入消息..." maxlength="2000"></textarea>
                <div class="file-actions">
                    <label for="imageInput" id="imageLabel">🖼️</label>
                    <input type="file" id="imageInput" accept="image/jpeg,image/png,image/gif,image/webp">
                    <label for="videoInput" id="videoLabel">🎬</label>
                    <input type="file" id="videoInput" accept="video/mp4,video/webm,video/quicktime">
                </div>
            </div>
            <button class="send-btn" id="sendBtn">发送</button>
        </div>
    </div>
</div>

<script>
let socket = null;
let currentRoom = '';
let currentNick = '';
let mySid = '';
let connected = false;
let fileUploading = false;
let reconnectAttempts = 0;
let maxReconnectAttempts = 10;
let isReconnecting = false;

const msgContainer = document.getElementById('messages');
const userList = document.getElementById('userList');
const connStatus = document.getElementById('connStatus');
const reconnectingBar = document.getElementById('reconnectingBar');
const msgInput = document.getElementById('msgInput');
const sendBtn = document.getElementById('sendBtn');
const imageLabel = document.getElementById('imageLabel');
const videoLabel = document.getElementById('videoLabel');

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatTime(ts) {
    const d = new Date(ts);
    return d.toTimeString().slice(0,5);
}

function addMessage(data) {
    const div = document.createElement('div');
    div.className = 'msg';
    if (data.type === 'system') {
        div.classList.add('system');
        div.innerHTML = `<div class="bubble">${escapeHtml(data.text)}</div>`;
    } else if (data.type === 'error') {
        div.classList.add('error');
        div.innerHTML = `<div class="bubble">⚠️ ${escapeHtml(data.text)}</div>`;
    } else {
        const isSelf = data.sid === mySid;
        const nameColor = isSelf ? '#60a5fa' : 'rgba(255,255,255,0.6)';
        let content = '';
        if (data.msg_type === 'image') {
            const size = data.file_size || 0;
            if (size <= 3 * 1024 * 1024) {
                content = `<img src="${escapeHtml(data.content)}" onclick="window.open('${escapeHtml(data.content)}','_blank')">`;
            } else {
                content = `<div class="file-load" onclick="loadFile(this,'${escapeHtml(data.content)}','image')">🖼️ 点击加载原图 (${(size/1024/1024).toFixed(1)}MB)</div>`;
            }
        } else if (data.msg_type === 'video') {
            const size = data.file_size || 0;
            content = `<div class="file-load" onclick="loadFile(this,'${escapeHtml(data.content)}','video')">🎬 点击播放视频 (${(size/1024/1024).toFixed(1)}MB)</div>`;
        } else {
            const textContent = data.text || data.content || '';
            if (textContent.trim() === '') {
                content = '<span class="empty-placeholder">[空消息]</span>';
            } else {
                content = escapeHtml(textContent);
            }
        }
        div.innerHTML = `
            <div class="meta">
                <span class="name" style="color:${nameColor}">${escapeHtml(data.nickname)}</span>
                <span class="time">${formatTime(data.time)}</span>
            </div>
            <div class="bubble">${content}</div>
        `;
    }
    msgContainer.appendChild(div);
    msgContainer.scrollTop = msgContainer.scrollHeight;
}

function addSystemMessage(text) {
    addMessage({ type: 'system', text: text, time: Date.now() });
}

function addErrorMessage(text) {
    addMessage({ type: 'error', text: text, time: Date.now() });
}

function loadFile(el, url, type) {
    if (type === 'image') {
        const img = document.createElement('img');
        img.src = url;
        img.onclick = function() { window.open(url, '_blank'); };
        el.parentElement.replaceChild(img, el);
    } else if (type === 'video') {
        const video = document.createElement('video');
        video.src = url;
        video.controls = true;
        video.style.maxWidth = '100%';
        video.style.maxHeight = '360px';
        video.style.borderRadius = '8px';
        video.autoplay = true;
        el.parentElement.replaceChild(video, el);
    }
}

function updateUserList(users) {
    userList.innerHTML = '';
    const count = document.getElementById('onlineCount');
    count.textContent = users ? Object.keys(users).length : 0;
    if (!users) return;
    for (const [sid, nick] of Object.entries(users)) {
        const div = document.createElement('div');
        div.className = 'user-item' + (sid === mySid ? ' self' : '');
        div.innerHTML = `<span class="dot"></span><span class="nick">${escapeHtml(nick)}${sid === mySid ? ' (我)' : ''}</span>`;
        userList.appendChild(div);
    }
}

function setUIEnabled(enabled) {
    if (enabled) {
        msgInput.disabled = false;
        sendBtn.disabled = false;
        imageLabel.classList.remove('disabled');
        videoLabel.classList.remove('disabled');
        connStatus.textContent = '● 已连接';
        connStatus.className = 'status online';
        reconnectingBar.classList.remove('active');
    } else {
        msgInput.disabled = true;
        sendBtn.disabled = true;
        imageLabel.classList.add('disabled');
        videoLabel.classList.add('disabled');
        connStatus.textContent = '● 已断开';
        connStatus.className = 'status offline';
    }
}

function saveRoomState(room, nick) {
    try {
        localStorage.setItem('chatroom_room', room);
        localStorage.setItem('chatroom_nick', nick);
    } catch(e) {}
}

function loadRoomState() {
    try {
        const room = localStorage.getItem('chatroom_room');
        const nick = localStorage.getItem('chatroom_nick');
        return { room: room || '', nick: nick || '' };
    } catch(e) {
        return { room: '', nick: '' };
    }
}

function clearRoomState() {
    try {
        localStorage.removeItem('chatroom_room');
        localStorage.removeItem('chatroom_nick');
    } catch(e) {}
}

document.getElementById('joinBtn').addEventListener('click', function() {
    const room = document.getElementById('roomInput').value.trim();
    const code = document.getElementById('codeInput').value.trim();
    const nick = document.getElementById('nickInput').value.trim();
    const errEl = document.getElementById('loginError');
    const banEl = document.getElementById('loginBan');
    errEl.textContent = '';
    banEl.textContent = '';

    if (!room || !code || !nick) {
        errEl.textContent = '请填写完整信息';
        return;
    }
    if (!/^[A-Za-z0-9]{2,20}$/.test(room)) {
        errEl.textContent = '房间号: 2-20位字母数字';
        return;
    }
    if (!/^[A-Za-z0-9]{4,12}$/.test(code)) {
        errEl.textContent = '邀请码: 4-12位字母数字';
        return;
    }
    if (nick.length < 2 || nick.length > 30) {
        errEl.textContent = '昵称: 2-30个字符';
        return;
    }

    this.disabled = true;
    this.textContent = '连接中...';

    fetch('/api/join', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ room_id: room, invite_code: code, nickname: nick })
    })
    .then(res => res.json())
    .then(data => {
        this.disabled = false;
        this.textContent = '加入房间';
        if (data.code === 0) {
            currentRoom = room;
            currentNick = nick;
            saveRoomState(room, nick);
            document.getElementById('loginOverlay').classList.add('hidden');
            document.getElementById('chatContainer').classList.remove('hidden');
            document.getElementById('roomTitle').textContent = room;
            document.getElementById('roomCodeDisplay').textContent = '🔑 已验证';
            initSocket(room, nick);
        } else if (data.code === 403) {
            if (data.ban_until) {
                const remain = Math.ceil((data.ban_until - Date.now()) / 60000);
                banEl.textContent = '⛔ 尝试次数过多，IP被封禁 ' + remain + ' 分钟';
            } else {
                errEl.textContent = data.msg || '加入失败';
            }
        } else {
            errEl.textContent = data.msg || '加入失败';
        }
    })
    .catch(err => {
        this.disabled = false;
        this.textContent = '加入房间';
        errEl.textContent = '网络错误，请重试';
    });
});

document.getElementById('roomInput').addEventListener('keydown', e => { if (e.key === 'Enter') document.getElementById('joinBtn').click(); });
document.getElementById('codeInput').addEventListener('keydown', e => { if (e.key === 'Enter') document.getElementById('joinBtn').click(); });
document.getElementById('nickInput').addEventListener('keydown', e => { if (e.key === 'Enter') document.getElementById('joinBtn').click(); });

document.getElementById('sendBtn').addEventListener('click', sendMessage);
document.getElementById('msgInput').addEventListener('keydown', function(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
    }
});

document.getElementById('imageInput').addEventListener('change', function() { uploadFile(this, 'image'); });
document.getElementById('videoInput').addEventListener('change', function() { uploadFile(this, 'video'); });

function sendMessage() {
    const input = document.getElementById('msgInput');
    const text = input.value.trim();
    if (!text) return;
    if (!connected || !socket) {
        addErrorMessage('未连接到服务器，请等待重连或刷新页面');
        return;
    }
    if (text.length > 2000) {
        addErrorMessage('消息不能超过2000字');
        return;
    }
    socket.emit('send_message', { text: text }, function(response) {
        if (response && response.status === 'error') {
            addErrorMessage(response.msg || '发送失败，请重试');
        }
    });
    input.value = '';
    input.style.height = 'auto';
}

function uploadFile(input, type) {
    if (!input.files || !input.files[0]) return;
    if (!connected || !socket) {
        addErrorMessage('未连接到服务器，请等待重连或刷新页面');
        input.value = '';
        return;
    }
    if (fileUploading) { addErrorMessage('正在上传，请稍后'); return; }
    const file = input.files[0];
    const maxSize = type === 'image' ? 10 * 1024 * 1024 : 50 * 1024 * 1024;
    if (file.size > maxSize) {
        addErrorMessage('文件过大，' + (type==='image'?'图片':'视频') + '最大 ' + maxSize/1024/1024 + 'MB');
        input.value = '';
        return;
    }
    const formData = new FormData();
    formData.append('file', file);
    formData.append('room_id', currentRoom);
    formData.append('nickname', currentNick);
    formData.append('msg_type', type);

    fileUploading = true;
    sendBtn.disabled = true;
    sendBtn.textContent = '上传中...';

    fetch('/api/upload', {
        method: 'POST',
        body: formData
    })
    .then(res => res.json())
    .then(data => {
        if (data.code === 0) {
            socket.emit('file_message', {
                file_url: data.file_url,
                msg_type: data.msg_type || type,
                file_size: data.file_size
            }, function(response) {
                if (response && response.status === 'error') {
                    addErrorMessage(response.msg || '文件消息广播失败');
                }
            });
        } else {
            addErrorMessage(data.msg || '上传失败');
        }
    })
    .catch(err => { addErrorMessage('上传失败: ' + err.message); })
    .finally(() => {
        fileUploading = false;
        sendBtn.disabled = false;
        sendBtn.textContent = '发送';
        input.value = '';
    });
}

function initSocket(room, nick) {
    connected = false;
    setUIEnabled(false);
    
    if (socket) {
        socket.disconnect();
        socket = null;
    }
    
    socket = io({
        reconnection: true,
        reconnectionAttempts: 10,
        reconnectionDelay: 1000,
        reconnectionDelayMax: 5000
    });

    socket.on('connect', function() {
        connected = true;
        setUIEnabled(true);
        reconnectAttempts = 0;
        isReconnecting = false;
        socket.emit('join', { room_id: room, nickname: nick });
    });

    socket.on('history', function(data) {
        if (data.messages) {
            for (const msg of data.messages) {
                addMessage(msg);
            }
        }
        if (data.users) {
            updateUserList(data.users);
        }
        if (data.my_sid) {
            mySid = data.my_sid;
        }
    });

    socket.on('user_list', function(data) {
        updateUserList(data.users);
    });

    socket.on('new_message', function(data) {
        addMessage(data);
    });

    socket.on('system_message', function(data) {
        addSystemMessage(data.text);
    });

    socket.on('send_message_response', function(response) {
        if (response.status === 'error') {
            addErrorMessage(response.msg);
        }
    });

    socket.on('file_message_response', function(response) {
        if (response.status === 'error') {
            addErrorMessage(response.msg);
        }
    });

    socket.on('kicked', function(data) {
        addSystemMessage(data.msg || '房间已关闭');
        clearRoomState();
        if (socket) socket.disconnect();
        setTimeout(function() {
            location.reload();
        }, 2000);
    });

    socket.on('disconnect', function() {
        connected = false;
        setUIEnabled(false);
    });

    socket.on('connect_error', function(err) {
        addErrorMessage('连接失败: ' + err.message);
    });

    socket.on('reconnect_attempt', function(attempt) {
        reconnectAttempts = attempt;
        isReconnecting = true;
        reconnectingBar.classList.add('active');
        reconnectingBar.textContent = '⏳ 正在重连... (' + attempt + '/' + maxReconnectAttempts + ')';
    });

    socket.on('reconnect_failed', function() {
        reconnectingBar.textContent = '❌ 重连失败，请刷新页面重新加入';
        addErrorMessage('重连失败，请刷新页面重新加入');
    });

    socket.on('reconnect', function() {
        connected = true;
        setUIEnabled(true);
        isReconnecting = false;
        reconnectingBar.classList.remove('active');
        addSystemMessage('重连成功');
        socket.emit('join', { room_id: room, nickname: nick });
    });
}

window.addEventListener('beforeunload', function() {
    if (socket) {
        socket.disconnect();
    }
});

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
        const saved = loadRoomState();
        if (saved.room && saved.nick) {
            document.getElementById('roomInput').value = saved.room;
            document.getElementById('nickInput').value = saved.nick;
        }
    });
} else {
    const saved = loadRoomState();
    if (saved.room && saved.nick) {
        document.getElementById('roomInput').value = saved.room;
        document.getElementById('nickInput').value = saved.nick;
    }
}
</script>
</body>
</html>
'''

ADMIN_HTML = '''
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>管理后台</title>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a0f; color: #e0e0e0; min-height:100vh; padding:30px 20px; }
        .container { max-width:1100px; margin:0 auto; }
        .header { display:flex; justify-content:space-between; align-items:center; margin-bottom:30px; flex-wrap:wrap; gap:12px; }
        .header h1 { font-size:24px; font-weight:700; background:linear-gradient(135deg,#60a5fa,#a78bfa); -webkit-background-clip:text; -webkit-text-fill-color:transparent; }
        .header .logout-btn { padding:8px 20px; border-radius:8px; border:1px solid rgba(255,255,255,0.08); background:rgba(255,255,255,0.04); color:rgba(255,255,255,0.5); cursor:pointer; font-size:13px; transition:0.2s; }
        .header .logout-btn:hover { background:rgba(255,255,255,0.08); color:#fff; }
        .card { background:rgba(20,20,30,0.8); border-radius:14px; padding:24px 28px; margin-bottom:20px; border:1px solid rgba(255,255,255,0.05); backdrop-filter:blur(10px); }
        .card h3 { font-size:15px; font-weight:600; margin-bottom:16px; color:rgba(255,255,255,0.6); }
        .card .row { display:flex; gap:12px; flex-wrap:wrap; align-items:center; margin-bottom:10px; }
        .card .row label { font-size:13px; color:rgba(255,255,255,0.4); min-width:70px; }
        .card input[type="text"], .card input[type="password"], .card input[type="number"] { padding:8px 14px; border-radius:8px; border:1px solid rgba(255,255,255,0.06); background:rgba(255,255,255,0.04); color:#e0e0e0; font-size:14px; outline:none; transition:0.2s; flex:1; min-width:120px; }
        .card input:focus { border-color:rgba(96,165,250,0.3); background:rgba(255,255,255,0.06); }
        .card input::placeholder { color:rgba(255,255,255,0.15); }
        .card .btn { padding:8px 20px; border-radius:8px; border:none; background:linear-gradient(135deg,#60a5fa,#3b82f6); color:#fff; font-weight:600; font-size:13px; cursor:pointer; transition:0.2s; }
        .card .btn:hover { transform:scale(1.02); box-shadow:0 4px 16px rgba(96,165,250,0.2); }
        .card .btn.danger { background:linear-gradient(135deg,#f87171,#ef4444); }
        .card .btn.danger:hover { box-shadow:0 4px 16px rgba(248,113,113,0.2); }
        .card .btn.secondary { background:rgba(255,255,255,0.06); color:rgba(255,255,255,0.5); }
        .card .btn.secondary:hover { background:rgba(255,255,255,0.12); }
        .card .btn:disabled { opacity:0.4; cursor:not-allowed; transform:none; }
        .card .error { color:#f87171; font-size:13px; margin-top:8px; }
        .card .success { color:#4ade80; font-size:13px; margin-top:8px; }
        .card .ban-info { color:#fbbf24; font-size:13px; margin-top:8px; }
        table { width:100%; border-collapse:collapse; font-size:14px; }
        thead { color:rgba(255,255,255,0.3); font-size:12px; text-transform:uppercase; letter-spacing:0.5px; }
        td, th { padding:10px 8px; text-align:left; border-bottom:1px solid rgba(255,255,255,0.04); }
        tr:hover td { background:rgba(255,255,255,0.02); }
        .badge { display:inline-block; padding:2px 10px; border-radius:20px; font-size:12px; background:rgba(74,222,128,0.15); color:#4ade80; }
        .badge.warning { background:rgba(251,191,36,0.15); color:#fbbf24; }
        .room-code { font-family:monospace; color:rgba(255,255,255,0.6); }
        .help-content { font-size:14px; line-height:1.8; color:rgba(255,255,255,0.75); }
        .help-content h4 { font-size:14px; font-weight:600; color:#fff; margin-top:16px; margin-bottom:6px; }
        .help-content ul { padding-left:20px; margin-bottom:10px; }
        .help-content li { margin-bottom:4px; }
        .help-content .warning-box { background:rgba(251,191,36,0.06); border-left:3px solid #fbbf24; padding:12px 16px; border-radius:6px; margin:12px 0; }
        .help-content .danger-box { background:rgba(248,113,113,0.06); border-left:3px solid #f87171; padding:12px 16px; border-radius:6px; margin:12px 0; }
        .help-content code { background:rgba(255,255,255,0.06); padding:1px 8px; border-radius:4px; font-size:12px; color:rgba(255,255,255,0.5); }
        .help-content .disclaimer { background:rgba(255,255,255,0.02); padding:16px 20px; border-radius:8px; margin-top:16px; border:1px solid rgba(255,255,255,0.04); }
        .help-content .disclaimer strong { color:rgba(255,255,255,0.4); }
        .help-content .disclaimer p { margin-bottom:4px; font-size:13px; color:rgba(255,255,255,0.5); }
        .help-content .agree-box { background:rgba(96,165,250,0.06); border:1px solid rgba(96,165,250,0.1); padding:12px 16px; border-radius:8px; margin-top:16px; text-align:center; font-weight:600; color:rgba(255,255,255,0.6); }
        .tab-bar { display:flex; gap:8px; margin-bottom:20px; flex-wrap:wrap; }
        .tab-bar .tab { padding:8px 20px; border-radius:8px; background:rgba(255,255,255,0.04); color:rgba(255,255,255,0.4); cursor:pointer; font-size:13px; transition:0.2s; border:1px solid rgba(255,255,255,0.04); }
        .tab-bar .tab:hover { background:rgba(255,255,255,0.08); color:rgba(255,255,255,0.7); }
        .tab-bar .tab.active { background:rgba(96,165,250,0.12); color:#60a5fa; border-color:rgba(96,165,250,0.15); }
        .tab-content { display:none; }
        .tab-content.active { display:block; }
        .settings-row { display:flex; gap:12px; align-items:center; flex-wrap:wrap; margin-bottom:8px; }
        @media (max-width:600px) { .card { padding:16px; } td,th { font-size:12px; padding:6px 4px; } .header h1 { font-size:18px; } }
        .inline-flex { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>⚙️ 管理后台</h1>
        <div class="inline-flex">
            <span style="font-size:12px;color:rgba(255,255,255,0.2);" id="sessionTime"></span>
            <button class="logout-btn" onclick="logout()">退出登录</button>
        </div>
    </div>

    <div id="loginBox" class="card">
        <h3>🔐 管理员登录</h3>
        <div class="row">
            <label>密码</label>
            <input type="password" id="adminPwd" placeholder="请输入管理员密码" onkeydown="if(event.key==='Enter') adminLogin()">
            <button class="btn" onclick="adminLogin()">登录</button>
        </div>
        <div id="adminLoginError" class="error"></div>
        <div id="adminLoginBan" class="ban-info"></div>
    </div>

    <div id="adminContent" style="display:none;">
        <div class="tab-bar">
            <div class="tab active" onclick="switchTab('dashboard')">📊 房间管理</div>
            <div class="tab" onclick="switchTab('create')">➕ 创建房间</div>
            <div class="tab" onclick="switchTab('settings')">⚙️ 全局设置</div>
            <div class="tab" onclick="switchTab('password')">🔑 修改密码</div>
            <div class="tab" onclick="switchTab('help')">📖 使用说明</div>
        </div>

        <div id="tabDashboard" class="tab-content active">
            <div class="card">
                <h3>📊 所有房间</h3>
                <div id="roomList"><p style="color:rgba(255,255,255,0.2);font-size:13px;">加载中...</p></div>
            </div>
        </div>

        <div id="tabCreate" class="tab-content">
            <div class="card">
                <h3>➕ 创建新房间</h3>
                <div class="row"><label>房间号</label><input type="text" id="newRoomId" placeholder="2-20位字母数字" maxlength="20"></div>
                <div class="row"><label>邀请码</label><input type="text" id="newInviteCode" placeholder="4-12位字母数字" maxlength="12"></div>
                <div class="row"><label>最大人数</label><input type="number" id="newMaxUsers" placeholder="默认100，最高500" min="1" max="500"></div>
                <button class="btn" onclick="createRoom()">创建房间</button>
                <div id="createResult" class="success"></div>
                <div id="createError" class="error"></div>
            </div>
        </div>

        <div id="tabSettings" class="tab-content">
            <div class="card">
                <h3>⚙️ 全局设置</h3>
                <div class="settings-row"><label style="min-width:140px;font-size:13px;color:rgba(255,255,255,0.4);">默认最大人数</label><input type="number" id="defaultMaxUsers" min="1" max="500" style="flex:0 1 120px;"><span style="font-size:12px;color:rgba(255,255,255,0.2);">最高500</span><button class="btn secondary" onclick="saveDefaultMax()">保存</button></div>
                <div class="settings-row"><label style="min-width:140px;font-size:13px;color:rgba(255,255,255,0.4);">历史消息加载条数</label><input type="number" id="msgLoadLimit" min="10" max="1000" style="flex:0 1 120px;"><span style="font-size:12px;color:rgba(255,255,255,0.2);">新用户进入加载最近N条</span><button class="btn secondary" onclick="saveMsgLimit()">保存</button></div>
                <div id="settingsResult" class="success"></div>
                <div id="settingsError" class="error"></div>
            </div>
        </div>

        <div id="tabPassword" class="tab-content">
            <div class="card">
                <h3>🔑 修改管理员密码</h3>
                <div class="row"><label>旧密码</label><input type="password" id="oldPwd" placeholder="请输入旧密码"></div>
                <div class="row"><label>新密码</label><input type="password" id="newPwd" placeholder="请输入新密码" maxlength="32"></div>
                <div class="row"><label>确认密码</label><input type="password" id="confirmPwd" placeholder="请再次输入新密码"></div>
                <button class="btn" onclick="changePwd()">修改密码</button>
                <div id="pwdResult" class="success"></div>
                <div id="pwdError" class="error"></div>
            </div>
        </div>

        <div id="tabHelp" class="tab-content">
            <div class="card">
                <h3>📖 使用说明</h3>
                <div class="help-content">
                    <h4>关于本软件</h4>
                    <p>出品方：风景云创科技 (ScenCloud)</p>
                    <p>官网：https://www.scencloud.com</p>
                    <p>联系邮箱：chatroom@scencloud.com</p>
                    <p>版本：v1.0.0</p>
                    <p style="margin-top:6px;color:rgba(255,255,255,0.4);">本软件是一款内网匿名聊天室系统，支持多房间隔离、图片视频上传、实时通信等功能。</p>

                    <h4>快速上手</h4>
                    <ul>
                        <li>第一次启动软件，控制台会给一个16位初始密码，复制保存好</li>
                        <li>浏览器访问 http://127.0.0.1:3986/yesadmin 进入后台</li>
                        <li>用初始密码登录，第一时间修改密码</li>
                        <li>创建房间，把房间号和邀请码告诉要进来的人</li>
                        <li>用户访问 http://127.0.0.1:3986 输入信息就能进房间聊天</li>
                    </ul>

                    <h4>创建房间</h4>
                    <ul>
                        <li>房间号：2-20位，只能用字母和数字</li>
                        <li>邀请码：4-12位，只能用字母和数字，用户进房间必须输</li>
                        <li>人数上限：默认100，最高500，自己根据服务器性能掂量</li>
                        <li>不同房间数据完全隔离，互相看不到</li>
                    </ul>

                    <h4>房间管理</h4>
                    <ul>
                        <li>列表显示：房间号、邀请码、在线人数、总消息数、创建时间</li>
                        <li>删除房间：聊天记录全清 + 上传文件全删 + 在线用户全踢</li>
                        <li class="danger-box" style="list-style:none;padding:8px 12px;margin-top:6px;">删前想清楚，没有后悔药，删完所有数据找不回来</li>
                    </ul>

                    <h4>全局设置</h4>
                    <ul>
                        <li>默认人数上限：新建房间默认用这个值，最高500</li>
                        <li>历史消息加载条数：默认200条，新用户进房间加载最近N条</li>
                        <li>改了之后，已经在房间里的人不受影响，重新进才生效</li>
                        <li>不会因为改设置把所有人踢出去</li>
                    </ul>

                    <h4>忘记密码</h4>
                    <div class="warning-box">
                        删掉 data/chatroom.db 文件，重启程序会生成新密码<br>
                        ⚠️ 注意：所有房间数据（房间配置、聊天记录）会全部丢失
                    </div>

                    <h4>其他提醒</h4>
                    <ul>
                        <li>聊天记录存SQLite，重启不丢</li>
                        <li>上传文件存 uploads/房间号/，程序退出自动清空</li>
                        <li>同一个IP输错6次房间号/邀请码，封10分钟</li>
                        <li>后台登录输错6次密码，也封10分钟</li>
                        <li>每人每秒最多发3条消息，防刷屏</li>
                        <li>上传文件格式：图片(jpg/png/gif/webp) 视频(mp4/webm/mov)</li>
                        <li>图片小于等于3MB自动加载，大于3MB点击加载，视频手动点击播放</li>
                        <li>端口默认3986，被占用需改代码重新打包</li>
                    </ul>

                    <h4>免责声明</h4>
                    <div class="disclaimer">
                        <p>1. 软件仅供内部交流，使用者的一切言行及上传内容，由使用者自行承担全部法律责任</p>
                        <p>2. 严禁色情、暴力、赌博、诈骗、诽谤、侵犯他人隐私等违法行为</p>
                        <p>3. 软件按现状提供，开发方不对稳定性、安全性作任何担保</p>
                        <p>4. 本软件建议部署于内网，如自行暴露于公网，后果自负</p>
                        <p>5. 匿名不是护身符，网络非法外之地</p>
                        <p>6. 未经授权禁止逆向工程、反编译</p>
                        <p>7. 开发方保留以上条款的最终解释权和修改权</p>
                    </div>

                    <div class="agree-box">⚠️ 使用本软件即表示您已阅读并同意以上全部条款</div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
let adminLoggedIn = false;

function switchTab(name) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
    document.getElementById('tab' + name.charAt(0).toUpperCase() + name.slice(1)).classList.add('active');
    document.querySelector(`.tab[onclick="switchTab('${name}')"]`).classList.add('active');
    if (name === 'dashboard') loadRooms();
}

function adminLogin() {
    const pwd = document.getElementById('adminPwd').value;
    const errEl = document.getElementById('adminLoginError');
    const banEl = document.getElementById('adminLoginBan');
    errEl.textContent = '';
    banEl.textContent = '';
    if (!pwd) { errEl.textContent = '请输入密码'; return; }
    fetch('/api/admin/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: pwd })
    })
    .then(res => res.json())
    .then(data => {
        if (data.code === 0) {
            adminLoggedIn = true;
            document.getElementById('loginBox').style.display = 'none';
            document.getElementById('adminContent').style.display = 'block';
            loadRooms();
            loadSettings();
            setInterval(() => {
                const now = new Date();
                document.getElementById('sessionTime').textContent = '会话有效 ' + now.toLocaleTimeString();
            }, 30000);
        } else if (data.code === 403) {
            if (data.ban_until) {
                const remain = Math.ceil((data.ban_until - Date.now()) / 60000);
                banEl.textContent = '⛔ 尝试次数过多，IP被封禁 ' + remain + ' 分钟';
            } else {
                errEl.textContent = data.msg || '登录失败';
            }
        } else {
            errEl.textContent = data.msg || '登录失败';
        }
    })
    .catch(err => { errEl.textContent = '网络错误'; });
}

function logout() {
    fetch('/api/admin/logout', { method: 'POST' })
    .then(() => { location.reload(); });
}

function loadRooms() {
    fetch('/api/admin/rooms')
    .then(res => res.json())
    .then(data => {
        const container = document.getElementById('roomList');
        if (data.code !== 0 || !data.rooms || data.rooms.length === 0) {
            container.innerHTML = '<p style="color:rgba(255,255,255,0.2);font-size:13px;">暂无房间</p>';
            return;
        }
        let html = `<table><thead><tr><th>房间号</th><th>邀请码</th><th>在线</th><th>消息数</th><th>创建时间</th><th>操作</th></tr></thead><tbody>`;
        for (const r of data.rooms) {
            html += `<tr>
                <td><strong>${escapeHtml(r.room_id)}</strong></td>
                <td class="room-code">${escapeHtml(r.invite_code)}</td>
                <td><span class="badge">${r.online_count || 0} 人</span></td>
                <td>${r.msg_count || 0}</td>
                <td style="font-size:12px;color:rgba(255,255,255,0.3);">${r.created_at || '-'}</td>
                <td><button class="btn danger" style="padding:4px 12px;font-size:12px;" onclick="deleteRoom('${escapeHtml(r.room_id)}')">删除</button></td>
            </tr>`;
        }
        html += '</tbody></table>';
        container.innerHTML = html;
    })
    .catch(() => { document.getElementById('roomList').innerHTML = '<p style="color:rgba(255,255,255,0.2);font-size:13px;">加载失败</p>'; });
}

function deleteRoom(roomId) {
    if (!confirm('确定删除房间 ' + roomId + ' 吗？\\n所有聊天记录和上传文件将被永久删除！')) return;
    fetch('/api/admin/room/' + encodeURIComponent(roomId), { method: 'DELETE' })
    .then(res => res.json())
    .then(data => {
        if (data.code === 0) { loadRooms(); }
        else { alert(data.msg || '删除失败'); }
    })
    .catch(err => { alert('删除失败'); });
}

function createRoom() {
    const roomId = document.getElementById('newRoomId').value.trim();
    const code = document.getElementById('newInviteCode').value.trim();
    const maxUsers = parseInt(document.getElementById('newMaxUsers').value) || 100;
    const errEl = document.getElementById('createError');
    const resEl = document.getElementById('createResult');
    errEl.textContent = '';
    resEl.textContent = '';
    if (!roomId || !code) { errEl.textContent = '请填写完整'; return; }
    if (!/^[A-Za-z0-9]{2,20}$/.test(roomId)) { errEl.textContent = '房间号: 2-20位字母数字'; return; }
    if (!/^[A-Za-z0-9]{4,12}$/.test(code)) { errEl.textContent = '邀请码: 4-12位字母数字'; return; }
    if (maxUsers < 1 || maxUsers > 500) { errEl.textContent = '人数范围 1-500'; return; }
    fetch('/api/admin/room', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ room_id: roomId, invite_code: code, max_users: maxUsers })
    })
    .then(res => res.json())
    .then(data => {
        if (data.code === 0) {
            resEl.textContent = '✅ 创建成功！';
            document.getElementById('newRoomId').value = '';
            document.getElementById('newInviteCode').value = '';
            document.getElementById('newMaxUsers').value = '';
            loadRooms();
        } else {
            errEl.textContent = data.msg || '创建失败';
        }
    })
    .catch(err => { errEl.textContent = '网络错误'; });
}

function loadSettings() {
    fetch('/api/admin/settings')
    .then(res => res.json())
    .then(data => {
        if (data.code === 0) {
            document.getElementById('defaultMaxUsers').value = data.default_max_users || 100;
            document.getElementById('msgLoadLimit').value = data.msg_load_limit || 200;
        }
    });
}

function saveDefaultMax() {
    const val = parseInt(document.getElementById('defaultMaxUsers').value) || 100;
    if (val < 1 || val > 500) { alert('请输入1-500之间的数字'); return; }
    fetch('/api/admin/settings/default_max_users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ value: val })
    })
    .then(res => res.json())
    .then(data => {
        if (data.code === 0) {
            document.getElementById('settingsResult').textContent = '✅ 保存成功';
            setTimeout(() => document.getElementById('settingsResult').textContent = '', 3000);
        } else {
            document.getElementById('settingsError').textContent = data.msg || '保存失败';
        }
    });
}

function saveMsgLimit() {
    const val = parseInt(document.getElementById('msgLoadLimit').value) || 200;
    if (val < 10 || val > 1000) { alert('请输入10-1000之间的数字'); return; }
    fetch('/api/admin/settings/msg_load_limit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ value: val })
    })
    .then(res => res.json())
    .then(data => {
        if (data.code === 0) {
            document.getElementById('settingsResult').textContent = '✅ 保存成功';
            setTimeout(() => document.getElementById('settingsResult').textContent = '', 3000);
        } else {
            document.getElementById('settingsError').textContent = data.msg || '保存失败';
        }
    });
}

function changePwd() {
    const oldPwd = document.getElementById('oldPwd').value;
    const newPwd = document.getElementById('newPwd').value;
    const confirmPwd = document.getElementById('confirmPwd').value;
    const resEl = document.getElementById('pwdResult');
    const errEl = document.getElementById('pwdError');
    resEl.textContent = '';
    errEl.textContent = '';
    if (!oldPwd || !newPwd || !confirmPwd) { errEl.textContent = '请填写完整'; return; }
    if (newPwd.length < 6) { errEl.textContent = '新密码至少6位'; return; }
    if (newPwd !== confirmPwd) { errEl.textContent = '两次密码不一致'; return; }
    fetch('/api/admin/password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ old_password: oldPwd, new_password: newPwd })
    })
    .then(res => res.json())
    .then(data => {
        if (data.code === 0) {
            resEl.textContent = '✅ 密码修改成功！';
            document.getElementById('oldPwd').value = '';
            document.getElementById('newPwd').value = '';
            document.getElementById('confirmPwd').value = '';
            setTimeout(() => resEl.textContent = '', 3000);
        } else {
            errEl.textContent = data.msg || '修改失败';
        }
    });
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

document.getElementById('adminPwd').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') adminLogin();
});
</script>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(USER_HTML)

@app.route('/yesadmin')
def admin():
    return render_template_string(ADMIN_HTML)

@app.route('/api/join', methods=['POST'])
def api_join():
    data = request.json
    room_id = data.get('room_id', '').strip()
    invite_code = data.get('invite_code', '').strip()
    nickname = data.get('nickname', '').strip()
    ip = get_ip()

    if not room_id or not invite_code or not nickname:
        return jsonify({'code': 1, 'msg': '请填写完整信息'})
    if not re.match(r'^[A-Za-z0-9]{2,20}$', room_id):
        return jsonify({'code': 1, 'msg': '房间号格式错误'})
    if not re.match(r'^[A-Za-z0-9]{4,12}$', invite_code):
        return jsonify({'code': 1, 'msg': '邀请码格式错误'})
    if len(nickname) < 2 or len(nickname) > 30:
        return jsonify({'code': 1, 'msg': '昵称长度2-30字符'})

    if check_ip_ban(ip, room_id):
        ban_data = ip_error_count.get(f'{ip}:{room_id}', {})
        return jsonify({'code': 403, 'msg': 'IP被封禁', 'ban_until': ban_data.get('ban_until')})

    with db_lock:
        conn = get_db()
        cur = conn.execute('SELECT invite_code, max_users FROM rooms WHERE room_id = ?', (room_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({'code': 1, 'msg': '房间不存在'})
        if row[0] != invite_code:
            record_ip_error(ip, room_id)
            return jsonify({'code': 1, 'msg': '邀请码错误'})
        max_users = row[1] or int(get_setting('default_max_users', '100'))
        clear_ip_record(ip, room_id)

    with online_lock:
        if room_id in online_users:
            for existing_nick in online_users[room_id].values():
                if existing_nick == nickname:
                    return jsonify({'code': 1, 'msg': '昵称已被占用，请换一个'})

    return jsonify({'code': 0, 'msg': '成功'})

@app.route('/api/upload', methods=['POST'])
def api_upload():
    try:
        if request.content_length and request.content_length > 60 * 1024 * 1024:
            return jsonify({'code': 1, 'msg': '文件超过最大限制60MB'})
        if 'file' not in request.files:
            return jsonify({'code': 1, 'msg': '未上传文件'})
        file = request.files['file']
        room_id = request.form.get('room_id', '').strip()
        if not file or not room_id:
            return jsonify({'code': 1, 'msg': '参数错误'})
        with db_lock:
            conn = get_db()
            cur = conn.execute('SELECT room_id FROM rooms WHERE room_id = ?', (room_id,))
            if not cur.fetchone():
                return jsonify({'code': 1, 'msg': '房间不存在'})
        file_data = file.read()
        if len(file_data) == 0:
            return jsonify({'code': 1, 'msg': '空文件'})
        file_type, ext = validate_file_type(file_data, file.filename)
        if not file_type:
            return jsonify({'code': 1, 'msg': '不支持的文件格式'})
        if file_type == 'image' and len(file_data) > 10 * 1024 * 1024:
            return jsonify({'code': 1, 'msg': '图片最大10MB'})
        if file_type == 'video' and len(file_data) > 50 * 1024 * 1024:
            return jsonify({'code': 1, 'msg': '视频最大50MB'})
        room_upload_dir = os.path.join(UPLOAD_DIR, room_id)
        os.makedirs(room_upload_dir, exist_ok=True)
        filename = f"{uuid.uuid4().hex}.{ext}"
        filepath = os.path.join(room_upload_dir, filename)
        with open(filepath, 'wb') as f:
            f.write(file_data)
        return jsonify({
            'code': 0,
            'file_url': f'/uploads/{room_id}/{filename}',
            'file_size': len(file_data),
            'msg_type': file_type
        })
    except Exception as e:
        return jsonify({'code': 1, 'msg': f'上传异常: {str(e)}'})

@app.route('/uploads/<room_id>/<filename>')
def uploaded_file(room_id, filename):
    try:
        safe_room = secure_filename(room_id)
        safe_file = secure_filename(filename)
        filepath = os.path.join(UPLOAD_DIR, safe_room, safe_file)
        if not os.path.exists(filepath):
            abort(404)
        with db_lock:
            conn = get_db()
            cur = conn.execute('SELECT room_id FROM rooms WHERE room_id = ?', (room_id,))
            if not cur.fetchone():
                abort(404)
        return send_file(filepath)
    except Exception as e:
        abort(404)

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    password = request.json.get('password', '')
    ip = get_ip()
    if check_ip_ban(ip):
        ban_data = admin_ip_error_count.get(f'admin:{ip}', {})
        return jsonify({'code': 403, 'msg': 'IP被封禁', 'ban_until': ban_data.get('ban_until')})
    with db_lock:
        conn = get_db()
        cur = conn.execute('SELECT password_hash FROM admin WHERE id = 1')
        row = cur.fetchone()
        if not row or not check_password_hash(row[0], password):
            record_ip_error(ip)
            return jsonify({'code': 1, 'msg': '密码错误'})
        clear_ip_record(ip)
    session['admin_logged_in'] = True
    session['admin_login_time'] = time.time()
    session.permanent = True
    return jsonify({'code': 0, 'msg': '登录成功'})

@app.route('/api/admin/logout', methods=['POST'])
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_login_time', None)
    return jsonify({'code': 0})

@app.route('/api/admin/rooms')
def admin_rooms():
    if not is_admin_logged_in():
        return jsonify({'code': 1, 'msg': '未登录'})
    with db_lock:
        conn = get_db()
        rooms = conn.execute('SELECT room_id, invite_code, max_users, created_at FROM rooms ORDER BY created_at DESC').fetchall()
        result = []
        for r in rooms:
            msg_count = conn.execute('SELECT COUNT(*) FROM messages WHERE room_id = ?', (r[0],)).fetchone()[0]
            with online_lock:
                online = len(online_users.get(r[0], {}))
            result.append({
                'room_id': r[0],
                'invite_code': r[1],
                'max_users': r[2],
                'created_at': r[3],
                'msg_count': msg_count,
                'online_count': online
            })
    return jsonify({'code': 0, 'rooms': result})

@app.route('/api/admin/room', methods=['POST'])
def admin_create_room():
    if not is_admin_logged_in():
        return jsonify({'code': 1, 'msg': '未登录'})
    data = request.json
    room_id = data.get('room_id', '').strip()
    invite_code = data.get('invite_code', '').strip()
    max_users = data.get('max_users', 100)
    if not re.match(r'^[A-Za-z0-9]{2,20}$', room_id):
        return jsonify({'code': 1, 'msg': '房间号格式错误'})
    if not re.match(r'^[A-Za-z0-9]{4,12}$', invite_code):
        return jsonify({'code': 1, 'msg': '邀请码格式错误'})
    if max_users < 1 or max_users > 500:
        return jsonify({'code': 1, 'msg': '人数范围1-500'})
    with db_lock:
        conn = get_db()
        cur = conn.execute('SELECT room_id FROM rooms WHERE room_id = ?', (room_id,))
        if cur.fetchone():
            return jsonify({'code': 1, 'msg': '房间号已存在'})
        conn.execute('INSERT INTO rooms (room_id, invite_code, max_users) VALUES (?, ?, ?)',
                     (room_id, invite_code, max_users))
    return jsonify({'code': 0, 'msg': '创建成功'})

@app.route('/api/admin/room/<room_id>', methods=['DELETE'])
def admin_delete_room(room_id):
    if not is_admin_logged_in():
        return jsonify({'code': 1, 'msg': '未登录'})
    with online_lock:
        if room_id in online_users:
            for sid in list(online_users[room_id].keys()):
                socketio.emit('kicked', {'msg': '房间已关闭'}, room=sid, to=sid)
                socketio.server.disconnect(sid)
                if sid in user_last_active:
                    del user_last_active[sid]
            del online_users[room_id]
    with db_lock:
        conn = get_db()
        conn.execute('DELETE FROM rooms WHERE room_id = ?', (room_id,))
        conn.execute('DELETE FROM messages WHERE room_id = ?', (room_id,))
    clean_room_uploads(room_id)
    if room_id in room_max_users_cache:
        del room_max_users_cache[room_id]
    return jsonify({'code': 0, 'msg': '删除成功'})

@app.route('/api/admin/settings')
def admin_get_settings():
    if not is_admin_logged_in():
        return jsonify({'code': 1, 'msg': '未登录'})
    return jsonify({
        'code': 0,
        'default_max_users': int(get_setting('default_max_users', '100')),
        'msg_load_limit': int(get_setting('msg_load_limit', '200'))
    })

@app.route('/api/admin/settings/default_max_users', methods=['POST'])
def admin_set_default_max_users():
    if not is_admin_logged_in():
        return jsonify({'code': 1, 'msg': '未登录'})
    val = request.json.get('value', 100)
    if val < 1 or val > 500:
        return jsonify({'code': 1, 'msg': '范围1-500'})
    set_setting('default_max_users', str(val))
    return jsonify({'code': 0, 'msg': '保存成功'})

@app.route('/api/admin/settings/msg_load_limit', methods=['POST'])
def admin_set_msg_load_limit():
    if not is_admin_logged_in():
        return jsonify({'code': 1, 'msg': '未登录'})
    val = request.json.get('value', 200)
    if val < 10 or val > 1000:
        return jsonify({'code': 1, 'msg': '范围10-1000'})
    set_setting('msg_load_limit', str(val))
    return jsonify({'code': 0, 'msg': '保存成功'})

@app.route('/api/admin/password', methods=['POST'])
def admin_change_password():
    if not is_admin_logged_in():
        return jsonify({'code': 1, 'msg': '未登录'})
    data = request.json
    old = data.get('old_password', '')
    new = data.get('new_password', '')
    if not old or not new or len(new) < 6:
        return jsonify({'code': 1, 'msg': '新密码至少6位'})
    with db_lock:
        conn = get_db()
        cur = conn.execute('SELECT password_hash FROM admin WHERE id = 1')
        row = cur.fetchone()
        if not row or not check_password_hash(row[0], old):
            return jsonify({'code': 1, 'msg': '旧密码错误'})
        conn.execute('UPDATE admin SET password_hash = ? WHERE id = 1', (generate_password_hash(new),))
    return jsonify({'code': 0, 'msg': '修改成功'})

@socketio.on('join')
def handle_join(data):
    room_id = data.get('room_id')
    nickname = data.get('nickname')
    if not room_id or not nickname:
        return
    sid = request.sid
    with online_lock:
        if room_id not in online_users:
            online_users[room_id] = {}
        max_users = get_room_max_users(room_id)
        if len(online_users[room_id]) >= max_users:
            emit('kicked', {'msg': f'房间已满 (最多{max_users}人)'})
            return
        for existing_sid, existing_nick in list(online_users[room_id].items()):
            if existing_nick == nickname and existing_sid != sid:
                socketio.emit('kicked', {'msg': '有同名用户加入，您被踢出'}, room=existing_sid, to=existing_sid)
                socketio.server.disconnect(existing_sid)
                del online_users[room_id][existing_sid]
                if existing_sid in user_last_active:
                    del user_last_active[existing_sid]
                break
        online_users[room_id][sid] = nickname
        user_last_active[sid] = time.time()
    join_room(room_id)
    msg_limit = get_room_msg_limit()
    with db_lock:
        conn = get_db()
        msgs = conn.execute(
            'SELECT sender_sid, nickname, msg_type, content, file_size, created_at FROM messages WHERE room_id = ? ORDER BY id DESC LIMIT ?',
            (room_id, msg_limit)
        ).fetchall()
        msgs = list(reversed(msgs))
    hist = []
    for m in msgs:
        hist.append({
            'type': 'message',
            'sid': m[0] or '',
            'nickname': m[1],
            'msg_type': m[2],
            'content': m[3],
            'file_size': m[4] or 0,
            'time': int(datetime.fromisoformat(m[5]).timestamp() * 1000)
        })
    with online_lock:
        users_copy = online_users.get(room_id, {}).copy()
    emit('history', {'messages': hist, 'users': users_copy, 'my_sid': sid})
    socketio.emit('user_list', {'users': users_copy}, room=room_id)
    socketio.emit('system_message', {'text': f'{nickname} 进入房间'}, room=room_id)

@socketio.on('send_message')
def handle_send_message(data):
    sid = request.sid
    text = data.get('text', '').strip()
    if not text:
        emit('send_message_response', {'status': 'error', 'msg': '消息不能为空'})
        return
    update_user_active(sid)
    room_id = None
    nickname = None
    with online_lock:
        for rid, users in online_users.items():
            if sid in users:
                room_id = rid
                nickname = users[sid]
                break
    if not room_id or not nickname:
        emit('send_message_response', {'status': 'error', 'msg': '您已不在线，请重新加入'})
        return
    if not check_rate_limit(sid):
        emit('send_message_response', {'status': 'error', 'msg': '发送频率过快，请稍后'})
        return
    content = text[:2000]
    with db_lock:
        conn = get_db()
        conn.execute('INSERT INTO messages (room_id, sender_sid, nickname, msg_type, content) VALUES (?, ?, ?, ?, ?)',
                     (room_id, sid, nickname, 'text', content))
    socketio.emit('new_message', {
        'type': 'message',
        'sid': sid,
        'nickname': nickname,
        'msg_type': 'text',
        'text': content,
        'time': int(time.time() * 1000)
    }, room=room_id)
    emit('send_message_response', {'status': 'ok'})

@socketio.on('file_message')
def handle_file_message(data):
    sid = request.sid
    update_user_active(sid)
    room_id = None
    nickname = None
    with online_lock:
        for rid, users in online_users.items():
            if sid in users:
                room_id = rid
                nickname = users[sid]
                break
    if not room_id or not nickname:
        emit('file_message_response', {'status': 'error', 'msg': '您已不在线'})
        return
    file_url = data.get('file_url')
    msg_type = data.get('msg_type', 'image')
    file_size = data.get('file_size', 0)
    if not file_url:
        emit('file_message_response', {'status': 'error', 'msg': '文件URL为空'})
        return
    with db_lock:
        conn = get_db()
        conn.execute('INSERT INTO messages (room_id, sender_sid, nickname, msg_type, content, file_size) VALUES (?, ?, ?, ?, ?, ?)',
                     (room_id, sid, nickname, msg_type, file_url, file_size))
    socketio.emit('new_message', {
        'type': 'message',
        'sid': sid,
        'nickname': nickname,
        'msg_type': msg_type,
        'content': file_url,
        'file_size': file_size,
        'time': int(time.time() * 1000)
    }, room=room_id)
    emit('file_message_response', {'status': 'ok'})

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    room_id = None
    nickname = None
    with online_lock:
        for rid, users in online_users.items():
            if sid in users:
                room_id = rid
                nickname = users[sid]
                break
        if room_id and nickname:
            del online_users[room_id][sid]
            if not online_users[room_id]:
                del online_users[room_id]
        if sid in user_last_active:
            del user_last_active[sid]
    if room_id and nickname:
        with online_lock:
            users_copy = online_users.get(room_id, {}).copy()
        socketio.emit('user_list', {'users': users_copy}, room=room_id)
        socketio.emit('system_message', {'text': f'{nickname} 退出房间'}, room=room_id)

@socketio.on('ping')
def handle_ping():
    sid = request.sid
    update_user_active(sid)
    emit('pong')

def print_banner(init_pwd):
    print('=' * 60)
    print('       匿名聊天室 v1.0.0 - 风景云创科技 (ScenCloud)')
    print('=' * 60)
    if init_pwd:
        print(f'\n【首次启动】管理员初始密码：{init_pwd}')
        print('请访问 http://127.0.0.1:3986/yesadmin 登录后台\n')
    print('【使用说明】')
    print('  管理员：')
    print('    1. 首次启动控制台打印初始密码，复制保存')
    print('    2. 访问 /yesadmin 登录后台，立即修改密码')
    print('    3. 创建房间，设置房间号（2-20位字母数字）、邀请码（4-12位字母数字）、最大人数')
    print('    4. 可调整全局历史消息加载条数（默认200条）')
    print('    5. 删除房间会清空所有消息和上传文件')
    print('  用户：')
    print('    1. 访问首页，输入房间号、邀请码、昵称加入')
    print('    2. 昵称2-30字，支持中文、符号、表情')
    print('    3. 图片不超过3MB自动显示，超过3MB需点击加载，视频需点击播放')
    print('    4. 关闭浏览器即退出')
    print('\n【注意事项】')
    print('  1. 建议部署于内网，暴露公网后果自负')
    print('  2. 管理员密码忘了：删除 data/chatroom.db 重启（房间数据会丢失）')
    print('  3. 端口 3986 被占用：修改代码重新打包')
    print('  4. 上传文件仅支持：图片(jpg/png/gif/webp) 视频(mp4/webm/mov)')
    print('\n【免责声明】')
    print('  1. 软件仅供内部交流，使用者言行及上传内容自行承担法律责任')
    print('  2. 严禁色情、暴力、赌博、诈骗、诽谤、侵犯他人隐私等违法行为')
    print('  3. 软件按现状提供，开发方不对稳定性、安全性作担保')
    print('  4. 匿名不是护身符，网络非法外之地')
    print('  5. 禁止逆向工程、反编译')
    print('=' * 60)
    print('⚠️  如果您开始使用本软件，则表示您已阅读并同意以上全部条款')
    print('=' * 60)
    print(f'\n服务已启动：http://0.0.0.0:3986')
    print(f'后台地址：http://0.0.0.0:3986/yesadmin')
    print('按 Ctrl+C 停止服务\n')

if __name__ == '__main__':
    init_pwd = init_db()
    print_banner(init_pwd)
    try:
        socketio.run(app, host='0.0.0.0', port=3986, debug=False, allow_unsafe_werkzeug=True)
    finally:
        pass
    print('    3. 图片不超过3MB自动显示，超过3MB需点击加载，视频需点击播放')
    print('    4. 关闭浏览器即退出')
    print('\n【注意事项】')
    print('  1. 建议部署于内网，暴露公网后果自负')
    print('  2. 管理员密码忘了：删除 data/chatroom.db 重启（房间数据会丢失）')
    print('  3. 端口 3986 被占用：修改代码重新打包')
    print('  4. 上传文件仅支持：图片(jpg/png/gif/webp) 视频(mp4/webm/mov)')
    print('\n【免责声明】')
    print('  1. 软件仅供内部交流，使用者言行及上传内容自行承担法律责任')
    print('  2. 严禁色情、暴力、赌博、诈骗、诽谤、侵犯他人隐私等违法行为')
    print('  3. 软件按现状提供，开发方不对稳定性、安全性作担保')
    print('  4. 匿名不是护身符，网络非法外之地')
    print('  5. 禁止逆向工程、反编译')
    print('=' * 60)
    print('⚠️  如果您开始使用本软件，则表示您已阅读并同意以上全部条款')
    print('=' * 60)
    print(f'\n服务已启动：http://0.0.0.0:3986')
    print(f'后台地址：http://0.0.0.0:3986/yesadmin')
    print('按 Ctrl+C 停止服务\n')

if __name__ == '__main__':
    init_pwd = init_db()
    print_banner(init_pwd)
    try:
        socketio.run(app, host='0.0.0.0', port=3986, debug=False, allow_unsafe_werkzeug=True)
    finally:
        clean_uploads()