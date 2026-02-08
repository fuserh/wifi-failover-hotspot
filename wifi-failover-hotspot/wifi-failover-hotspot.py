#!/usr/bin/env python3
"""
WiFi Failover Hotspot Service
监控WiFi连接，断连时自动启动热点
启动时如果WiFi未连接也会自动开启热点
设备连接web管理界面：包含WiFi连接和热点管理功能
"""

import subprocess
import time
import logging
import json
import dbus
import dbus.mainloop.glib
from gi.repository import GLib
import signal
import sys
import os
from datetime import datetime
import threading
from flask import Flask, redirect, render_template, request, jsonify, make_response
import hashlib
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
# 配置参数
HOTSPOT_SSID = "RaspberryPi-Hotspot"
HOTSPOT_PASSWORD = "RaspberryPi123********"
HOTSPOT_CONNECTION_NAME = "Hotspot-Failover"
INTERFACE = "wlan0"  # 无线网卡接口
CHECK_INTERVAL = 30  # 检查间隔（秒）
RETRY_THRESHOLD = 3  # 重试阈值
LOG_FILE = "/var/log/wifi-failover.log"

# Web管理界面配置
WEB_HOST = "0.0.0.0"  # 监听所有接口
WEB_PORT = 8080
WEB_DEBUG = False  # 生产环境设置为False
WEB_PASSWORD = os.environ.get('WEB_PASSWORD', '240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9')  # Web管理界面密码（admin123的SHA256哈希）
WEB_PASSWORD_SALT = os.environ.get('WEB_PASSWORD_SALT', 'change_this_salt_in_production')  # 密码盐值
TOKEN_EXPIRY = int(os.environ.get('TOKEN_EXPIRY', 3600))  # 认证令牌过期时间（秒）

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class WiFiFailoverHotspot:
    def __init__(self):
        self.hotspot_active = False
        self.wifi_connected = False
        self.retry_count = 0
        self.main_loop = None
        self.nm = None
        self.manual_mode = None  # None表示自动模式，'hotspot'表示启动并连接到热点
        self.web_thread = None
        self.app = None
        
        # 设置信号处理
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)
        
        # 初始化DBus
        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
        
        # 验证WEB_PASSWORD必须是64位十六进制哈希字符串
        import re
        hex_pattern = re.compile(r'^[0-9a-f]{64}$', re.IGNORECASE)
        if not hex_pattern.match(WEB_PASSWORD):
            raise ValueError(
                "WEB_PASSWORD必须是64位十六进制SHA256哈希字符串。"
                f"当前值: '{WEB_PASSWORD}'。"
                "请运行: echo -n 'your_password' | sha256sum | awk '{print $1}' 获取哈希值。"
            )
        self.password_hash = WEB_PASSWORD.lower()
        logger.info("使用密码哈希进行认证")
        
        # 初始化认证令牌签名器，使用password_hash + salt的哈希作为密钥
        secret_key = hashlib.sha256(
            (self.password_hash + WEB_PASSWORD_SALT).encode()
        ).hexdigest()
        self.token_signer = URLSafeTimedSerializer(
            secret_key
        )
        
    def signal_handler(self, signum, frame):
        """处理终止信号"""
        logger.info(f"收到信号 {signum}，正在关闭...")
        if self.hotspot_active:
            self.deactivate_hotspot()
        if self.main_loop:
            self.main_loop.quit()
        sys.exit(0)
    
    # Web管理界面相关方法
    def scan_wifi_networks(self):
        """扫描可用的WiFi网络"""
        try:
            result = subprocess.run(
                ['nmcli', '-t', '-f', 'SSID,SIGNAL,SECURITY', 'device', 'wifi', 'list'],
                capture_output=True,
                text=True,
                timeout=30
            )
            networks = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split(':')
                    if len(parts) >= 3:
                        ssid = parts[0]
                        signal = parts[1] if len(parts) > 1 else '0'
                        security = parts[2] if len(parts) > 2 else ''
                        networks.append({
                            'ssid': ssid,
                            'signal': signal,
                            'security': security
                        })
            return networks
        except Exception as e:
            logger.error(f"扫描WiFi网络失败: {e}")
            return []

    def connect_to_wifi(self, ssid, password):
        """连接到指定WiFi网络"""
        try:
            # 输入验证，防止代码注入
            dangerous_chars = [';', '&', '|', '$', '`', "'", '"', '>', '<', '\n', '\r']
            for char in dangerous_chars:
                if char in ssid:
                    return {'success': False, 'message': f'SSID包含非法字符: {repr(char)}'}
                if char in password:
                    return {'success': False, 'message': f'密码包含非法字符: {repr(char)}'}
            # 限制长度
            if len(ssid) > 32:
                return {'success': False, 'message': 'SSID过长'}
            if len(password) > 64:
                return {'success': False, 'message': '密码过长'}
            # 首先断开当前连接（如果有）
            subprocess.run(['nmcli', 'con', 'down', 'id', 'wifi*'], 
                          capture_output=True, timeout=5)
            time.sleep(1)
            
            # 检查是否已有该SSID的配置
            check = subprocess.run(
                ['nmcli', 'connection', 'show', ssid],
                capture_output=True,
                text=True
            )
            
            if check.returncode != 0:
                # 创建新连接 - 使用正确的密码传递方式
                if password:
                    # 对于需要密码的网络
                    cmd = [
                        'nmcli', 'device', 'wifi', 'connect', ssid, 
                        'password', password
                    ]
                else:
                    # 对于开放网络
                    cmd = ['nmcli', 'device', 'wifi', 'connect', ssid]
            else:
                # 如果配置已存在但需要更新密码
                if password:
                    # 先修改连接的密码
                    modify_cmd = [
                        'nmcli', 'connection', 'modify', ssid,
                        'wifi-sec.key-mgmt', 'wpa-psk',
                        'wifi-sec.psk', password
                    ]
                    subprocess.run(modify_cmd, capture_output=True, text=True, timeout=10)
                
                # 然后激活连接
                cmd = ['nmcli', 'connection', 'up', ssid]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                logger.info(f"成功连接到WiFi网络: {ssid}")
                return {'success': True, 'message': f'已连接到 {ssid}'}
            else:
                error_msg = result.stderr.strip()
                logger.error(f"连接WiFi失败: {error_msg}")
                # 连接失败，删除该失败的连接配置
                self.delete_wifi_config(ssid)
                return {'success': False, 'message': f'连接失败: {error_msg}'}
                
        except Exception as e:
            logger.error(f"连接WiFi时出错: {e}")
            return {'success': False, 'message': f'连接时发生错误: {str(e)}'}

    def delete_wifi_config(self, ssid):
        """删除指定SSID的WiFi连接配置"""
        try:
            # 检查配置是否存在
            check = subprocess.run(
                ['nmcli', 'connection', 'show', ssid],
                capture_output=True,
                text=True
            )
            if check.returncode == 0:
                subprocess.run(['nmcli', 'connection', 'delete', ssid], 
                              capture_output=True, text=True, timeout=5)
                logger.info(f"已删除WiFi连接配置: {ssid}")
                return True
            else:
                logger.debug(f"WiFi连接配置不存在: {ssid}")
                return False
        except Exception as e:
            logger.error(f"删除WiFi配置时出错: {e}")
            return False
    def verify_password(self, password):
        """验证Web管理界面密码"""
        # 计算输入密码的SHA256哈希（不带盐）
        input_hash = hashlib.sha256(password.encode()).hexdigest()
        # 与存储的密码哈希比较
        return input_hash == self.password_hash
    
    def generate_auth_token(self):
        """生成认证令牌"""
        return self.token_signer.dumps({'user': 'admin'})
    
    def verify_auth_token(self, token):
        """验证认证令牌"""
        try:
            data = self.token_signer.loads(token, max_age=TOKEN_EXPIRY)
            return data.get('user') == 'admin'
        except SignatureExpired:  # 修改异常类型
            logger.warning("认证令牌已过期")
            return False
        except BadSignature:  # 修改异常类型
            logger.warning("无效的认证令牌")
            return False
        except Exception as e:
            logger.error(f"验证令牌时出错: {e}")
            return False
    def get_hotspot_config(self):
        """获取当前热点配置"""
        try:
            result = subprocess.run(
                ['nmcli', '-t', '-f', '802-11-wireless.ssid,802-11-wireless-security.psk', 
                 'connection', 'show', HOTSPOT_CONNECTION_NAME],
                capture_output=True,
                text=True
            )
            ssid = HOTSPOT_SSID
            password = HOTSPOT_PASSWORD
            for line in result.stdout.strip().split('\n'):
                if line.startswith('802-11-wireless.ssid:'):
                    ssid = line.split(':')[1]
                elif line.startswith('802-11-wireless-security.psk:'):
                    password = line.split(':')[1]
            return {
                'ssid': ssid,
                'password': password,
                'interface': INTERFACE,
                'ip': '192.168.42.1'
            }
        except Exception as e:
            logger.error(f"获取热点配置失败: {e}")
            return {
                'ssid': HOTSPOT_SSID,
                'password': HOTSPOT_PASSWORD,
                'interface': INTERFACE,
                'ip': '192.168.42.1'
            }

    def update_hotspot_config(self, ssid=None, password=None):
        """更新热点配置"""
        global HOTSPOT_SSID, HOTSPOT_PASSWORD
        try:
            # 输入验证，防止代码注入
            dangerous_chars = [';', '&', '|', '$', '`', "'", '"', '>', '<', '\n', '\r']
            if ssid:
                for char in dangerous_chars:
                    if char in ssid:
                        return {'success': False, 'message': f'SSID包含非法字符: {repr(char)}'}
                if len(ssid) > 32:
                    return {'success': False, 'message': 'SSID过长'}
            if password:
                for char in dangerous_chars:
                    if char in password:
                        return {'success': False, 'message': f'密码包含非法字符: {repr(char)}'}
                if len(password) > 64:
                    return {'success': False, 'message': '密码过长'}
            
            # 记录是否热点正在运行
            hotspot_was_active = self.hotspot_active
            
            if ssid and ssid != HOTSPOT_SSID:
                # 如果热点正在运行，先停用
                if hotspot_was_active:
                    self.deactivate_hotspot()
                
                subprocess.run([
                    'nmcli', 'connection', 'modify', HOTSPOT_CONNECTION_NAME,
                    '802-11-wireless.ssid', ssid
                ], check=True)
                HOTSPOT_SSID = ssid
                logger.info(f"热点SSID更新为: {ssid}")
            
            if password and password != HOTSPOT_PASSWORD:
                # 如果热点正在运行，先停用
                if hotspot_was_active and not (ssid and ssid != HOTSPOT_SSID):
                    # 只有在SSID没有变化且热点正在运行时才需要停用
                    self.deactivate_hotspot()
                
                subprocess.run([
                    'nmcli', 'connection', 'modify', HOTSPOT_CONNECTION_NAME,
                    '802-11-wireless-security.psk', password
                ], check=True)
                HOTSPOT_PASSWORD = password
                logger.info("热点密码已更新")
            
            # 如果热点之前正在运行，重新激活
            if hotspot_was_active:
                logger.info("重新激活热点以应用新配置...")
                self.setup_hotspot_profile()  # 确保配置是最新的
                self.activate_hotspot()
            
            return {'success': True, 'message': '热点配置已更新'}
        except Exception as e:
            logger.error(f"更新热点配置失败: {e}")
            # 如果更新失败，尝试恢复热点状态
            if hotspot_was_active and not self.hotspot_active:
                try:
                    self.activate_hotspot()
                except:
                    pass
            return {'success': False, 'message': f'更新失败: {str(e)}'}

    def get_nm_client(self):
        """获取NetworkManager DBus接口"""
        try:
            bus = dbus.SystemBus()
            proxy = bus.get_object('org.freedesktop.NetworkManager', 
                                  '/org/freedesktop/NetworkManager')
            return dbus.Interface(proxy, 'org.freedesktop.NetworkManager')
        except Exception as e:
            logger.error(f"获取NetworkManager接口失败: {e}")
            return None
    
    def check_wifi_status(self):
        """检查WiFi连接状态"""
        try:
            # 方法1：使用nmcli检查连接状态
            result = subprocess.run(
                ['nmcli', '-t', '-f', 'TYPE,STATE', 'c', 'show', '--active'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            wifi_active = False
            for line in result.stdout.strip().split('\n'):
                if line and '802-11-wireless' in line and ':activated' in line:
                    wifi_active = True
                    break
            
            # 方法2：检查是否获取到IP
            if wifi_active:
                ip_result = subprocess.run(
                    ['ip', '-4', 'addr', 'show', INTERFACE],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                has_ip = 'inet ' in ip_result.stdout
                return wifi_active and has_ip
            
            return wifi_active
            
        except subprocess.TimeoutExpired:
            logger.warning("检查WiFi状态超时")
            return False
        except Exception as e:
            logger.error(f"检查WiFi状态时出错: {e}")
            return False
    
    def setup_hotspot_profile(self):
        """创建或更新热点配置"""
        try:
            # 检查热点配置是否存在
            check = subprocess.run(
                ['nmcli', 'connection', 'show', HOTSPOT_CONNECTION_NAME],
                capture_output=True,
                text=True
            )
            
            if check.returncode != 0:
                logger.info("创建热点配置...")
                # 创建热点连接
                subprocess.run([
                    'nmcli', 'connection', 'add',
                    'type', 'wifi',
                    'ifname', INTERFACE,
                    'con-name', HOTSPOT_CONNECTION_NAME,
                    'autoconnect', 'no',
                    'ssid', HOTSPOT_SSID
                ], check=True)
                
                # 配置热点参数
                subprocess.run([
                    'nmcli', 'connection', 'modify', HOTSPOT_CONNECTION_NAME,
                    '802-11-wireless.mode', 'ap',
                    '802-11-wireless.band', 'bg',
                    'ipv4.method', 'shared',
                    'ipv4.addresses', '192.168.42.1/24',
                    'ipv6.method', 'ignore'
                ], check=True)
                
                # 设置WPA2密码
                subprocess.run([
                    'nmcli', 'connection', 'modify', HOTSPOT_CONNECTION_NAME,
                    '802-11-wireless-security.key-mgmt', 'wpa-psk',
                    '802-11-wireless-security.psk', HOTSPOT_PASSWORD,
                    '802-11-wireless-security.proto', 'rsn',
                    '802-11-wireless-security.group', 'ccmp',
                    '802-11-wireless-security.pairwise', 'ccmp'
                ], check=True)
                
                logger.info("热点配置创建成功")
            else:
                logger.info("热点配置已存在，更新配置...")
                # 更新SSID
                subprocess.run([
                    'nmcli', 'connection', 'modify', HOTSPOT_CONNECTION_NAME,
                    '802-11-wireless.ssid', HOTSPOT_SSID
                ], check=True)
                
                # 更新密码
                subprocess.run([
                    'nmcli', 'connection', 'modify', HOTSPOT_CONNECTION_NAME,
                    '802-11-wireless-security.psk', HOTSPOT_PASSWORD
                ], check=True)
                
                logger.info(f"热点配置已更新 - SSID: {HOTSPOT_SSID}")
                
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"创建/更新热点配置失败: {e}")
            return False
    
    def activate_hotspot(self):
        """激活热点"""
        if self.hotspot_active:
            return True
            
        try:
            logger.info("正在激活热点...")
            
            # 禁用其他WiFi连接
            
            #subprocess.run(['nmcli', 'radio', 'wifi', 'off'], timeout=10)
            #time.sleep(1)
            #subprocess.run(['nmcli', 'radio', 'wifi', 'on'], timeout=10)
            #time.sleep(2)
            #关闭再打开WiFi射频可能导致其他网络管理操作失败。使用更优雅的方式
            # 先禁用所有WiFi连接
            subprocess.run(['nmcli', 'con', 'down', 'id', 'wifi*'], 
                        capture_output=True, timeout=5)
            # 激活热点
            result = subprocess.run(
                ['nmcli', 'connection', 'up', HOTSPOT_CONNECTION_NAME],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                self.hotspot_active = True
                logger.info(f"热点已激活 - SSID: {HOTSPOT_SSID}, IP: 192.168.42.1")
                return True
            else:
                logger.error(f"激活热点失败: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"激活热点时出错: {e}")
            return False
    
    def deactivate_hotspot(self):
        """停用热点"""
        if not self.hotspot_active:
            return True
            
        try:
            logger.info("正在停用热点...")
            
            result = subprocess.run(
                ['nmcli', 'connection', 'down', HOTSPOT_CONNECTION_NAME],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                self.hotspot_active = False
                logger.info("热点已停用")
                return True
            else:
                logger.warning(f"停用热点失败: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"停用热点时出错: {e}")
            return False
    
    def monitor_network_state(self):
        """监控网络状态变化（DBus事件驱动）"""
        try:
            bus = dbus.SystemBus()
            proxy = bus.get_object('org.freedesktop.NetworkManager', 
                                  '/org/freedesktop/NetworkManager')
            
            # 连接到状态变化信号
            proxy.connect_to_signal(
                'StateChanged',
                self.on_nm_state_changed,
                dbus_interface='org.freedesktop.NetworkManager'
            )
            
            logger.info("开始监控NetworkManager状态变化...")
            
            # 运行GLib主循环
            self.main_loop = GLib.MainLoop()
            self.main_loop.run()
            
        except Exception as e:
            logger.error(f"监控DBus事件失败: {e}")
            return self.monitor_polling()  # 回退到轮询模式
    
    def on_nm_state_changed(self, state):
        """处理NetworkManager状态变化"""
        # NetworkManager状态码：
        # 20: disconnected, 60: connected (local), 70: connected (global)
        logger.debug(f"NetworkManager状态变化: {state}")
        
        if state >= 60:  # 已连接
            self.handle_wifi_connected()
        elif state == 20:  # 已断开
            self.handle_wifi_disconnected()
    
    def handle_wifi_connected(self):
        """处理WiFi连接事件"""
        if not self.wifi_connected:
            logger.info("WiFi已连接")
            self.wifi_connected = True
            self.retry_count = 0
            
            # 如果热点正在运行且不是启动并连接到热点模式，停用它
            if self.hotspot_active and self.manual_mode != 'hotspot':
                self.deactivate_hotspot()
    
    def handle_wifi_disconnected(self):
        """处理WiFi断开事件"""
        time.sleep(8)
        if not self.check_wifi_status():
            logger.warning("WiFi连接确认断开")
            self.wifi_connected = False
            # 如果不是启动并连接到热点模式，立即尝试激活热点
            if not self.hotspot_active and self.manual_mode != 'hotspot':
                self.setup_hotspot_profile()
                self.activate_hotspot()
    
    def monitor_polling(self):
        """轮询监控模式（备用）"""
        logger.info("使用轮询模式监控网络状态...")
        
        # 初始检查 - 考虑手动模式
        self.wifi_connected = self.check_wifi_status()
        
        if self.manual_mode == 'hotspot':
            logger.info("启动并连接到热点模式，激活热点...")
            self.setup_hotspot_profile()
            self.activate_hotspot()
        else:  # 自动模式
            if not self.wifi_connected:
                logger.info("启动时检测到WiFi未连接，立即激活热点...")
                self.setup_hotspot_profile()
                self.activate_hotspot()
            else:
                logger.info("启动时检测到WiFi已连接")
        
        while True:
            try:
                # 检查WiFi状态
                current_status = self.check_wifi_status()
                
                # 如果处于手动模式，根据模式处理
                if self.manual_mode == 'hotspot':
                    # 启动并连接到热点模式：确保热点激活
                    if not self.hotspot_active:
                        self.setup_hotspot_profile()
                        self.activate_hotspot()
                else:  # 自动模式
                    # 状态变化处理
                    if current_status and not self.wifi_connected:
                        # WiFi从断开变为连接
                        self.handle_wifi_connected()
                        
                    elif not current_status and self.wifi_connected:
                        # WiFi从连接变为断开
                        self.handle_wifi_disconnected()
                        
                    elif not current_status and not self.wifi_connected and not self.hotspot_active:
                        # 保持断开状态，尝试激活热点
                        self.retry_count += 1
                        if self.retry_count >= RETRY_THRESHOLD:
                            logger.info("WiFi持续断开，尝试激活热点...")
                            self.setup_hotspot_profile()
                            self.activate_hotspot()
                            self.retry_count = 0
                
                # 更新当前连接状态
                self.wifi_connected = current_status
                
                # 等待下一次检查
                time.sleep(CHECK_INTERVAL)
                
            except KeyboardInterrupt:
                logger.info("收到中断信号，正在退出...")
                break
            except Exception as e:
                logger.error(f"监控循环出错: {e}")
                time.sleep(CHECK_INTERVAL)
    
    def start_web_server(self):
        """启动Web管理界面"""
        try:
            self.app = Flask(__name__)
            # 认证中间件
            @self.app.before_request
            def require_auth():
                # 公开路径白名单
                public_paths = ['/', '/css', '/js', '/api/login']
                if request.path in public_paths:
                    return None
                # 检查认证令牌 - 仅支持HttpOnly cookie
                token = request.cookies.get('auth_token')
                if not token:
                    return jsonify({'success': False, 'message': '未授权'}), 401
                if not self.verify_auth_token(token):
                    return jsonify({'success': False, 'message': '无效或过期的令牌'}), 401
            
            @self.app.route('/')
            def login():
                # 如果已经登录，重定向到dashboard
                token = request.cookies.get('auth_token')
                if token and self.verify_auth_token(token):
                    return redirect('/dashboard')
                # 否则显示登录页面
                return render_template('login.html')
            
            @self.app.route('/dashboard')
            def dashboard():
                hotspot_config = self.get_hotspot_config()
                # 直接使用render_template函数渲染模板
                return render_template('dashboard.html', hotspot_config=hotspot_config)
            
            @self.app.route('/js')
            def js():
                # 直接读取JavaScript文件并返回
                try:
                    with open('/usr/local/bin/wifi-failover-hotspot/bootstrap.bundle.min.js', 'r') as f:
                        return f.read(), 200, {'Content-Type': 'application/javascript'}
                except Exception as e:
                    logger.error(f"无法读取JS文件: {e}")
                    return "文件未找到", 404
            
            @self.app.route('/css')
            def css():
                # 直接读取CSS文件并返回
                try:
                    with open('/usr/local/bin/wifi-failover-hotspot/bootstrap.min.css', 'r') as f:
                        return f.read(), 200, {'Content-Type': 'text/css'}
                except Exception as e:
                    logger.error(f"无法读取CSS文件: {e}")
                    return "文件未找到", 404
            
            @self.app.route('/api/login', methods=['POST'])
            def api_login():
                data = request.get_json()
                password = data.get('password', '')
                if not password:
                    return jsonify({'success': False, 'message': '请输入密码'}), 400
                if self.verify_password(password):
                    token = self.generate_auth_token()
                    # 创建响应并设置HttpOnly cookie
                    resp = make_response(jsonify({'success': True, 'message': '登录成功'}))
                    resp.set_cookie('auth_token', token, httponly=True, secure=False, samesite='Strict', max_age=TOKEN_EXPIRY)
                    return resp
                else:
                    return jsonify({'success': False, 'message': '密码错误'}), 401
            
            @self.app.route('/api/logout', methods=['POST'])
            def api_logout():
                # 清除认证cookie
                resp = make_response(jsonify({'success': True, 'message': '已退出登录'}))
                resp.set_cookie('auth_token', '', expires=0, httponly=True, secure=False, samesite='Strict')
                return resp
            
            @self.app.route('/api/status')
            def api_status():
                # 获取当前IP
                current_ip = '未知'
                try:
                    result = subprocess.run(
                        ['ip', '-4', 'addr', 'show', INTERFACE],
                        capture_output=True,
                        text=True
                    )
                    for line in result.stdout.split('\n'):
                        if 'inet ' in line:
                            current_ip = line.strip().split()[1].split('/')[0]
                            break
                except:
                    pass
                
                return jsonify({
                    'wifi_connected': self.wifi_connected,
                    'hotspot_active': self.hotspot_active,
                    'manual_mode': self.manual_mode,
                    'current_ip': current_ip
                })
            
            @self.app.route('/api/wifi/scan')
            def api_wifi_scan():
                networks = self.scan_wifi_networks()
                return jsonify(networks)
            
            @self.app.route('/api/wifi/connect', methods=['POST'])
            def api_wifi_connect():
                data = request.get_json()
                ssid = data.get('ssid', '').strip()
                password = data.get('password', '')
                
                if not ssid:
                    return jsonify({'success': False, 'message': '请输入SSID'})
                
                result = self.connect_to_wifi(ssid, password)
                return jsonify(result)
            
            @self.app.route('/api/hotspot/config', methods=['POST'])
            def api_hotspot_config():
                data = request.get_json()
                ssid = data.get('ssid', '').strip()
                password = data.get('password', '')
                
                if not ssid:
                    return jsonify({'success': False, 'message': '请输入热点SSID'})
                
                if password and len(password) < 8:
                    return jsonify({'success': False, 'message': '密码至少需要8个字符'})
                
                result = self.update_hotspot_config(ssid, password)
                return jsonify(result)
            
            @self.app.route('/api/mode/switch', methods=['POST'])
            def api_mode_switch():
                data = request.get_json()
                mode = data.get('mode', 'auto')
                
                if mode not in ['auto', 'hotspot']:
                    return jsonify({'success': False, 'message': '无效的模式'})
                
                self.manual_mode = None if mode == 'auto' else mode
                logger.info(f"切换模式到: {mode}")
                
                # 根据模式执行操作
                if mode == 'hotspot':
                    # 激活热点
                    if not self.hotspot_active:
                        self.setup_hotspot_profile()
                        self.activate_hotspot()
                else:  # auto
                    # 恢复自动模式，根据当前状态决定
                    pass
                
                return jsonify({'success': True, 'message': f'已切换到{mode}模式'})
            
            # 在后台线程中运行Flask应用
            def run_flask():
                # 设置模板文件夹路径
                self.app.template_folder = '/usr/local/bin/wifi-failover-hotspot'
                self.app.run(host=WEB_HOST, port=WEB_PORT, debug=WEB_DEBUG, threaded=True, use_reloader=False)
            
            self.web_thread = threading.Thread(target=run_flask, daemon=True)
            self.web_thread.start()
            logger.info(f"Web管理界面已启动: http://{WEB_HOST}:{WEB_PORT}")
            
        except Exception as e:
            logger.error(f"启动Web服务器失败: {e}")
    
    def run(self):
        """运行主服务"""
        logger.info("=" * 50)
        logger.info("WiFi故障转移热点服务启动")
        logger.info(f"热点SSID: {HOTSPOT_SSID}")
        logger.info(f"热点密码: {HOTSPOT_PASSWORD}")
        logger.info(f"网络接口: {INTERFACE}")
        logger.info("=" * 50)
        
        # 确保NetworkManager管理wlan0
        try:
            subprocess.run(['nmcli', 'dev', 'set', INTERFACE, 'managed', 'yes'], check=True)
        except:
            pass
        
        # 首先确保热点配置存在
        if not self.setup_hotspot_profile():
            logger.error("无法设置热点配置，退出")
            return
        
        # 启动Web管理界面
        self.start_web_server()
        
        # 启动时立即检查WiFi状态，根据手动模式决定是否开启热点
        logger.info("检查启动时WiFi连接状态...")
        initial_wifi_status = self.check_wifi_status()
        self.wifi_connected = initial_wifi_status
        
        if self.manual_mode == 'hotspot':
            logger.info("启动并连接到热点模式，激活热点...")
            self.setup_hotspot_profile()
            self.activate_hotspot()
        else:  # 自动模式
            if not initial_wifi_status:
                logger.info("启动时WiFi未连接，立即激活热点...")
                self.wifi_connected = False
                self.activate_hotspot()
            else:
                logger.info("启动时WiFi已连接，等待监控...")
                self.wifi_connected = True
        
        # 尝试使用事件驱动模式，失败则回退到轮询
        try:
            self.monitor_network_state()
        except Exception as e:
            logger.error(f"事件驱动模式失败: {e}")
            self.monitor_polling()

def main():
    """主函数"""
    # 确保以root权限运行
    if os.geteuid() != 0:
        print("错误：此脚本需要以root权限运行")
        print("请使用: sudo python3 wifi-failover-hotspot.py")
        sys.exit(1)
    
    service = WiFiFailoverHotspot()
    service.run()

if __name__ == "__main__":
    main()