#!/usr/bin/env python3
"""
WiFi Failover Hotspot Service
监控WiFi连接，断连时自动启动热点
启动时如果WiFi未连接也会自动开启热点
"""

import subprocess
import time
import logging
#import json
import dbus
import dbus.mainloop.glib
from gi.repository import GLib
import signal
import sys
import os
from datetime import datetime

# 配置参数
HOTSPOT_SSID = "RaspberryPi-Hotspot"
HOTSPOT_PASSWORD = "RaspberryPi123********"
HOTSPOT_CONNECTION_NAME = "Hotspot-Failover"
INTERFACE = "wlan0"  # 无线网卡接口
CHECK_INTERVAL = 30  # 检查间隔（秒）
RETRY_THRESHOLD = 3  # 重试阈值
LOG_FILE = "/var/log/wifi-failover.log"

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
        
        # 设置信号处理
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)
        
        # 初始化DBus
        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
        
    def signal_handler(self, signum, frame):
        """处理终止信号"""
        logger.info(f"收到信号 {signum}，正在关闭...")
        if self.hotspot_active:
            self.deactivate_hotspot()
        if self.main_loop:
            self.main_loop.quit()
        sys.exit(0)
    
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
        """创建热点配置"""
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
                    'wifi-sec.key-mgmt', 'wpa-psk',
                    'wifi-sec.psk', HOTSPOT_PASSWORD
                ], check=True)
                
                logger.info("热点配置创建成功")
            else:
                logger.info("热点配置已存在")
                
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"创建热点配置失败: {e}")
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
            
            # 如果热点正在运行，停用它
            if self.hotspot_active:
                self.deactivate_hotspot()
    
    def handle_wifi_disconnected(self):
        """处理WiFi断开事件"""
        time.sleep(8)
        if not self.check_wifi_status():
            logger.warning("WiFi连接确认断开")
            self.wifi_connected = False
            # 立即尝试激活热点
            if not self.hotspot_active:
                self.setup_hotspot_profile()
                self.activate_hotspot()
    
    def monitor_polling(self):
        """轮询监控模式（备用）"""
        logger.info("使用轮询模式监控网络状态...")
        
        # 初始检查 - 如果启动时WiFi未连接，立即开启热点
        self.wifi_connected = self.check_wifi_status()
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
                
                # 等待下一次检查
                time.sleep(CHECK_INTERVAL)
                
            except KeyboardInterrupt:
                logger.info("收到中断信号，正在退出...")
                break
            except Exception as e:
                logger.error(f"监控循环出错: {e}")
                time.sleep(CHECK_INTERVAL)
    
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
        
        # 启动时立即检查WiFi状态，如果未连接就开启热点
        logger.info("检查启动时WiFi连接状态...")
        initial_wifi_status = self.check_wifi_status()
        
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
