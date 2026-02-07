#!/bin/bash
# WiFi Failover Hotspot 安装脚本

set -e

echo "正在安装WiFi故障转移热点服务..."

# 1. 复制Python脚本
echo "复制主脚本到 /usr/local/bin/"
sudo cp wifi-failover-hotspot.py /usr/local/bin/
sudo chmod +x /usr/local/bin/wifi-failover-hotspot.py

# 2. 复制服务文件
#echo "复制系统服务文件"
#sudo cp wifi-failover-hotspot.service /etc/systemd/system/

# 3. 确保NetworkManager管理无线接口
echo "配置NetworkManager..."
sudo nmcli radio wifi on
sudo nmcli dev set wlan0 managed yes

echo "创建日志文件..."
touch /var/log/wifi-failover.log
chmod 644 /var/log/wifi-failover.log

# 4. 启用并启动服务
echo "启用系统服务..."
sudo systemctl daemon-reload
sudo systemctl enable wifi-failover-hotspot.service
sudo systemctl start wifi-failover-hotspot.service

# 5. 创建日志轮转配置
echo "配置日志轮转..."
sudo tee /etc/logrotate.d/wifi-failover > /dev/null << EOF
/var/log/wifi-failover.log {
    weekly
    missingok
    rotate 4
    compress
    delaycompress
    notifempty
    create 640 root adm
    postrotate
        systemctl kill -s USR1 wifi-failover-hotspot.service >/dev/null 2>&1 || true
    endscript
}
EOF

echo "安装完成！"
echo ""
echo "服务状态: sudo systemctl status wifi-failover-hotspot.service"
echo "查看日志: sudo journalctl -u wifi-failover-hotspot.service -f"
echo "热点SSID: RaspberryPi-Hotspot"
echo "热点密码: RaspberryPi123"
echo "热点IP: 192.168.42.1"
