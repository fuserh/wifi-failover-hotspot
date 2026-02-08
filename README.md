# WiFi故障转移热点服务 / WiFi Failover Hotspot Service

[English](#english) | [中文](#中文)

<a name="english"></a>
## 🌐 WiFi Failover Hotspot Service

A Python-based service that monitors WiFi connectivity and automatically activates a hotspot when WiFi connection is lost. Includes a web management interface for configuration and control.

### ✨ Features

- **Automatic Failover**: Monitors WiFi connection and activates hotspot when disconnected
- **Web Management Interface**: User-friendly web dashboard for configuration
- **Manual Mode Control**: Switch between automatic and manual hotspot modes
- **WiFi Network Management**: Scan and connect to available WiFi networks
- **Hotspot Configuration**: Customize hotspot SSID and password
- **Real-time Status**: View current connection status and IP address
- **Secure Authentication**: Password-protected web interface with token-based authentication

### 📋 Requirements

- **Operating System**: Linux (tested on Raspberry Pi OS, Ubuntu)
- **Python**: 3.6+
- **Dependencies**:
  - `dbus-python`
  - `Flask`
  - `itsdangerous`
  - `NetworkManager` (system service)

### 🚀 Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/fuserh/wifi-failover-hotspot.git
   cd wifi-failover-hotspot
   ```

2. **Install Python dependencies**:
   ```bash
   pip install dbus-python Flask itsdangerous
   ```

3. **Run the installation script**:
   ```bash
   sudo ./install-wifi-failover.sh
   ```

4. **Configure web password** (optional):
   ```bash
   # Generate SHA256 hash for your password
   echo -n 'your_password' | sha256sum | awk '{print $1}'
   
   # Set environment variables
   export WEB_PASSWORD='your_sha256_hash'
   export WEB_PASSWORD_SALT='your_salt_value'
   ```

### ⚙️ Configuration

#### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WEB_PASSWORD` | SHA256 hash of 'admin123' | Web interface password (SHA256 hash) |
| `WEB_PASSWORD_SALT` | 'change_this_salt_in_production' | Password salt for token generation |
| `TOKEN_EXPIRY` | 3600 | Authentication token expiry in seconds |

#### Service Configuration

Edit `/usr/local/bin/wifi-failover-hotspot/wifi-failover-hotspot.py` to modify:

- `HOTSPOT_SSID`: Hotspot network name (default: "RaspberryPi-Hotspot")
- `HOTSPOT_PASSWORD`: Hotspot password (default: "RaspberryPi123********")
- `INTERFACE`: Wireless interface (default: "wlan0")
- `CHECK_INTERVAL`: WiFi check interval in seconds (default: 30)
- `WEB_PORT`: Web management port (default: 8080)

### Usage

#### Starting the Service

```bash
# Start as systemd service
sudo systemctl start wifi-failover-hotspot

# Enable auto-start on boot
sudo systemctl enable wifi-failover-hotspot

# Check service status
sudo systemctl status wifi-failover-hotspot
```

#### Web Management Interface

1. **Access the interface**: Open browser and navigate to `http://<device-ip>:8080`
2. **Default credentials**: Password is `admin123` (can be changed via environment variables)
3. **Features available**:
   - View current connection status
   - Scan and connect to WiFi networks
   - Configure hotspot settings
   - Switch between automatic/manual modes
   - Manual status refresh

#### Manual Control

```bash
# Check service logs
sudo journalctl -u wifi-failover-hotspot -f

# Restart service
sudo systemctl restart wifi-failover-hotspot

# Stop service
sudo systemctl stop wifi-failover-hotspot
```

### 📊 Web Interface Features

#### Dashboard
- **Current Status**: WiFi connection, hotspot status, IP address
- **Manual Refresh**: Click "Refresh Status" button to update status
- **Last Update Time**: Shows when status was last refreshed

#### WiFi Management
- **Network Scanning**: Scan for available WiFi networks
- **Signal Strength**: Visual signal strength indicators
- **Connection**: Connect to WiFi networks with password

#### Hotspot Management
- **Configuration**: Set hotspot SSID and password
- **Security**: Minimum 8-character password requirement
- **Interface Info**: Display network interface and IP information

#### Mode Control
- **Automatic Mode**: Automatically switches between WiFi and hotspot
- **Hotspot Mode**: Manually activate and connect to hotspot

### 🔧 Troubleshooting

#### Common Issues

1. **Service fails to start**:
   ```bash
   # Check dependencies
   sudo apt-get install network-manager dbus
   
   # Check logs
   sudo journalctl -u wifi-failover-hotspot -n 50
   ```

2. **Web interface not accessible**:
   ```bash
   # Check if service is running
   sudo systemctl status wifi-failover-hotspot
   
   # Check firewall settings
   sudo ufw allow 8080/tcp
   ```

3. **Hotspot not activating**:
   ```bash
   # Check NetworkManager
   sudo systemctl status NetworkManager
   
   # Check interface
   ip link show wlan0
   ```

#### Logs
- Service logs: `/var/log/wifi-failover.log`
- System logs: `sudo journalctl -u wifi-failover-hotspot`

### 📁 Project Structure

```
wifi-failover-hotspot/
├── wifi-failover-hotspot.py          # Main service script
├── dashboard.html                    # Web management interface
├── login.html                       # Login page
├── bootstrap.min.css                # Bootstrap CSS
├── bootstrap.bundle.min.js          # Bootstrap JavaScript
├── wifi-failover-hotspot.service    # Systemd service file
└── install-wifi-failover.sh         # Installation script
```

### 🔒 Security Notes

1. **Change default passwords**:
   - Web interface password (via `WEB_PASSWORD` environment variable)
   - Hotspot password (in configuration file)

2. **Use secure salts**:
   - Change `WEB_PASSWORD_SALT` in production

3. **Network security**:
   - Use strong WiFi and hotspot passwords
   - Consider changing default port (8080)

4. **Access control**:
   - Web interface is password-protected
   - Authentication tokens expire after 1 hour

### 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request
6. Translate the project into more languages

### 📄 License

This project is licensed under the GPLv3 License - see the LICENSE file for details.


---

<a name="中文"></a>
## 🌐 WiFi故障转移热点服务

基于Python的服务，监控WiFi连接并在断开时自动激活热点。包含用于配置和控制的Web管理界面。

### ✨ 功能特性

- **自动故障转移**: 监控WiFi连接，断开时自动激活热点
- **Web管理界面**: 用户友好的Web控制面板
- **手动模式控制**: 在自动和手动热点模式之间切换
- **WiFi网络管理**: 扫描并连接到可用的WiFi网络
- **热点配置**: 自定义热点SSID和密码
- **实时状态**: 查看当前连接状态和IP地址
- **安全认证**: 密码保护的Web界面，基于令牌的认证

### 📋 系统要求

- **操作系统**: Linux (已在Raspberry Pi OS、Ubuntu上测试)
- **Python**: 3.6+
- **依赖项**:
  - `dbus-python`
  - `Flask`
  - `itsdangerous`
  - `NetworkManager` (系统服务)

### 🚀 安装步骤

1. **克隆仓库**:
   ```bash
   git clone https://github.com/fuserh/wifi-failover-hotspot.git
   cd wifi-failover-hotspot
   ```

2. **安装Python依赖**:
   ```bash
   pip install dbus-python Flask itsdangerous
   ```

3. **运行安装脚本**:
   ```bash
   sudo ./install-wifi-failover.sh
   ```

4. **配置Web密码** (可选):
   ```bash
   # 为密码生成SHA256哈希
   echo -n '你的密码' | sha256sum | awk '{print $1}'
   
   # 设置环境变量
   export WEB_PASSWORD='你的sha256哈希'
   export WEB_PASSWORD_SALT='你的盐值'
   ```

### ⚙️ 配置说明

#### 环境变量

| 变量名 | 默认值 | 描述 |
|--------|--------|------|
| `WEB_PASSWORD` | 'admin123'的SHA256哈希 | Web界面密码(SHA256哈希) |
| `WEB_PASSWORD_SALT` | 'change_this_salt_in_production' | 令牌生成的密码盐值 |
| `TOKEN_EXPIRY` | 3600 | 认证令牌过期时间(秒) |

#### 服务配置

编辑 `/usr/local/bin/wifi-failover-hotspot/wifi-failover-hotspot.py` 修改:

- `HOTSPOT_SSID`: 热点网络名称 (默认: "RaspberryPi-Hotspot")
- `HOTSPOT_PASSWORD`: 热点密码 (默认: "RaspberryPi123********")
- `INTERFACE`: 无线接口 (默认: "wlan0")
- `CHECK_INTERVAL`: WiFi检查间隔(秒) (默认: 30)
- `WEB_PORT`: Web管理端口 (默认: 8080)

### 使用方法

#### 启动服务

```bash
# 作为systemd服务启动
sudo systemctl start wifi-failover-hotspot

# 启用开机自启动
sudo systemctl enable wifi-failover-hotspot

# 检查服务状态
sudo systemctl status wifi-failover-hotspot
```

#### Web管理界面

1. **访问界面**: 打开浏览器访问 `http://<设备IP>:8080`
2. **默认凭据**: 密码为 `admin123` (可通过环境变量更改)
3. **可用功能**:
   - 查看当前连接状态
   - 扫描并连接WiFi网络
   - 配置热点设置
   - 在自动/手动模式之间切换
   - 手动刷新状态

#### 手动控制

```bash
# 查看服务日志
sudo journalctl -u wifi-failover-hotspot -f

# 重启服务
sudo systemctl restart wifi-failover-hotspot

# 停止服务
sudo systemctl stop wifi-failover-hotspot
```

### 📊 Web界面功能

#### 控制面板
- **当前状态**: WiFi连接、热点状态、IP地址
- **手动刷新**: 点击"刷新状态"按钮更新状态
- **最后更新时间**: 显示上次状态刷新时间

#### WiFi管理
- **网络扫描**: 扫描可用的WiFi网络
- **信号强度**: 可视化信号强度指示器
- **连接**: 使用密码连接WiFi网络

#### 热点管理
- **配置**: 设置热点SSID和密码
- **安全性**: 至少8个字符的密码要求
- **接口信息**: 显示网络接口和IP信息

#### 模式控制
- **自动模式**: 自动在WiFi和热点之间切换
- **热点模式**: 手动激活并连接到热点

### 🔧 故障排除

#### 常见问题

1. **服务启动失败**:
   ```bash
   # 检查依赖项
   sudo apt-get install network-manager dbus
   
   # 检查日志
   sudo journalctl -u wifi-failover-hotspot -n 50
   ```

2. **Web界面无法访问**:
   ```bash
   # 检查服务是否运行
   sudo systemctl status wifi-failover-hotspot
   
   # 检查防火墙设置
   sudo ufw allow 8080/tcp
   ```

3. **热点无法激活**:
   ```bash
   # 检查NetworkManager
   sudo systemctl status NetworkManager
   
   # 检查接口
   ip link show wlan0
   ```

#### 日志
- 服务日志: `/var/log/wifi-failover.log`
- 系统日志: `sudo journalctl -u wifi-failover-hotspot`

### 📁 项目结构

```
wifi-failover-hotspot/
├── wifi-failover-hotspot.py          # 主服务脚本
├── dashboard.html                    # Web管理界面
├── login.html                       # 登录页面
├── bootstrap.min.css                # Bootstrap CSS
├── bootstrap.bundle.min.js          # Bootstrap JavaScript
├── wifi-failover-hotspot.service    # Systemd服务文件
└── install-wifi-failover.sh         # 安装脚本
```

### 🔒 安全注意事项

1. **更改默认密码**:
   - Web界面密码 (通过 `WEB_PASSWORD` 环境变量)
   - 热点密码 (在配置文件中)

2. **使用安全的盐值**:
   - 在生产环境中更改 `WEB_PASSWORD_SALT`

3. **网络安全**:
   - 使用强密码的WiFi和热点
   - 考虑更改默认端口(8080)

4. **访问控制**:
   - Web界面有密码保护
   - 认证令牌1小时后过期

### 🤝 贡献指南

1. Fork本仓库
2. 创建功能分支
3. 进行修改
4. 充分测试
5. 提交Pull Request
6. 将项目翻译成更多语言

### 📄 许可证

本项目采用GPLv3许可证 - 详见LICENSE文件。
