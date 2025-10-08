# ProxyInstaller — Sing-box 一键安装管理脚本

---

## 功能特性

- 安装 **VLESS + TCP + Reality** 协议  
- 安装 **VLESS + WS (WebSocket)** 协议  
- 安装 **Shadowsocks (中转)** 协议  
- 一键启用 **BBR 加速**  
- 支持修改端口 / 用户名 / 密码  
- 一键卸载脚本与所有配置  
- 多系统支持（Debian / Ubuntu / CentOS / Alpine / Fedora / Arch）

---

## 一键安装命令

在你的 VPS 上执行以下命令：

```bash
bash <(curl -Ls https://raw.githubusercontent.com/dabadabader/install/main/installer.sh)

## 若提示权限不足，可加上 sudo：
sudo bash <(curl -Ls https://raw.githubusercontent.com/dabadabader/install/main/installer.sh)

