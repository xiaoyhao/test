#!/usr/bin/env bash
# EdgeChat-LAN 局域网启动脚本
cd "$(dirname "$0")"
pip3 install -q -r requirements.txt
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
echo "==============================================="
echo " EdgeChat-LAN  局域网访问地址: http://${IP:-<本机IP>}:${EDGECHAT_PORT:-8790}"
echo " 首次启动会打印 admin 初始密码，请妥善保存"
echo "==============================================="
exec python3 app.py
