#!/bin/bash
# ==============================================================
# Project: Xray Uninstaller
# Description: Remove Xray, Configs, and related tools
# ==============================================================

if [[ $EUID -ne 0 ]]; then
    echo -e "\033[31m❌ 错误：请使用 root 权限运行此脚本。\033[0m"
    exit 1
fi

echo "🗑️ 正在停止并卸载 Xray 服务..."

# 1. 停止并禁用服务
systemctl stop xray >/dev/null 2>&1
systemctl disable xray >/dev/null 2>&1

# 2. 删除 Xray 主程序与资源文件
rm -rf /usr/local/bin/xray
rm -rf /usr/local/share/xray
rm -rf /usr/local/etc/xray

# 3. 删除 Systemd 服务文件
rm -f /etc/systemd/system/xray.service
rm -rf /etc/systemd/system/xray.service.d
systemctl daemon-reload

# 4. 删除附加工具 (mode 指令和自动更新脚本)
rm -f /usr/local/bin/mode
rm -f /usr/local/bin/update_geoip.sh

# 5. 清理定时任务 (Crontab)
# 仅删除包含 update_geoip.sh 的行，保留其他任务
crontab -l 2>/dev/null | grep -v "update_geoip.sh" | crontab -

echo "=========================================================="
echo -e "\033[32m✅ Xray 已成功卸载\033[0m"
echo "=========================================================="
echo "⚠️  注意："
echo "1. 系统优化 (BBR, Swap) 和基础依赖已保留，以免影响系统稳定性。"
echo "2. 防火墙规则 (iptables) 未被重置。如果需要恢复默认防火墙，"
echo "   请手动执行: iptables -P INPUT ACCEPT && iptables -F"
echo "=========================================================="
