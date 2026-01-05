# Xray Auto Installer

<p align="center">
  <img src="https://img.shields.io/github/v/release/accforeve/Xray-Auto?style=flat-square&color=success" alt="Version">
  <img src="https://img.shields.io/github/license/accforeve/Xray-Auto?style=flat-square&color=blue" alt="License">
  <img src="https://img.shields.io/badge/Protocol-VLESS%2BReality%2BVision-blueviolet?style=flat-square" alt="Protocol">
  <img src="https://img.shields.io/badge/Language-Bash-green?style=flat-square" alt="Language">
</p>

> **极简、健壮、智能的 Xray 一键安装脚本**。
> 专为 Debian / Ubuntu 打造，集成最新的 VLESS-Reality-Vision 协议，完美支持 IPv4/IPv6 双栈环境。

## ✨ 核心特性 (Features)

* **🔒 顶级协议**: 默认部署 **VLESS + XTLS-rprx-vision + Reality**，目前最先进的抗封锁组合，隐蔽性极强。
* **🌐 双栈兼容**: 完美支持 **IPv4 / IPv6** 单栈或双栈服务器。脚本会自动识别 IP 类型并在 VLESS 链接中自动适配格式（IPv6 自动添加 `[]`）。
* **🛡️ 安全加固**:
    * 内置 **双栈防火墙 (iptables + ip6tables)**，默认拒绝所有入站连接，仅放行 SSH 和业务端口。
    * 自动配置 **Fail2Ban**，防御 SSH 暴力破解。
* **⚡ 智能优选**: 安装时自动测试并筛选低延迟的大厂目标域名 (SNI)，无需人工干预。
* **🛠️ 极度健壮 (Robust)**:
    * **时间同步前置**: 在安装依赖前强制同步系统时间，彻底解决因时间偏差导致的 SSL 证书验证失败问题。
    * **智能锁清理**: 采用精准打击 (`fuser`) + 全局兜底 (`killall`) 策略，自动修复 `dpkg/apt` 被锁或卡死的问题。
    * **内存保护**: 检测到内存不足 2GB 时，自动创建 1GB Swap 交换分区，防止 OOM。
* **🔧 纯净安装**: 移除 `net-tools` 等冗余依赖，全部采用 Linux 原生指令 (`ss`, `ip`, `fuser`)，系统更干净。

## 📥 一键安装 (Installation)

**系统要求**: Debian 10+ / Ubuntu 20.04+ (推荐 Debian 12)
**权限要求**: 请使用 `root` 用户执行。

```bash
bash <(curl -Ls [https://raw.githubusercontent.com/accforeve/Xray-Auto/main/install.sh](https://raw.githubusercontent.com/accforeve/Xray-Auto/main/install.sh))

📜 License
本项目基于 MIT License 开源。

