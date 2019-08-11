## 系统：

Debian，CentOS

## 一：获取root权限并安装中文版：

sudo su root

source <(curl -sL https://git.io/fNgqx) --zh

## 二：进入v2ray-util管理程序：

v2ray

##  三：设置传输方式：

3   5     组   3   www.bilibili.com

## 四：设置Tcp Fast Open：

3   7     组   1

## 五：多用户

sudo su root

v2ray

2   2   (K   V)
----------------------------------------------	

## 六：使用：

v2ray -h	                查看帮助

v2ray start	             启动	

v2ray stop	              停止

v2ray status	            状态

v2ray log	               日志

v2ray update	            更新v2ray

v2ray update.sh	         更新multi-v2ray脚本

v2ray add	               新增协议

v2ray del	               删除端口组

v2ray info	              查看配置

v2ray port	              修改端口

v2ray tls	               修改tls

v2ray tfo	               修改tcpFastOpen

v2ray stream             修改传输协议

v2ray stats              流量统计

v2ray clean              清理日志

## 七：升级内核：

source <(curl -sL https://git.io/fNgqx) -k

## 八：卸载：

source <(curl -sL https://git.io/fNgqx) --remove

## 九：防火墙：
Debian:
确定你已经安装Iptables：whereis iptables
安装Iptables：sudo apt-get install iptables
查看Iptables配置信息：sudo iptables -L
