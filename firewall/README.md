# Debian

## 打开防火墙

## 添加端口

iptables -I INPUT -p tcp --dport 端口号 -j ACCEPT

iptables -I INPUT -p udp --dport 端口号 -j ACCEPT

## 保存防火墙

service iptables save

## 重启防火墙

service iptables restart

## 查看允许列表

iptables -L -n

## 移除防火墙：

iptables -I INPUT -p tcp --dport 端口号 -j DROP

iptables -I INPUT -p udp --dport 端口号 -j DROP

## 查看端口号是否开启，运行命令：

# CentOS

## 打开防火墙

firewall-cmd --get-active-zones

## 添加端口

firewall-cmd --zone=public --add-port=端口号/tcp --permanent

firewall-cmd --zone=public --add-port=端口号/udp --permanent

## 重启防火墙

firewall-cmd --reload

## 查看允许列表

firewall-cmd --permanent --list-port

## 移除防火墙：

firewall-cmd --zone=public --remove-port=端口号/tcp --permanent

firewall-cmd --zone=public --remove-port=端口号/udp --permanent

## 查看端口号是否开启，运行命令：

firewall-cmd --query-port=端口号/tcp

firewall-cmd --query-port=端口号/udp
