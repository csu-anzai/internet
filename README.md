# internet
SSR:
wget https://raw.githubusercontent.com/AmuyangA/internet/master/shadowsocksR.sh
chmod +x shadowsocksR.sh
./shadowsocksR.sh 2>&1 | tee shadowsocksR

V2Ray:
wget https://raw.githubusercontent.com/AmuyangA/internet/master/multi-v2ray.sh
chmod +x multi-v2ray.sh
./multi-v2ray.sh

Wireguard:
（该一键脚本会先安装单用户然后自动安装多用户，不需单独下载安装多用户脚本）
wget -qO- https://raw.githubusercontent.com/AmuyangA/internet/master/wireguard/wireguard-master/debian_wg_vpn.sh | bash
1、本脚本为2个用户，如果要添加N个用户，同步修改用户数和端口数，可以自定义修改端口
2、一键脚本运行完成后，做以下步骤：
允许转发在VPN通道内的数据包：
iptables -A FORWARD -i wg0 -o wg0 -m conntrack --ctstate NEW -j ACCEPT
设置NAT：
iptables -t nat -A POSTROUTING -s 10.80.80.0/24 -o eth0 -j MASQUERADE
3、安装iptables-persistent使设置在重启后保持有效：
apt-get install iptables-persistent（安装时提示y/n，选择：y）
systemctl enable netfilter-persistent
netfilter-persistent save
4、优化系统配置：
使用脚本进行优化（运行脚本选择优化配置即可）：
cd /usr/src && wget -N --no-check-certificate "https://raw.githubusercontent.com/AmuyangA/internet/master/bbr/centos7-debian9-ubuntu_bbr.sh" && chmod +x centos7-debian9-ubuntu_bbr.sh && ./centos7-debian9-ubuntu_bbr.sh
设置后运行：sysctl -p
说明：
1、如果要升级内核，请先停止wireguard，命令：wg-quick down wg0
2、内核升级后再运行：wg-quick up wg0
3、升级内核可以手动也可以使用上面的脚本，使用脚本仅升级了系统未升级内核，需按照上面的步骤手动安装新的内核
4、更新系统和安装新的内核后，用命令查看一下系统和内核，命令：
dpkg -l|grep linux-image
dpkg -l|grep linux-headers
用dpkg -l|grep linux-headers查看内核可能有旧版内核，需要卸载，命令：
apt-get remove --purge 旧内核名称  -y（如有提示y/n，选择n）
5、其他：
查看升级包：apt list --upgradable
修复内核：apt --fix-broken install
6、centos7多用户脚本，默认同步安装2用户，如果需要增加用户，请按照上面要求修改
wget -qO- https://raw.githubusercontent.com/AmuyangA/internet/master/wireguard/wireguard-master/centos7-wg-vpn.sh | bash

BBR:
wget https://raw.githubusercontent.com/AmuyangA/internet/master/bbr/centos7-debian9-ubuntu_bbr.sh
chmod +x centos7-debian9-ubuntu_bbr.sh
./centos7-debian9-ubuntu_bbr.sh

udp2raw:
wget https://raw.githubusercontent.com/AmuyangA/internet/master/wireguard/wg%2Budp2raw/wireguard_udp2raw.sh
chmod +x wireguard_udp2raw.sh
./wireguard_udp2raw.sh
