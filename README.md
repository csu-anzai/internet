## 装wget

CentOS:

sudo yum -y install wget

Debian/Ubuntu

sudo apt-get install wget

可能需要装

ca-certificates python3-pip make curl subversion

修复

apt --fix-broken install

## 超级Internet一键设置脚本，集成V2Ray，SSR，BBR，Lotserver，SSH端口修改，Root用户改密，VPS系统重装，Nginx，Caddy

sudo su && wget https://raw.githubusercontent.com/AmuyangA/internet/master/supervpn/sv.sh && chmod +x sv.sh && ./sv.sh

## 设置更改root用户登录密码

sudo su && wget https://raw.githubusercontent.com/AmuyangA/internet/master/root/rtpw.sh && chmod +x rtpw.sh && ./rtpw.sh

## 修改SSH端口:

wget https://raw.githubusercontent.com/AmuyangA/internet/master/ssh/sshport.sh && chmod +x sshport.sh && ./sshport.sh

## SSR:

wget https://raw.githubusercontent.com/AmuyangA/internet/master/ssr/shadowsocksR.sh && chmod +x shadowsocksR.sh && ./shadowsocksR.sh 2>&1 | tee shadowsocksR

## V2Ray:

wget https://raw.githubusercontent.com/AmuyangA/internet/master/v2ray/multi-v2ray.sh && chmod +x multi-v2ray.sh && ./multi-v2ray.sh

## Wireguard:

（该一键脚本会先安装单用户然后自动安装多用户，不需单独下载安装多用户脚本）

wget -qO- https://raw.githubusercontent.com/AmuyangA/internet/master/wireguard/wireguard-master/debian_wg_vpn.sh | bash

## BBR:

wget https://raw.githubusercontent.com/AmuyangA/internet/master/bbr/bbr.sh && chmod +x bbr.sh && ./bbr.sh

## udp2raw:

wget https://raw.githubusercontent.com/AmuyangA/internet/master/wireguard/wg%2Budp2raw/wireguard_udp2raw.sh && chmod +x wireguard_udp2raw.sh && ./wireguard_udp2raw.sh

## 宝塔面板

https://www.bt.cn/btcode.html

## 服务器性能测试

wget -qO- --no-check-certificate https://raw.githubusercontent.com/AmuyangA/internet/master/bench/ibench.sh | bash

wget -qO- --no-check-certificate https://raw.githubusercontent.com/AmuyangA/internet/master/bench/cbench.sh | bash

##  删除文件

删除/opt/目录下的svn文件夹，将会删除/opt/svn/目录以及其下所有文件夹，包括文件：

rm -rf /opt/svn

删除特定文件，将/opt/目录下的test.txt文件删除：

rm -f /opt/test.txt

## 如果不能编辑

先安装VIM编辑器

install -y vim

alias vi=vim
