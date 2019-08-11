# internet
## 修改SSH端口:

wget https://raw.githubusercontent.com/AmuyangA/internet/master/sshport.sh && chmod +x sshport.sh && ./sshport.sh

## SSR:

wget https://raw.githubusercontent.com/AmuyangA/internet/master/shadowsocksR.sh && chmod +x shadowsocksR.sh && ./shadowsocksR.sh 2>&1 | tee shadowsocksR

## V2Ray:

wget https://raw.githubusercontent.com/AmuyangA/internet/master/multi-v2ray.sh && chmod +x multi-v2ray.sh && ./multi-v2ray.sh

## Wireguard:

（该一键脚本会先安装单用户然后自动安装多用户，不需单独下载安装多用户脚本）

wget -qO- https://raw.githubusercontent.com/AmuyangA/internet/master/wireguard/wireguard-master/debian_wg_vpn.sh | bash

## BBR:

wget https://raw.githubusercontent.com/AmuyangA/internet/master/bbr/bbr.sh && chmod +x bbr.sh && ./bbr.sh

## udp2raw:

wget https://raw.githubusercontent.com/AmuyangA/internet/master/wireguard/wg%2Budp2raw/wireguard_udp2raw.sh && chmod +x wireguard_udp2raw.sh && ./wireguard_udp2raw.sh
