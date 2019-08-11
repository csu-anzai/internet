一：装SSR:
wget --no-check-certificate https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocksR.sh && chmod +x shadowsocksR.sh && ./shadowsocksR.sh 2>&1 | tee shadowsocksR

2  4  3

卸载： 
./shadowsocksR.sh uninstall

二：装加速器内核：
wget "https://github.com/chiakge/Linux-NetSpeed/raw/master/tcp.sh" && chmod +x tcp.sh && ./tcp.sh

2  7

重启之后应用加速器：
./tcp.sh

三：打开配置指令：
vi /etc/shadowsocks.json

{
    "server":"0.0.0.0",
    "server_ipv6":"[::]",
    "local_address":"127.0.0.1",
    "local_port":1080,
    "port_password":{"1923":"mjdczftr",
                     "3615":"mjdczftr",
                     "4123":"mjdczftr",
                     "4246":"mjdczftr",
                     "4345":"mjdczftr",
                     "4435":"mjdczftr",
                     "4564":"mjdczftr",
                     "4615":"mjdczftr",
                     "4725":"mjdczftr",
                     "4823":"mjdczftr",
                     "4914":"mjdczftr",
                     "5075":"mjdczftr",
                     "5123":"mjdczftr",
                     "5246":"mjdczftr",
                     "5345":"mjdczftr",
                     "5435":"mjdczftr",
                     "5564":"mjdczftr",
                     "5615":"mjdczftr",
                     "5725":"mjdczftr",
                     "5823":"mjdczftr",
                     "5914":"mjdczftr",
                     "6075":"mjdczftr"},
    "timeout":120,
    "method":"aes-256-cfb",
    "protocol":"auth_sha1_v4_compatible",
    "protocol_param":"3",
    "obfs":"http_simple_compatible",
    "obfs_param":"",
    "redirect":"",
    "dns_ipv6":true,
    "fast_open":true,
    "workers":1
}

生效配置文件（重启）：
service shadowsocks restart

i   进入到文本输入模式
出现“-- INSERT --”字样，此时可以直接修改文本

修改完之后
按下键盘左上角的ESC键，“-- INSERT --”字样消失
回到了指令模式，指令模式下输入
:wq   是保存并退出
:q!   是退出不保存。注意英文冒号“:”。

附：ss启动停止方法
启动：service shadowsocks start
停止：service shadowsocks stop
重启：service shadowsocks restart
状态：service shadowsocks status

四：防火墙：
1，打开防火墙，添加端口，重启防火墙，查看允许列表
firewall-cmd --get-active-zones
firewall-cmd --zone=public --add-port=1644/tcp --permanent
firewall-cmd --zone=public --add-port=1644/udp --permanent
firewall-cmd --zone=public --add-port=2583/tcp --permanent
firewall-cmd --zone=public --add-port=2583/udp --permanent
firewall-cmd --zone=public --add-port=3585/tcp --permanent
firewall-cmd --zone=public --add-port=3585/udp --permanent
firewall-cmd --zone=public --add-port=4671/tcp --permanent
firewall-cmd --zone=public --add-port=4671/udp --permanent
firewall-cmd --zone=public --add-port=5384/tcp --permanent
firewall-cmd --zone=public --add-port=5384/udp --permanent
firewall-cmd --zone=public --add-port=6572/tcp --permanent
firewall-cmd --zone=public --add-port=6572/udp --permanent
firewall-cmd --zone=public --add-port=7268/tcp --permanent
firewall-cmd --zone=public --add-port=7268/udp --permanent
firewall-cmd --zone=public --add-port=8846/tcp --permanent
firewall-cmd --zone=public --add-port=8846/udp --permanent
firewall-cmd --zone=public --add-port=9952/tcp --permanent
firewall-cmd --zone=public --add-port=9952/udp --permanent
firewall-cmd --zone=public --add-port=1097/tcp --permanent
firewall-cmd --zone=public --add-port=1097/udp --permanent
firewall-cmd --zone=public --add-port=1165/tcp --permanent
firewall-cmd --zone=public --add-port=1165/udp --permanent
firewall-cmd --zone=public --add-port=12345/tcp --permanent
firewall-cmd --zone=public --add-port=12345/udp --permanent
firewall-cmd --reload
firewall-cmd --permanent --list-port

2，移除防火墙：
firewall-cmd --zone=public --remove-port=3644/tcp --permanent
firewall-cmd --zone=public --remove-port=3644/udp --permanent
3，查看端口号是否开启，运行命令：
firewall-cmd --query-port=12345/tcp

五：修改SSH 端口
1，修改/etc/ssh/sshd_config
vi /etc/ssh/sshd_config
#Port 22         //这行去掉#号，防止配置不好以后不能远程登录，还得去机房修改，等修改以后的端口能使用以后在注释掉
Port 12345      //下面添加这一行

2，添加防火墙：打开防火墙，添加想要修改的ssh端口，重启防火墙
查看添加端口是否成功，如果添加成功则会显示yes，否则no：
firewall-cmd --query-port=12345/tcp

3，重启ssh
systemctl restart sshd.service

Ubuntu下的vi编辑器可能是不完整的
输入I之后无法进入文本输入模式
具体表现为只能输
但是不能删等等异常情况
解决办法：
接着直接输入apt-get install -y vim安装VIM编辑器
之后再输入alias vi=vim,然后断开ssh连接
重新连接vps即可
