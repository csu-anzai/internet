## 一：装SSR:

wget --no-check-certificate https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocksR.sh && chmod +x shadowsocksR.sh && ./shadowsocksR.sh 2>&1 | tee shadowsocksR

2  4  3

卸载： 
./shadowsocksR.sh uninstall

## 二：装加速器内核：

wget "https://github.com/chiakge/Linux-NetSpeed/raw/master/tcp.sh" && chmod +x tcp.sh && ./tcp.sh

2  7

### 重启之后应用加速器：

./tcp.sh

## 三：打开配置指令：

vi /etc/shadowsocks.json

### 输入 i 编辑配置

### 多用户配置
{

    "server":"0.0.0.0",
    
    "server_ipv6":"[::]",
    
    "local_address":"127.0.0.1",
    
    "local_port":1080,
    
    "port_password":{"端口1":"密码1",
    
                     "端口2":"密码2"
                     
                     },
                     
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

### 按 ESC 键退出编辑

### :wq 保存修改

### 生效配置文件（重启）：

service shadowsocks restart



## 附：ss启动停止方法

启动：service shadowsocks start

停止：service shadowsocks stop

重启：service shadowsocks restart

状态：service shadowsocks status

## 四：修改防火墙：

### 打开防火墙

firewall-cmd --get-active-zones

### 添加端口

firewall-cmd --zone=public --add-port=端口号/tcp --permanent

firewall-cmd --zone=public --add-port=端口号/udp --permanent

### 重启防火墙

firewall-cmd --reload

### 查看允许列表

firewall-cmd --permanent --list-port

### 移除防火墙：

firewall-cmd --zone=public --remove-port=端口号/tcp --permanent

firewall-cmd --zone=public --remove-port=端口号/udp --permanent

### 查看端口号是否开启，运行命令：

firewall-cmd --query-port=端口号/tcp

firewall-cmd --query-port=端口号/udp

## 五：修改SSH 端口

### 1，修改/etc/ssh/sshd_config

vi /etc/ssh/sshd_config

#Port 22         //这行去掉#号，防止配置不好以后不能远程登录，还得去机房修改，等修改以后的端口能使用以后在注释掉

Port 12345      //下面添加这一行

### 2，添加防火墙：打开防火墙，添加想要修改的ssh端口，重启防火墙

查看添加端口是否成功，如果添加成功则会显示yes，否则no：

firewall-cmd --query-port=12345/tcp

### 3，重启ssh

systemctl restart sshd.service
