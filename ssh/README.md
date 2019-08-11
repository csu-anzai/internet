## 系统要求：

支持Debian、Ubuntu、CentOS系统。

## 运行修改SSH的脚本

wget https://raw.githubusercontent.com/AmuyangA/internet/master/ssh/sshport.sh && chmod +x sshport.sh && ./sshport.sh

### 输入端口确认。再打开防火墙端口：

### 如果防火墙使用的iptables（Centos 6），修改端口为8080

iptables -I INPUT -p tcp --dport 8080 -j ACCEPT

service iptables save

service iptables restart

### 如果使用的是firewall（CentOS 7）

firewall-cmd --zone=public --add-port=8080/tcp --permanent

firewall-cmd --reload

## 最后重启ssh生效：

### CentOS系统

service sshd restart

### Debian/Ubuntu系统

service ssh restart

然后就可以使用新端口SSH登录了
