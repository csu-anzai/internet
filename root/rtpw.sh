#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#=================================================
#	System Required: CentOS 6+,Debian7+,Ubuntu12+
#	Description: 设置修改root用户登录密码
#	Version: 1.0
#	Author: 胖波比
#	Project: https://github.com/AmuyangA/
#=================================================

sh_ver="1.1.9"
github="raw.githubusercontent.com/zxlhhyccc/-BBR-/master"

Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[信息]${Font_color_suffix}"
Error="${Red_font_prefix}[错误]${Font_color_suffix}"
Tip="${Green_font_prefix}[注意]${Font_color_suffix}"

# 一键启用root帐号命令
Modify_root(){
        if [[ "${release}" == "centos" || "${release}" == "debian" ]]; then
        # 修改root 密码
        echo "请输入 passwd  命令修改root用户的密码"
        passwd root
        # 启用root密码登陆
        sed -i "s/PermitRootLogin.*/PermitRootLogin yes/g"   /etc/ssh/sshd_config
        sed -i "s/PasswordAuthentication.*/PasswordAuthentication yes/g"   /etc/ssh/sshd_config
        # 重启ssh服务
        systemctl restart sshd	
        elif [[ "${release}" == "ubuntu" ]]; then
        # 修改root 密码
        echo "请输入 passwd  命令修改root用户的密码"
        passwd root
        # 启用root密码登陆
        sed -i "s/#PermitRootLogin.*/PermitRootLogin yes/g"   /etc/ssh/sshd_config
        sed -i "s/PasswordAuthentication.*/PasswordAuthentication yes/g"   /etc/ssh/sshd_config
        # 重启ssh服务
        systemctl restart sshd
        fi
}

#开始菜单
start_menu(){
clear
echo && echo -e " 一键更改root登录密码脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
  -- 胖波比 --
  
————————————root管理————————————
 ${Green_font_prefix}1.${Font_color_suffix} 设置root用户登录
 ${Green_font_prefix}2.${Font_color_suffix} 退出脚本
————————————————————————————————" && echo

echo
read -p " 请输入数字 [1-2]:" num
case "$num" in
	1)
	Modify_root
	;;
	2)
	exit 1
	;;
	*)
	clear
	echo -e "${Error}:请输入正确数字 [0-15]"
	sleep 5s
	start_menu
	;;
esac
}

#############系统检测组件#############

#检查系统
check_sys(){
	if [[ -f /etc/redhat-release ]]; then
		release="centos"
	elif cat /etc/issue | grep -q -E -i "debian"; then
		release="debian"
	elif cat /etc/issue | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
	elif cat /proc/version | grep -q -E -i "debian"; then
		release="debian"
	elif cat /proc/version | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
    fi
}

#检查Linux版本
check_version(){
	if [[ -s /etc/redhat-release ]]; then
		version=`grep -oE  "[0-9.]+" /etc/redhat-release | cut -d . -f 1`
	else
		version=`grep -oE  "[0-9.]+" /etc/issue | cut -d . -f 1`
	fi
	bit=`uname -m`
	if [[ ${bit} = "x86_64" ]]; then
		bit="x64"
	else
		bit="x32"
	fi
}

#############系统检测组件#############
check_sys
check_version
[[ ${release} != "debian" ]] && [[ ${release} != "ubuntu" ]] && [[ ${release} != "centos" ]] && echo -e "${Error} 本脚本不支持当前系统 ${release} !" && exit 1
start_menu
