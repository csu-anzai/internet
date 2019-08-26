#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#==========================================================
#	超级VPN一键设置脚本
#	Description: V2Ray+SSR+BBR+Lotserver+SSH+Root+VPS+Nginx
#	Version: 1.0
#	Author: 胖波比
#	Project: https://github.com/AmuyangA/
#==========================================================

sh_ver="1.0"
github="https://github.com/AmuyangA/internet/"

Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[信息]${Font_color_suffix}"
Error="${Red_font_prefix}[错误]${Font_color_suffix}"
Tip="${Green_font_prefix}[注意]${Font_color_suffix}"

#安装V2ray
install_v2ray(){
	#!/bin/bash
	# Author: Jrohy
	# github: https://github.com/Jrohy/multi-v2ray

	#定时任务北京执行时间(0~23)
	BEIJING_UPDATE_TIME=3

	#记录最开始运行脚本的路径
	BEGIN_PATH=$(pwd)

	#安装方式, 0为全新安装, 1为保留v2ray配置更新
	INSTALL_WAY=0

	#定义操作变量, 0为否, 1为是
	HELP=0
	REMOVE=0
	CHINESE=0
	BASE_SOURCE_PATH="https://raw.githubusercontent.com/Jrohy/multi-v2ray/master"
	CLEAN_IPTABLES_SHELL="$BASE_SOURCE_PATH/v2ray_util/global_setting/clean_iptables.sh"
	BASH_COMPLETION_SHELL="$BASE_SOURCE_PATH/v2ray.bash"
	UTIL_CFG="$BASE_SOURCE_PATH/v2ray_util/util_core/util.cfg"
	UTIL_PATH="/etc/v2ray_util/util.cfg"

	#Centos 临时取消别名
	[[ -f /etc/redhat-release && -z $(echo $SHELL|grep zsh) ]] && unalias -a
	[[ -z $(echo $SHELL|grep zsh) ]] && ENV_FILE=".bashrc" || ENV_FILE=".zshrc"

	#######color code########
	RED="31m"
	GREEN="32m"
	YELLOW="33m"
	BLUE="36m"
	FUCHSIA="35m"

	colorEcho(){
		COLOR=$1
		echo -e "\033[${COLOR}${@:2}\033[0m"
	}

	#######get params#########
	while [[ $# > 0 ]];do
		key="$1"
		case $key in
			--remove)
			REMOVE=1
			;;
			-h|--help)
			HELP=1
			;;
			-k|--keep)
			INSTALL_WAY=1
			colorEcho ${BLUE} "keep v2ray profile to update\n"
			;;
			--zh)
			CHINESE=1
			colorEcho ${BLUE} "安装中文版..\n"
			;;
			*)
					# unknown option
			;;
		esac
		shift # past argument or value
	done
	#############################

	help(){
		echo "bash multi-v2ray.sh [-h|--help] [-k|--keep] [--remove]"
		echo "  -h, --help           Show help"
		echo "  -k, --keep           keep the v2ray config.json to update"
		echo "      --remove         remove v2ray && multi-v2ray"
		echo "                       no params to new install"
		return 0
	}

	removeV2Ray() {
		#卸载V2ray官方脚本
		systemctl stop v2ray  >/dev/null 2>&1
		systemctl disable v2ray  >/dev/null 2>&1
		service v2ray stop  >/dev/null 2>&1
		update-rc.d -f v2ray remove  >/dev/null 2>&1
		rm -rf  /etc/v2ray/  >/dev/null 2>&1
		rm -rf /usr/bin/v2ray  >/dev/null 2>&1
		rm -rf /var/log/v2ray/  >/dev/null 2>&1
		rm -rf /lib/systemd/system/v2ray.service  >/dev/null 2>&1
		rm -rf /etc/init.d/v2ray  >/dev/null 2>&1

		#清理v2ray相关iptable规则
		bash <(curl -L -s $CLEAN_IPTABLES_SHELL)

		#卸载multi-v2ray
		pip uninstall v2ray_util -y
		rm -rf /etc/bash_completion.d/v2ray.bash >/dev/null 2>&1
		rm -rf /usr/local/bin/v2ray >/dev/null 2>&1
		rm -rf /etc/v2ray_util >/dev/null 2>&1

		#删除v2ray定时更新任务
		crontab -l|sed '/SHELL=/d;/v2ray/d' > crontab.txt
		crontab crontab.txt >/dev/null 2>&1
		rm -f crontab.txt >/dev/null 2>&1

		if [[ ${OS} == 'CentOS' || ${OS} == 'Fedora' ]];then
			service crond restart >/dev/null 2>&1
		else
			service cron restart >/dev/null 2>&1
		fi

		#删除multi-v2ray环境变量
		sed -i '/v2ray/d' ~/$ENV_FILE
		source ~/$ENV_FILE

		colorEcho ${GREEN} "uninstall success!"
	}

	closeSELinux() {
		#禁用SELinux
		if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
			sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
			setenforce 0
		fi
	}

	checkSys() {
		#检查是否为Root
		[ $(id -u) != "0" ] && { colorEcho ${RED} "Error: You must be root to run this script"; exit 1; }

		#检查系统信息
		if [[ -e /etc/redhat-release ]];then
			if [[ $(cat /etc/redhat-release | grep Fedora) ]];then
				OS='Fedora'
				PACKAGE_MANAGER='dnf'
			else
				OS='CentOS'
				PACKAGE_MANAGER='yum'
			fi
		elif [[ $(cat /etc/issue | grep Debian) ]];then
			OS='Debian'
			PACKAGE_MANAGER='apt-get'
		elif [[ $(cat /etc/issue | grep Ubuntu) ]];then
			OS='Ubuntu'
			PACKAGE_MANAGER='apt-get'
		elif [[ $(cat /etc/issue | grep Raspbian) ]];then
			OS='Raspbian'
			PACKAGE_MANAGER='apt-get'
		else
			colorEcho ${RED} "Not support OS, Please reinstall OS and retry!"
			exit 1
		fi
	}

	#安装依赖
	installDependent(){
		if [[ ${OS} == 'CentOS' || ${OS} == 'Fedora' ]];then
			${PACKAGE_MANAGER} install ntpdate socat crontabs lsof which -y
		else
			${PACKAGE_MANAGER} update
			${PACKAGE_MANAGER} install ntpdate socat cron lsof -y
		fi

		#install python3 & pip3
		bash <(curl -sL https://git.io/fhqMz)
	}

	#设置定时升级任务
	planUpdate(){
		if [[ $CHINESE == 1 ]];then
			#计算北京时间早上3点时VPS的实际时间
			ORIGIN_TIME_ZONE=$(date -R|awk '{printf"%d",$6}')
			LOCAL_TIME_ZONE=${ORIGIN_TIME_ZONE%00}
			BEIJING_ZONE=8
			DIFF_ZONE=$[$BEIJING_ZONE-$LOCAL_TIME_ZONE]
			LOCAL_TIME=$[$BEIJING_UPDATE_TIME-$DIFF_ZONE]
			if [ $LOCAL_TIME -lt 0 ];then
				LOCAL_TIME=$[24+$LOCAL_TIME]
			elif [ $LOCAL_TIME -ge 24 ];then
				LOCAL_TIME=$[$LOCAL_TIME-24]
			fi
			colorEcho ${BLUE} "beijing time ${BEIJING_UPDATE_TIME}, VPS time: ${LOCAL_TIME}\n"
		else
			LOCAL_TIME=3
		fi
		OLD_CRONTAB=$(crontab -l)
		echo "SHELL=/bin/bash" >> crontab.txt
		echo "${OLD_CRONTAB}" >> crontab.txt
		echo "0 ${LOCAL_TIME} * * * bash <(curl -L -s https://install.direct/go.sh) | tee -a /root/v2rayUpdate.log && service v2ray restart" >> crontab.txt
		crontab crontab.txt
		sleep 1
		if [[ ${OS} == 'CentOS' || ${OS} == 'Fedora' ]];then
			service crond restart
		else
			service cron restart
		fi
		rm -f crontab.txt
		colorEcho ${GREEN} "success open schedule update task: beijing time ${BEIJING_UPDATE_TIME}\n"
	}

	updateProject() {
		local DOMAIN=""

		[[ ! $(type pip3 2>/dev/null) ]] && colorEcho $RED "pip3 no install!" && exit 1

		if [[ -e /usr/local/multi-v2ray/multi-v2ray.conf ]];then
			TEMP_VALUE=$(cat /usr/local/multi-v2ray/multi-v2ray.conf|grep domain|awk 'NR==1')
			DOMAIN=${TEMP_VALUE/*=}
			rm -rf /usr/local/multi-v2ray
		fi

		pip3 install -U v2ray_util

		if [[ -e $UTIL_PATH ]];then
			[[ -z $(cat $UTIL_PATH|grep lang) ]] && echo "lang=en" >> $UTIL_PATH
		else
			mkdir -p /etc/v2ray_util
			curl $UTIL_CFG > $UTIL_PATH
			[[ ! -z $DOMAIN ]] && sed -i "s/^domain.*/domain=${DOMAIN}/g" $UTIL_PATH
		fi

		[[ $CHINESE == 1 ]] && sed -i "s/lang=en/lang=zh/g" $UTIL_PATH

		rm -f /usr/local/bin/v2ray >/dev/null 2>&1
		ln -s $(which v2ray-util) /usr/local/bin/v2ray

		#更新v2ray bash_completion脚本
		curl $BASH_COMPLETION_SHELL > /etc/bash_completion.d/v2ray.bash
		[[ -z $(echo $SHELL|grep zsh) ]] && source /etc/bash_completion.d/v2ray.bash
		
		#安装/更新V2ray主程序
		bash <(curl -L -s https://install.direct/go.sh)
	}

	#时间同步
	timeSync() {
		if [[ ${INSTALL_WAY} == 0 ]];then
			echo -e "${Info} Time Synchronizing.. ${Font}"
			ntpdate pool.ntp.org
			if [[ $? -eq 0 ]];then 
				echo -e "${OK} Time Sync Success ${Font}"
				echo -e "${OK} now: `date -R`${Font}"
				sleep 1
			else
				echo -e "${Error} Time sync fail, please run command to sync:${Font}${Yellow}ntpdate pool.ntp.org${Font}"
			fi
		fi
	}

	profileInit() {

		#清理v2ray模块环境变量
		[[ $(grep v2ray ~/$ENV_FILE) ]] && sed -i '/v2ray/d' ~/$ENV_FILE && source ~/$ENV_FILE

		#解决Python3中文显示问题
		[[ -z $(grep PYTHONIOENCODING=utf-8 ~/$ENV_FILE) ]] && echo "export PYTHONIOENCODING=utf-8" >> ~/$ENV_FILE && source ~/$ENV_FILE

		# 加入v2ray tab补全环境变量
		[[ -z $(echo $SHELL|grep zsh) && -z $(grep v2ray.bash ~/$ENV_FILE) ]] && echo "source /etc/bash_completion.d/v2ray.bash" >> ~/$ENV_FILE && source ~/$ENV_FILE

		#全新安装的新配置
		if [[ ${INSTALL_WAY} == 0 ]];then 
			v2ray new
		else
			v2ray convert
		fi

		bash <(curl -L -s $CLEAN_IPTABLES_SHELL)
		echo ""
	}

	installFinish() {
		#回到原点
		cd ${BEGIN_PATH}
		[[ ${INSTALL_WAY} == 0 ]] && WAY="install" || WAY="update"
		colorEcho  ${GREEN} "multi-v2ray ${WAY} success!\n"
		clear
		v2ray info
		echo -e "please input 'v2ray' command to manage v2ray\n"
	}

	main() {
		[[ ${HELP} == 1 ]] && help && return
		[[ ${REMOVE} == 1 ]] && removeV2Ray && return
		[[ ${INSTALL_WAY} == 0 ]] && colorEcho ${BLUE} "new install\n"
		
		checkSys
		installDependent
		closeSELinux
		timeSync
		
		#设置定时任务
		[[ -z $(crontab -l|grep v2ray) ]] && planUpdate
		updateProject
		profileInit
		service v2ray restart
		installFinish
	}
	main
}

#安装SSR
install_ssr(){
	#!/usr/bin/env bash
	PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
	export PATH
#=================================================================#
#   System Required:  CentOS 6,7, Debian, Ubuntu                  #
#   Description: One click Install ShadowsocksR Server            #
#   Author: Teddysun <i@teddysun.com>                             #
#   Thanks: @breakwa11 <https://twitter.com/breakwa11>            #
#   Intro:  https://shadowsocks.be/9.html                         #
#=================================================================#

	clear
	echo
	echo "#############################################################"
	echo "# One click Install ShadowsocksR Server                     #"
	echo "# Intro: https://shadowsocks.be/9.html                      #"
	echo "# Author: Teddysun <i@teddysun.com>                         #"
	echo "# Github: https://github.com/shadowsocksr/shadowsocksr      #"
	echo "#############################################################"
	echo

	libsodium_file="libsodium-1.0.17"
	libsodium_url="https://github.com/jedisct1/libsodium/releases/download/1.0.17/libsodium-1.0.17.tar.gz"
	shadowsocks_r_file="shadowsocksr-3.2.2"
	shadowsocks_r_url="https://github.com/shadowsocksrr/shadowsocksr/archive/3.2.2.tar.gz"

	#Current folder
	cur_dir=`pwd`
	# Stream Ciphers
	ciphers=(
	none
	aes-256-cfb
	aes-192-cfb
	aes-128-cfb
	aes-256-cfb8
	aes-192-cfb8
	aes-128-cfb8
	aes-256-ctr
	aes-192-ctr
	aes-128-ctr
	chacha20-ietf
	chacha20
	salsa20
	xchacha20
	xsalsa20
	rc4-md5
	)
	# Reference URL:
	# https://github.com/shadowsocksr-rm/shadowsocks-rss/blob/master/ssr.md
	# https://github.com/shadowsocksrr/shadowsocksr/commit/a3cf0254508992b7126ab1151df0c2f10bf82680
	# Protocol
	protocols=(
	origin
	verify_deflate
	auth_sha1_v4
	auth_sha1_v4_compatible
	auth_aes128_md5
	auth_aes128_sha1
	auth_chain_a
	auth_chain_b
	auth_chain_c
	auth_chain_d
	auth_chain_e
	auth_chain_f
	)
	# obfs
	obfs=(
	plain
	http_simple
	http_simple_compatible
	http_post
	http_post_compatible
	tls1.2_ticket_auth
	tls1.2_ticket_auth_compatible
	tls1.2_ticket_fastauth
	tls1.2_ticket_fastauth_compatible
	)
	# Color
	red='\033[0;31m'
	green='\033[0;32m'
	yellow='\033[0;33m'
	plain='\033[0m'

	# Make sure only root can run our script
	[[ $EUID -ne 0 ]] && echo -e "[${red}Error${plain}] This script must be run as root!" && exit 1

	# Disable selinux
	disable_selinux(){
		if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
			sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
			setenforce 0
		fi
	}

	#Check system
	check_sys(){
		local checkType=$1
		local value=$2

		local release=''
		local systemPackage=''

		if [[ -f /etc/redhat-release ]]; then
			release="centos"
			systemPackage="yum"
		elif grep -Eqi "debian|raspbian" /etc/issue; then
			release="debian"
			systemPackage="apt"
		elif grep -Eqi "ubuntu" /etc/issue; then
			release="ubuntu"
			systemPackage="apt"
		elif grep -Eqi "centos|red hat|redhat" /etc/issue; then
			release="centos"
			systemPackage="yum"
		elif grep -Eqi "debian|raspbian" /proc/version; then
			release="debian"
			systemPackage="apt"
		elif grep -Eqi "ubuntu" /proc/version; then
			release="ubuntu"
			systemPackage="apt"
		elif grep -Eqi "centos|red hat|redhat" /proc/version; then
			release="centos"
			systemPackage="yum"
		fi

		if [[ "${checkType}" == "sysRelease" ]]; then
			if [ "${value}" == "${release}" ]; then
				return 0
			else
				return 1
			fi
		elif [[ "${checkType}" == "packageManager" ]]; then
			if [ "${value}" == "${systemPackage}" ]; then
				return 0
			else
				return 1
			fi
		fi
	}

	# Get version
	getversion(){
		if [[ -s /etc/redhat-release ]]; then
			grep -oE  "[0-9.]+" /etc/redhat-release
		else
			grep -oE  "[0-9.]+" /etc/issue
		fi
	}

	# CentOS version
	centosversion(){
		if check_sys sysRelease centos; then
			local code=$1
			local version="$(getversion)"
			local main_ver=${version%%.*}
			if [ "$main_ver" == "$code" ]; then
				return 0
			else
				return 1
			fi
		else
			return 1
		fi
	}

	# Get public IP address
	get_ip(){
		local IP=$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )
		[ -z ${IP} ] && IP=$( wget -qO- -t1 -T2 ipv4.icanhazip.com )
		[ -z ${IP} ] && IP=$( wget -qO- -t1 -T2 ipinfo.io/ip )
		[ ! -z ${IP} ] && echo ${IP} || echo
	}

	get_char(){
		SAVEDSTTY=`stty -g`
		stty -echo
		stty cbreak
		dd if=/dev/tty bs=1 count=1 2> /dev/null
		stty -raw
		stty echo
		stty $SAVEDSTTY
	}

	# Pre-installation settings
	pre_install(){
		if check_sys packageManager yum || check_sys packageManager apt; then
			# Not support CentOS 5
			if centosversion 5; then
				echo -e "$[{red}Error${plain}] Not supported CentOS 5, please change to CentOS 6+/Debian 7+/Ubuntu 12+ and try again."
				exit 1
			fi
		else
			echo -e "[${red}Error${plain}] Your OS is not supported. please change OS to CentOS/Debian/Ubuntu and try again."
			exit 1
		fi
		# Set ShadowsocksR config password
		echo "Please enter password for ShadowsocksR:"
		read -p "(Default password: teddysun.com):" shadowsockspwd
		[ -z "${shadowsockspwd}" ] && shadowsockspwd="teddysun.com"
		echo
		echo "---------------------------"
		echo "password = ${shadowsockspwd}"
		echo "---------------------------"
		echo
		# Set ShadowsocksR config port
		while true
		do
		dport=$(shuf -i 9000-19999 -n 1)
		echo -e "Please enter a port for ShadowsocksR [1-65535]"
		read -p "(Default port: ${dport}):" shadowsocksport
		[ -z "${shadowsocksport}" ] && shadowsocksport=${dport}
		expr ${shadowsocksport} + 1 &>/dev/null
		if [ $? -eq 0 ]; then
			if [ ${shadowsocksport} -ge 1 ] && [ ${shadowsocksport} -le 65535 ] && [ ${shadowsocksport:0:1} != 0 ]; then
				echo
				echo "---------------------------"
				echo "port = ${shadowsocksport}"
				echo "---------------------------"
				echo
				break
			fi
		fi
		echo -e "[${red}Error${plain}] Please enter a correct number [1-65535]"
		done

		# Set shadowsocksR config stream ciphers
		while true
		do
		echo -e "Please select stream cipher for ShadowsocksR:"
		for ((i=1;i<=${#ciphers[@]};i++ )); do
			hint="${ciphers[$i-1]}"
			echo -e "${green}${i}${plain}) ${hint}"
		done
		read -p "Which cipher you'd select(Default: ${ciphers[1]}):" pick
		[ -z "$pick" ] && pick=2
		expr ${pick} + 1 &>/dev/null
		if [ $? -ne 0 ]; then
			echo -e "[${red}Error${plain}] Please enter a number"
			continue
		fi
		if [[ "$pick" -lt 1 || "$pick" -gt ${#ciphers[@]} ]]; then
			echo -e "[${red}Error${plain}] Please enter a number between 1 and ${#ciphers[@]}"
			continue
		fi
		shadowsockscipher=${ciphers[$pick-1]}
		echo
		echo "---------------------------"
		echo "cipher = ${shadowsockscipher}"
		echo "---------------------------"
		echo
		break
		done

		# Set shadowsocksR config protocol
		while true
		do
		echo -e "Please select protocol for ShadowsocksR:"
		for ((i=1;i<=${#protocols[@]};i++ )); do
			hint="${protocols[$i-1]}"
			echo -e "${green}${i}${plain}) ${hint}"
		done
		read -p "Which protocol you'd select(Default: ${protocols[0]}):" protocol
		[ -z "$protocol" ] && protocol=1
		expr ${protocol} + 1 &>/dev/null
		if [ $? -ne 0 ]; then
			echo -e "[${red}Error${plain}] Input error, please input a number"
			continue
		fi
		if [[ "$protocol" -lt 1 || "$protocol" -gt ${#protocols[@]} ]]; then
			echo -e "[${red}Error${plain}] Input error, please input a number between 1 and ${#protocols[@]}"
			continue
		fi
		shadowsockprotocol=${protocols[$protocol-1]}
		echo
		echo "---------------------------"
		echo "protocol = ${shadowsockprotocol}"
		echo "---------------------------"
		echo
		break
		done

		# Set shadowsocksR config obfs
		while true
		do
		echo -e "Please select obfs for ShadowsocksR:"
		for ((i=1;i<=${#obfs[@]};i++ )); do
			hint="${obfs[$i-1]}"
			echo -e "${green}${i}${plain}) ${hint}"
		done
		read -p "Which obfs you'd select(Default: ${obfs[0]}):" r_obfs
		[ -z "$r_obfs" ] && r_obfs=1
		expr ${r_obfs} + 1 &>/dev/null
		if [ $? -ne 0 ]; then
			echo -e "[${red}Error${plain}] Input error, please input a number"
			continue
		fi
		if [[ "$r_obfs" -lt 1 || "$r_obfs" -gt ${#obfs[@]} ]]; then
			echo -e "[${red}Error${plain}] Input error, please input a number between 1 and ${#obfs[@]}"
			continue
		fi
		shadowsockobfs=${obfs[$r_obfs-1]}
		echo
		echo "---------------------------"
		echo "obfs = ${shadowsockobfs}"
		echo "---------------------------"
		echo
		break
		done

		echo
		echo "Press any key to start...or Press Ctrl+C to cancel"
		char=`get_char`
		# Install necessary dependencies
		if check_sys packageManager yum; then
			yum install -y python python-devel python-setuptools openssl openssl-devel curl wget unzip gcc automake autoconf make libtool
		elif check_sys packageManager apt; then
			apt-get -y update
			apt-get -y install python python-dev python-setuptools openssl libssl-dev curl wget unzip gcc automake autoconf make libtool
		fi
		cd ${cur_dir}
	}

	# Download files
	download_files(){
		# Download libsodium file
		if ! wget --no-check-certificate -O ${libsodium_file}.tar.gz ${libsodium_url}; then
			echo -e "[${red}Error${plain}] Failed to download ${libsodium_file}.tar.gz!"
			exit 1
		fi
		# Download ShadowsocksR file
		if ! wget --no-check-certificate -O ${shadowsocks_r_file}.tar.gz ${shadowsocks_r_url}; then
			echo -e "[${red}Error${plain}] Failed to download ShadowsocksR file!"
			exit 1
		fi
		# Download ShadowsocksR init script
		if check_sys packageManager yum; then
			if ! wget --no-check-certificate https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocksR -O /etc/init.d/shadowsocks; then
				echo -e "[${red}Error${plain}] Failed to download ShadowsocksR chkconfig file!"
				exit 1
			fi
		elif check_sys packageManager apt; then
			if ! wget --no-check-certificate https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocksR-debian -O /etc/init.d/shadowsocks; then
				echo -e "[${red}Error${plain}] Failed to download ShadowsocksR chkconfig file!"
				exit 1
			fi
		fi
	}

	# Firewall set
	firewall_set(){
		echo -e "[${green}Info${plain}] firewall set start..."
		if centosversion 6; then
			/etc/init.d/iptables status > /dev/null 2>&1
			if [ $? -eq 0 ]; then
				iptables -L -n | grep -i ${shadowsocksport} > /dev/null 2>&1
				if [ $? -ne 0 ]; then
					iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${shadowsocksport} -j ACCEPT
					iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${shadowsocksport} -j ACCEPT
					/etc/init.d/iptables save
					/etc/init.d/iptables restart
				else
					echo -e "[${green}Info${plain}] port ${shadowsocksport} has been set up."
				fi
			else
				echo -e "[${yellow}Warning${plain}] iptables looks like shutdown or not installed, please manually set it if necessary."
			fi
		elif centosversion 7; then
			systemctl status firewalld > /dev/null 2>&1
			if [ $? -eq 0 ]; then
				default_zone=$(firewall-cmd --get-default-zone)
				firewall-cmd --permanent --zone=${default_zone} --add-port=${shadowsocksport}/tcp
				firewall-cmd --permanent --zone=${default_zone} --add-port=${shadowsocksport}/udp
				firewall-cmd --reload
			else
				echo -e "[${yellow}Warning${plain}] firewalld looks like not running or not installed, please enable port ${shadowsocksport} manually if necessary."
			fi
		fi
		echo -e "[${green}Info${plain}] firewall set completed..."
	}

	# Config ShadowsocksR
	config_shadowsocks(){
		cat > /etc/shadowsocks.json<<-EOF
	{
		"server":"0.0.0.0",
		"server_ipv6":"[::]",
		"server_port":${shadowsocksport},
		"local_address":"127.0.0.1",
		"local_port":1080,
		"password":"${shadowsockspwd}",
		"timeout":120,
		"method":"${shadowsockscipher}",
		"protocol":"${shadowsockprotocol}",
		"protocol_param":"",
		"obfs":"${shadowsockobfs}",
		"obfs_param":"",
		"redirect":"",
		"dns_ipv6":false,
		"fast_open":false,
		"workers":1
	}
	EOF
	}

	# Install ShadowsocksR
	install(){
		# Install libsodium
		if [ ! -f /usr/lib/libsodium.a ]; then
			cd ${cur_dir}
			tar zxf ${libsodium_file}.tar.gz
			cd ${libsodium_file}
			./configure --prefix=/usr && make && make install
			if [ $? -ne 0 ]; then
				echo -e "[${red}Error${plain}] libsodium install failed!"
				install_cleanup
				exit 1
			fi
		fi

		ldconfig
		# Install ShadowsocksR
		cd ${cur_dir}
		tar zxf ${shadowsocks_r_file}.tar.gz
		mv ${shadowsocks_r_file}/shadowsocks /usr/local/
		if [ -f /usr/local/shadowsocks/server.py ]; then
			chmod +x /etc/init.d/shadowsocks
			if check_sys packageManager yum; then
				chkconfig --add shadowsocks
				chkconfig shadowsocks on
			elif check_sys packageManager apt; then
				update-rc.d -f shadowsocks defaults
			fi
			/etc/init.d/shadowsocks start

			clear
			echo
			echo -e "Congratulations, ShadowsocksR server install completed!"
			echo -e "Your Server IP        : \033[41;37m $(get_ip) \033[0m"
			echo -e "Your Server Port      : \033[41;37m ${shadowsocksport} \033[0m"
			echo -e "Your Password         : \033[41;37m ${shadowsockspwd} \033[0m"
			echo -e "Your Protocol         : \033[41;37m ${shadowsockprotocol} \033[0m"
			echo -e "Your obfs             : \033[41;37m ${shadowsockobfs} \033[0m"
			echo -e "Your Encryption Method: \033[41;37m ${shadowsockscipher} \033[0m"
			echo
			echo "Welcome to visit:https://shadowsocks.be/9.html"
			echo "Enjoy it!"
			echo
		else
			echo "ShadowsocksR install failed, please Email to Teddysun <i@teddysun.com> and contact"
			install_cleanup
			exit 1
		fi
	}

	# Install cleanup
	install_cleanup(){
		cd ${cur_dir}
		rm -rf ${shadowsocks_r_file}.tar.gz ${shadowsocks_r_file} ${libsodium_file}.tar.gz ${libsodium_file}
	}


	# Uninstall ShadowsocksR
	uninstall_shadowsocksr(){
		printf "Are you sure uninstall ShadowsocksR? (y/n)"
		printf "\n"
		read -p "(Default: n):" answer
		[ -z ${answer} ] && answer="n"
		if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
			/etc/init.d/shadowsocks status > /dev/null 2>&1
			if [ $? -eq 0 ]; then
				/etc/init.d/shadowsocks stop
			fi
			if check_sys packageManager yum; then
				chkconfig --del shadowsocks
			elif check_sys packageManager apt; then
				update-rc.d -f shadowsocks remove
			fi
			rm -f /etc/shadowsocks.json
			rm -f /etc/init.d/shadowsocks
			rm -f /var/log/shadowsocks.log
			rm -rf /usr/local/shadowsocks
			echo "ShadowsocksR uninstall success!"
		else
			echo
			echo "uninstall cancelled, nothing to do..."
			echo
		fi
	}

	# Install ShadowsocksR
	install_shadowsocksr(){
		disable_selinux
		pre_install
		download_files
		config_shadowsocks
		if check_sys packageManager yum; then
			firewall_set
		fi
		install
		install_cleanup
	}

	# Initialization step
	action=$1
	[ -z $1 ] && action=install
	case "$action" in
		install|uninstall)
			${action}_shadowsocksr
			;;
		*)
			echo "Arguments error! [${action}]"
			echo "Usage: `basename $0` [install|uninstall]"
			;;
	esac
}

#安装BBR或锐速
install_bbr(){
	#!/usr/bin/env bash
	PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
	export PATH

#=================================================
#	System Required: CentOS 6/7,Debian 8/9,Ubuntu 16+
#	Description: BBR+BBR魔改版+BBRplus+Lotserver
#	Version: 1.3.2
#	Author: 千影,cx9208
#	Blog: https://www.94ish.me/
#=================================================

	sh_ver="1.3.2"
	github="raw.githubusercontent.com/chiakge/Linux-NetSpeed/master"

	Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
	Info="${Green_font_prefix}[信息]${Font_color_suffix}"
	Error="${Red_font_prefix}[错误]${Font_color_suffix}"
	Tip="${Green_font_prefix}[注意]${Font_color_suffix}"

	#安装BBR内核
	installbbr(){
		kernel_version="4.11.8"
		if [[ "${release}" == "centos" ]]; then
			rpm --import http://${github}/bbr/${release}/RPM-GPG-KEY-elrepo.org
			yum install -y http://${github}/bbr/${release}/${version}/${bit}/kernel-ml-${kernel_version}.rpm
			yum remove -y kernel-headers
			yum install -y http://${github}/bbr/${release}/${version}/${bit}/kernel-ml-headers-${kernel_version}.rpm
			yum install -y http://${github}/bbr/${release}/${version}/${bit}/kernel-ml-devel-${kernel_version}.rpm
		elif [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
			mkdir bbr && cd bbr
			wget http://security.debian.org/debian-security/pool/updates/main/o/openssl/libssl1.0.0_1.0.1t-1+deb8u10_amd64.deb
			wget -N --no-check-certificate http://${github}/bbr/debian-ubuntu/linux-headers-${kernel_version}-all.deb
			wget -N --no-check-certificate http://${github}/bbr/debian-ubuntu/${bit}/linux-headers-${kernel_version}.deb
			wget -N --no-check-certificate http://${github}/bbr/debian-ubuntu/${bit}/linux-image-${kernel_version}.deb
		
			dpkg -i libssl1.0.0_1.0.1t-1+deb8u10_amd64.deb
			dpkg -i linux-headers-${kernel_version}-all.deb
			dpkg -i linux-headers-${kernel_version}.deb
			dpkg -i linux-image-${kernel_version}.deb
			cd .. && rm -rf bbr
		fi
		detele_kernel
		BBR_grub
		echo -e "${Tip} 重启VPS后，请重新运行脚本开启${Red_font_prefix}BBR/BBR魔改版${Font_color_suffix}"
		stty erase '^H' && read -p "需要重启VPS后，才能开启BBR/BBR魔改版，是否现在重启 ? [Y/n] :" yn
		[ -z "${yn}" ] && yn="y"
		if [[ $yn == [Yy] ]]; then
			echo -e "${Info} VPS 重启中..."
			reboot
		fi
	}

	#安装BBRplus内核
	installbbrplus(){
		kernel_version="4.14.129-bbrplus"
		if [[ "${release}" == "centos" ]]; then
			wget -N --no-check-certificate https://${github}/bbrplus/${release}/${version}/kernel-${kernel_version}.rpm
			yum install -y kernel-${kernel_version}.rpm
			rm -f kernel-${kernel_version}.rpm
			kernel_version="4.14.129_bbrplus" #fix a bug
		elif [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
			mkdir bbrplus && cd bbrplus
			wget -N --no-check-certificate http://${github}/bbrplus/debian-ubuntu/${bit}/linux-headers-${kernel_version}.deb
			wget -N --no-check-certificate http://${github}/bbrplus/debian-ubuntu/${bit}/linux-image-${kernel_version}.deb
			dpkg -i linux-headers-${kernel_version}.deb
			dpkg -i linux-image-${kernel_version}.deb
			cd .. && rm -rf bbrplus
		fi
		detele_kernel
		BBR_grub
		echo -e "${Tip} 重启VPS后，请重新运行脚本开启${Red_font_prefix}BBRplus${Font_color_suffix}"
		stty erase '^H' && read -p "需要重启VPS后，才能开启BBRplus，是否现在重启 ? [Y/n] :" yn
		[ -z "${yn}" ] && yn="y"
		if [[ $yn == [Yy] ]]; then
			echo -e "${Info} VPS 重启中..."
			reboot
		fi
	}

	#安装Lotserver内核
	installlot(){
		if [[ "${release}" == "centos" ]]; then
			rpm --import http://${github}/lotserver/${release}/RPM-GPG-KEY-elrepo.org
			yum remove -y kernel-firmware
			yum install -y http://${github}/lotserver/${release}/${version}/${bit}/kernel-firmware-${kernel_version}.rpm
			yum install -y http://${github}/lotserver/${release}/${version}/${bit}/kernel-${kernel_version}.rpm
			yum remove -y kernel-headers
			yum install -y http://${github}/lotserver/${release}/${version}/${bit}/kernel-headers-${kernel_version}.rpm
			yum install -y http://${github}/lotserver/${release}/${version}/${bit}/kernel-devel-${kernel_version}.rpm
		elif [[ "${release}" == "ubuntu" ]]; then
			bash <(wget --no-check-certificate -qO- "http://${github}/Debian_Kernel.sh")
		elif [[ "${release}" == "debian" ]]; then
			bash <(wget --no-check-certificate -qO- "http://${github}/Debian_Kernel.sh")
		fi
		detele_kernel
		BBR_grub
		echo -e "${Tip} 重启VPS后，请重新运行脚本开启${Red_font_prefix}Lotserver${Font_color_suffix}"
		stty erase '^H' && read -p "需要重启VPS后，才能开启Lotserver，是否现在重启 ? [Y/n] :" yn
		[ -z "${yn}" ] && yn="y"
		if [[ $yn == [Yy] ]]; then
			echo -e "${Info} VPS 重启中..."
			reboot
		fi
	}

	#启用BBR
	startbbr(){
		remove_all
		echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
		sysctl -p
		echo -e "${Info}BBR启动成功！"
	}

	#启用BBRplus
	startbbrplus(){
		remove_all
		echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_congestion_control=bbrplus" >> /etc/sysctl.conf
		sysctl -p
		echo -e "${Info}BBRplus启动成功！"
	}

	#编译并启用BBR魔改
	startbbrmod(){
		remove_all
		if [[ "${release}" == "centos" ]]; then
			yum install -y make gcc
			mkdir bbrmod && cd bbrmod
			wget -N --no-check-certificate http://${github}/bbr/tcp_tsunami.c
			echo "obj-m:=tcp_tsunami.o" > Makefile
			make -C /lib/modules/$(uname -r)/build M=`pwd` modules CC=/usr/bin/gcc
			chmod +x ./tcp_tsunami.ko
			cp -rf ./tcp_tsunami.ko /lib/modules/$(uname -r)/kernel/net/ipv4
			insmod tcp_tsunami.ko
			depmod -a
		else
			apt-get update
			if [[ "${release}" == "ubuntu" && "${version}" = "14" ]]; then
				apt-get -y install build-essential
				apt-get -y install software-properties-common
				add-apt-repository ppa:ubuntu-toolchain-r/test -y
				apt-get update
			fi
			apt-get -y install make gcc
			mkdir bbrmod && cd bbrmod
			wget -N --no-check-certificate http://${github}/bbr/tcp_tsunami.c
			echo "obj-m:=tcp_tsunami.o" > Makefile
			ln -s /usr/bin/gcc /usr/bin/gcc-4.9
			make -C /lib/modules/$(uname -r)/build M=`pwd` modules CC=/usr/bin/gcc-4.9
			install tcp_tsunami.ko /lib/modules/$(uname -r)/kernel
			cp -rf ./tcp_tsunami.ko /lib/modules/$(uname -r)/kernel/net/ipv4
			depmod -a
		fi
		

		echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_congestion_control=tsunami" >> /etc/sysctl.conf
		sysctl -p
		cd .. && rm -rf bbrmod
		echo -e "${Info}魔改版BBR启动成功！"
	}

	#编译并启用BBR魔改
	startbbrmod_nanqinlang(){
		remove_all
		if [[ "${release}" == "centos" ]]; then
			yum install -y make gcc
			mkdir bbrmod && cd bbrmod
			wget -N --no-check-certificate https://raw.githubusercontent.com/chiakge/Linux-NetSpeed/master/bbr/centos/tcp_nanqinlang.c
			echo "obj-m := tcp_nanqinlang.o" > Makefile
			make -C /lib/modules/$(uname -r)/build M=`pwd` modules CC=/usr/bin/gcc
			chmod +x ./tcp_nanqinlang.ko
			cp -rf ./tcp_nanqinlang.ko /lib/modules/$(uname -r)/kernel/net/ipv4
			insmod tcp_nanqinlang.ko
			depmod -a
		else
			apt-get update
			if [[ "${release}" == "ubuntu" && "${version}" = "14" ]]; then
				apt-get -y install build-essential
				apt-get -y install software-properties-common
				add-apt-repository ppa:ubuntu-toolchain-r/test -y
				apt-get update
			fi
			apt-get -y install make gcc-4.9
			mkdir bbrmod && cd bbrmod
			wget -N --no-check-certificate https://raw.githubusercontent.com/chiakge/Linux-NetSpeed/master/bbr/tcp_nanqinlang.c
			echo "obj-m := tcp_nanqinlang.o" > Makefile
			make -C /lib/modules/$(uname -r)/build M=`pwd` modules CC=/usr/bin/gcc-4.9
			install tcp_nanqinlang.ko /lib/modules/$(uname -r)/kernel
			cp -rf ./tcp_nanqinlang.ko /lib/modules/$(uname -r)/kernel/net/ipv4
			depmod -a
		fi
		

		echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_congestion_control=nanqinlang" >> /etc/sysctl.conf
		sysctl -p
		echo -e "${Info}魔改版BBR启动成功！"
	}

	#启用Lotserver
	startlotserver(){
		remove_all
		if [[ "${release}" == "centos" ]]; then
			yum install ethtool
		else
			apt-get update
			apt-get install ethtool
		fi
		bash <(wget --no-check-certificate -qO- https://raw.githubusercontent.com/chiakge/lotServer/master/Install.sh) install
		sed -i '/advinacc/d' /appex/etc/config
		sed -i '/maxmode/d' /appex/etc/config
		echo -e "advinacc=\"1\"
	maxmode=\"1\"">>/appex/etc/config
		/appex/bin/lotServer.sh restart
		start_menu_bbr
	}

	#卸载全部加速
	remove_all(){
		rm -rf bbrmod
		sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
		sed -i '/fs.file-max/d' /etc/sysctl.conf
		sed -i '/net.core.rmem_max/d' /etc/sysctl.conf
		sed -i '/net.core.wmem_max/d' /etc/sysctl.conf
		sed -i '/net.core.rmem_default/d' /etc/sysctl.conf
		sed -i '/net.core.wmem_default/d' /etc/sysctl.conf
		sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf
		sed -i '/net.core.somaxconn/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_tw_reuse/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_tw_recycle/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_fin_timeout/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_keepalive_time/d' /etc/sysctl.conf
		sed -i '/net.ipv4.ip_local_port_range/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_max_syn_backlog/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_max_tw_buckets/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_rmem/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_wmem/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_mtu_probing/d' /etc/sysctl.conf
		sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
		sed -i '/fs.inotify.max_user_instances/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_fin_timeout/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_tw_reuse/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_max_syn_backlog/d' /etc/sysctl.conf
		sed -i '/net.ipv4.ip_local_port_range/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_max_tw_buckets/d' /etc/sysctl.conf
		sed -i '/net.ipv4.route.gc_timeout/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_synack_retries/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_syn_retries/d' /etc/sysctl.conf
		sed -i '/net.core.somaxconn/d' /etc/sysctl.conf
		sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_timestamps/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_max_orphans/d' /etc/sysctl.conf
		if [[ -e /appex/bin/lotServer.sh ]]; then
			bash <(wget --no-check-certificate -qO- https://github.com/MoeClub/lotServer/raw/master/Install.sh) uninstall
		fi
		clear
		echo -e "${Info}:清除加速完成。"
		sleep 1s
	}

	#优化系统配置
	optimizing_system(){
		sed -i '/fs.file-max/d' /etc/sysctl.conf
		sed -i '/fs.inotify.max_user_instances/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_fin_timeout/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_tw_reuse/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_max_syn_backlog/d' /etc/sysctl.conf
		sed -i '/net.ipv4.ip_local_port_range/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_max_tw_buckets/d' /etc/sysctl.conf
		sed -i '/net.ipv4.route.gc_timeout/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_synack_retries/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_syn_retries/d' /etc/sysctl.conf
		sed -i '/net.core.somaxconn/d' /etc/sysctl.conf
		sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_timestamps/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_max_orphans/d' /etc/sysctl.conf
		sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
		echo "fs.file-max = 1000000
	fs.inotify.max_user_instances = 8192
	net.ipv4.tcp_syncookies = 1
	net.ipv4.tcp_fin_timeout = 30
	net.ipv4.tcp_tw_reuse = 1
	net.ipv4.ip_local_port_range = 1024 65000
	net.ipv4.tcp_max_syn_backlog = 16384
	net.ipv4.tcp_max_tw_buckets = 6000
	net.ipv4.route.gc_timeout = 100
	net.ipv4.tcp_syn_retries = 1
	net.ipv4.tcp_synack_retries = 1
	net.core.somaxconn = 32768
	net.core.netdev_max_backlog = 32768
	net.ipv4.tcp_timestamps = 0
	net.ipv4.tcp_max_orphans = 32768
	# forward ipv4
	net.ipv4.ip_forward = 1">>/etc/sysctl.conf
		sysctl -p
		echo "*               soft    nofile           1000000
	*               hard    nofile          1000000">/etc/security/limits.conf
		echo "ulimit -SHn 1000000">>/etc/profile
		read -p "需要重启VPS后，才能生效系统优化配置，是否现在重启 ? [Y/n] :" yn
		[ -z "${yn}" ] && yn="y"
		if [[ $yn == [Yy] ]]; then
			echo -e "${Info} VPS 重启中..."
			reboot
		fi
	}
	#更新脚本
	Update_Shell(){
		echo -e "当前版本为 [ ${sh_ver} ]，开始检测最新版本..."
		sh_new_ver=$(wget --no-check-certificate -qO- "http://${github}/tcp.sh"|grep 'sh_ver="'|awk -F "=" '{print $NF}'|sed 's/\"//g'|head -1)
		[[ -z ${sh_new_ver} ]] && echo -e "${Error} 检测最新版本失败 !" && start_menu_bbr
		if [[ ${sh_new_ver} != ${sh_ver} ]]; then
			echo -e "发现新版本[ ${sh_new_ver} ]，是否更新？[Y/n]"
			read -p "(默认: y):" yn
			[[ -z "${yn}" ]] && yn="y"
			if [[ ${yn} == [Yy] ]]; then
				wget -N --no-check-certificate http://${github}/tcp.sh && chmod +x tcp.sh
				echo -e "脚本已更新为最新版本[ ${sh_new_ver} ] !"
			else
				echo && echo "	已取消..." && echo
			fi
		else
			echo -e "当前已是最新版本[ ${sh_new_ver} ] !"
			sleep 5s
		fi
	}

	#开始菜单
	start_menu_bbr(){
	clear
	echo && echo -e " TCP加速 一键安装管理脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
	  -- 就是爱生活 | 94ish.me --
	  
	 ${Green_font_prefix}0.${Font_color_suffix} 升级脚本
	————————————内核管理————————————
	 ${Green_font_prefix}1.${Font_color_suffix} 安装 BBR/BBR魔改版内核
	 ${Green_font_prefix}2.${Font_color_suffix} 安装 BBRplus版内核 
	 ${Green_font_prefix}3.${Font_color_suffix} 安装 Lotserver(锐速)内核
	————————————加速管理————————————
	 ${Green_font_prefix}4.${Font_color_suffix} 使用BBR加速
	 ${Green_font_prefix}5.${Font_color_suffix} 使用BBR魔改版加速
	 ${Green_font_prefix}6.${Font_color_suffix} 使用暴力BBR魔改版加速(不支持部分系统)
	 ${Green_font_prefix}7.${Font_color_suffix} 使用BBRplus版加速
	 ${Green_font_prefix}8.${Font_color_suffix} 使用Lotserver(锐速)加速
	————————————杂项管理————————————
	 ${Green_font_prefix}9.${Font_color_suffix} 卸载全部加速
	 ${Green_font_prefix}10.${Font_color_suffix} 系统配置优化
	 ${Green_font_prefix}11.${Font_color_suffix} 退出脚本
	————————————————————————————————" && echo

		check_status
		if [[ ${kernel_status} == "noinstall" ]]; then
			echo -e " 当前状态: ${Green_font_prefix}未安装${Font_color_suffix} 加速内核 ${Red_font_prefix}请先安装内核${Font_color_suffix}"
		else
			echo -e " 当前状态: ${Green_font_prefix}已安装${Font_color_suffix} ${_font_prefix}${kernel_status}${Font_color_suffix} 加速内核 , ${Green_font_prefix}${run_status}${Font_color_suffix}"
			
		fi
	echo
	read -p " 请输入数字 [0-11]:" num
	case "$num" in
		0)
		Update_Shell
		;;
		1)
		check_sys_bbr
		;;
		2)
		check_sys_bbrplus
		;;
		3)
		check_sys_Lotsever
		;;
		4)
		startbbr
		;;
		5)
		startbbrmod
		;;
		6)
		startbbrmod_nanqinlang
		;;
		7)
		startbbrplus
		;;
		8)
		startlotserver
		;;
		9)
		remove_all
		;;
		10)
		optimizing_system
		;;
		11)
		exit 1
		;;
		*)
		clear
		echo -e "${Error}:请输入正确数字 [0-11]"
		sleep 5s
		start_menu_bbr
		;;
	esac
	}
	#############内核管理组件#############

	#删除多余内核
	detele_kernel(){
		if [[ "${release}" == "centos" ]]; then
			rpm_total=`rpm -qa | grep kernel | grep -v "${kernel_version}" | grep -v "noarch" | wc -l`
			if [ "${rpm_total}" > "1" ]; then
				echo -e "检测到 ${rpm_total} 个其余内核，开始卸载..."
				for((integer = 1; integer <= ${rpm_total}; integer++)); do
					rpm_del=`rpm -qa | grep kernel | grep -v "${kernel_version}" | grep -v "noarch" | head -${integer}`
					echo -e "开始卸载 ${rpm_del} 内核..."
					rpm --nodeps -e ${rpm_del}
					echo -e "卸载 ${rpm_del} 内核卸载完成，继续..."
				done
				echo --nodeps -e "内核卸载完毕，继续..."
			else
				echo -e " 检测到 内核 数量不正确，请检查 !" && exit 1
			fi
		elif [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
			deb_total=`dpkg -l | grep linux-image | awk '{print $2}' | grep -v "${kernel_version}" | wc -l`
			if [ "${deb_total}" > "1" ]; then
				echo -e "检测到 ${deb_total} 个其余内核，开始卸载..."
				for((integer = 1; integer <= ${deb_total}; integer++)); do
					deb_del=`dpkg -l|grep linux-image | awk '{print $2}' | grep -v "${kernel_version}" | head -${integer}`
					echo -e "开始卸载 ${deb_del} 内核..."
					apt-get purge -y ${deb_del}
					echo -e "卸载 ${deb_del} 内核卸载完成，继续..."
				done
				echo -e "内核卸载完毕，继续..."
			else
				echo -e " 检测到 内核 数量不正确，请检查 !" && exit 1
			fi
		fi
	}

	#更新引导
	BBR_grub(){
		if [[ "${release}" == "centos" ]]; then
			if [[ ${version} = "6" ]]; then
				if [ ! -f "/boot/grub/grub.conf" ]; then
					echo -e "${Error} /boot/grub/grub.conf 找不到，请检查."
					exit 1
				fi
				sed -i 's/^default=.*/default=0/g' /boot/grub/grub.conf
			elif [[ ${version} = "7" ]]; then
				if [ ! -f "/boot/grub2/grub.cfg" ]; then
					echo -e "${Error} /boot/grub2/grub.cfg 找不到，请检查."
					exit 1
				fi
				grub2-set-default 0
			fi
		elif [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
			/usr/sbin/update-grub
		fi
	}

	#############内核管理组件#############



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

	#检查安装bbr的系统要求
	check_sys_bbr(){
		check_version
		if [[ "${release}" == "centos" ]]; then
			if [[ ${version} -ge "6" ]]; then
				installbbr
			else
				echo -e "${Error} BBR内核不支持当前系统 ${release} ${version} ${bit} !" && exit 1
			fi
		elif [[ "${release}" == "debian" ]]; then
			if [[ ${version} -ge "8" ]]; then
				installbbr
			else
				echo -e "${Error} BBR内核不支持当前系统 ${release} ${version} ${bit} !" && exit 1
			fi
		elif [[ "${release}" == "ubuntu" ]]; then
			if [[ ${version} -ge "14" ]]; then
				installbbr
			else
				echo -e "${Error} BBR内核不支持当前系统 ${release} ${version} ${bit} !" && exit 1
			fi
		else
			echo -e "${Error} BBR内核不支持当前系统 ${release} ${version} ${bit} !" && exit 1
		fi
	}

	check_sys_bbrplus(){
		check_version
		if [[ "${release}" == "centos" ]]; then
			if [[ ${version} -ge "6" ]]; then
				installbbrplus
			else
				echo -e "${Error} BBRplus内核不支持当前系统 ${release} ${version} ${bit} !" && exit 1
			fi
		elif [[ "${release}" == "debian" ]]; then
			if [[ ${version} -ge "8" ]]; then
				installbbrplus
			else
				echo -e "${Error} BBRplus内核不支持当前系统 ${release} ${version} ${bit} !" && exit 1
			fi
		elif [[ "${release}" == "ubuntu" ]]; then
			if [[ ${version} -ge "14" ]]; then
				installbbrplus
			else
				echo -e "${Error} BBRplus内核不支持当前系统 ${release} ${version} ${bit} !" && exit 1
			fi
		else
			echo -e "${Error} BBRplus内核不支持当前系统 ${release} ${version} ${bit} !" && exit 1
		fi
	}


	#检查安装Lotsever的系统要求
	check_sys_Lotsever(){
		check_version
		if [[ "${release}" == "centos" ]]; then
			if [[ ${version} == "6" ]]; then
				kernel_version="2.6.32-504"
				installlot
			elif [[ ${version} == "7" ]]; then
				yum -y install net-tools
				kernel_version="3.10.0-327"
				installlot
			else
				echo -e "${Error} Lotsever不支持当前系统 ${release} ${version} ${bit} !" && exit 1
			fi
		elif [[ "${release}" == "debian" ]]; then
			if [[ ${version} = "7" || ${version} = "8" ]]; then
				if [[ ${bit} == "x64" ]]; then
					kernel_version="3.16.0-4"
					installlot
				elif [[ ${bit} == "x32" ]]; then
					kernel_version="3.2.0-4"
					installlot
				fi
			elif [[ ${version} = "9" ]]; then
				if [[ ${bit} == "x64" ]]; then
					kernel_version="4.9.0-4"
					installlot
				fi
			else
				echo -e "${Error} Lotsever不支持当前系统 ${release} ${version} ${bit} !" && exit 1
			fi
		elif [[ "${release}" == "ubuntu" ]]; then
			if [[ ${version} -ge "12" ]]; then
				if [[ ${bit} == "x64" ]]; then
					kernel_version="4.4.0-47"
					installlot
				elif [[ ${bit} == "x32" ]]; then
					kernel_version="3.13.0-29"
					installlot
				fi
			else
				echo -e "${Error} Lotsever不支持当前系统 ${release} ${version} ${bit} !" && exit 1
			fi
		else
			echo -e "${Error} Lotsever不支持当前系统 ${release} ${version} ${bit} !" && exit 1
		fi
	}

	check_status(){
		kernel_version=`uname -r | awk -F "-" '{print $1}'`
		kernel_version_full=`uname -r`
		if [[ ${kernel_version_full} = "4.14.129-bbrplus" ]]; then
			kernel_status="BBRplus"
		elif [[ ${kernel_version} = "3.10.0" || ${kernel_version} = "3.16.0" || ${kernel_version} = "3.2.0" || ${kernel_version} = "4.4.0" || ${kernel_version} = "3.13.0"  || ${kernel_version} = "2.6.32" || ${kernel_version} = "4.9.0" ]]; then
			kernel_status="Lotserver"
		elif [[ `echo ${kernel_version} | awk -F'.' '{print $1}'` == "4" ]] && [[ `echo ${kernel_version} | awk -F'.' '{print $2}'` -ge 9 ]] || [[ `echo ${kernel_version} | awk -F'.' '{print $1}'` == "5" ]]; then
			kernel_status="BBR"
		else 
			kernel_status="noinstall"
		fi

		if [[ ${kernel_status} == "Lotserver" ]]; then
			if [[ -e /appex/bin/lotServer.sh ]]; then
				run_status=`bash /appex/bin/lotServer.sh status | grep "LotServer" | awk  '{print $3}'`
				if [[ ${run_status} = "running!" ]]; then
					run_status="启动成功"
				else 
					run_status="启动失败"
				fi
			else 
				run_status="未安装加速模块"
			fi
		elif [[ ${kernel_status} == "BBR" ]]; then
			run_status=`grep "net.ipv4.tcp_congestion_control" /etc/sysctl.conf | awk -F "=" '{print $2}'`
			if [[ ${run_status} == "bbr" ]]; then
				run_status=`lsmod | grep "bbr" | awk '{print $1}'`
				if [[ ${run_status} == "tcp_bbr" ]]; then
					run_status="BBR启动成功"
				else 
					run_status="BBR启动失败"
				fi
			elif [[ ${run_status} == "tsunami" ]]; then
				run_status=`lsmod | grep "tsunami" | awk '{print $1}'`
				if [[ ${run_status} == "tcp_tsunami" ]]; then
					run_status="BBR魔改版启动成功"
				else 
					run_status="BBR魔改版启动失败"
				fi
			elif [[ ${run_status} == "nanqinlang" ]]; then
				run_status=`lsmod | grep "nanqinlang" | awk '{print $1}'`
				if [[ ${run_status} == "tcp_nanqinlang" ]]; then
					run_status="暴力BBR魔改版启动成功"
				else 
					run_status="暴力BBR魔改版启动失败"
				fi
			else 
				run_status="未安装加速模块"
			fi
		elif [[ ${kernel_status} == "BBRplus" ]]; then
			run_status=`grep "net.ipv4.tcp_congestion_control" /etc/sysctl.conf | awk -F "=" '{print $2}'`
			if [[ ${run_status} == "bbrplus" ]]; then
				run_status=`lsmod | grep "bbrplus" | awk '{print $1}'`
				if [[ ${run_status} == "tcp_bbrplus" ]]; then
					run_status="BBRplus启动成功"
				else 
					run_status="BBRplus启动失败"
				fi
			else 
				run_status="未安装加速模块"
			fi
		fi
	}

	#############系统检测组件#############
	check_sys
	check_version
	[[ ${release} != "debian" ]] && [[ ${release} != "ubuntu" ]] && [[ ${release} != "centos" ]] && echo -e "${Error} 本脚本不支持当前系统 ${release} !" && exit 1
	start_menu_bbr
}

#设置SSH端口
set_ssh(){
	# Use default SSH port 22. If you use another SSH port on your server
	if [ -e "/etc/ssh/sshd_config" ];then
		[ -z "`grep ^Port /etc/ssh/sshd_config`" ] && ssh_port=22 || ssh_port=`grep ^Port /etc/ssh/sshd_config | awk '{print $2}'`
		while :; do echo
			read -p "Please input SSH port(Default: $ssh_port): " SSH_PORT
			[ -z "$SSH_PORT" ] && SSH_PORT=$ssh_port
			if [ $SSH_PORT -eq 22 >/dev/null 2>&1 -o $SSH_PORT -gt 1024 >/dev/null 2>&1 -a $SSH_PORT -lt 65535 >/dev/null 2>&1 ];then
				break
			else
				echo "${CWARNING}input error! Input range: 22,1025~65534${CEND}"
			fi
		done
	 
		if [ -z "`grep ^Port /etc/ssh/sshd_config`" -a "$SSH_PORT" != '22' ];then
			sed -i "s@^#Port.*@&\nPort $SSH_PORT@" /etc/ssh/sshd_config
		elif [ -n "`grep ^Port /etc/ssh/sshd_config`" ];then
			sed -i "s@^Port.*@Port $SSH_PORT@" /etc/ssh/sshd_config
		fi
	fi
 }
 
#设置root用户密码
set_root(){
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

#重装VPS系统
reinstall_sys(){
	#检查系统
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
	
	#安装所需软件
	if [[ "${release}" == "centos" ]]; then
		yum install -y xz openssl gawk file
	elif [[ "${release}" == "debian" ]]; then
		apt-get install -y xz-utils openssl gawk file
	elif [[ "${release}" == "ubuntu" ]]; then
		apt-get install -y xz-utils openssl gawk file
	else
		echo -e "${Error} BBR内核不支持当前系统 ${release} !" && exit 1
	fi
	
	#!/bin/bash

	## License: GPL
	## It can reinstall Debian, Ubuntu, CentOS system with network.
	## 默认密码: MoeClub.org
	## Blog: https://moeclub.org
	## Written By MoeClub.org


	export tmpVER=''
	export tmpDIST=''
	export tmpURL=''
	export tmpWORD=''
	export tmpMirror=''
	export tmpSSL=''
	export tmpINS=''
	export ipAddr=''
	export ipMask=''
	export ipGate=''
	export Relese=''
	export ddMode='0'
	export setNet='0'
	export setRDP='0'
	export setIPv6='0'
	export isMirror='0'
	export FindDists='0'
	export loaderMode='0'
	export IncFirmware='0'
	export SpikCheckDIST='0'
	export setInterfaceName='0'
	export UNKNOWHW='0'
	export UNVER='6.4'

	while [[ $# -ge 1 ]]; do
	  case $1 in
		-v|--ver)
		  shift
		  tmpVER="$1"
		  shift
		  ;;
		-d|--debian)
		  shift
		  Relese='Debian'
		  tmpDIST="$1"
		  shift
		  ;;
		-u|--ubuntu)
		  shift
		  Relese='Ubuntu'
		  tmpDIST="$1"
		  shift
		  ;;
		-c|--centos)
		  shift
		  Relese='CentOS'
		  tmpDIST="$1"
		  shift
		  ;;
		-dd|--image)
		  shift
		  ddMode='1'
		  tmpURL="$1"
		  shift
		  ;;
		-p|--password)
		  shift
		  tmpWORD="$1"
		  shift
		  ;;
		-i|--interface)
		  shift
		  interface="$1"
		  shift
		  ;;
		--ip-addr)
		  shift
		  ipAddr="$1"
		  shift
		  ;;
		--ip-mask)
		  shift
		  ipMask="$1"
		  shift
		  ;;
		--ip-gate)
		  shift
		  ipGate="$1"
		  shift
		  ;;
		--dev-net)
		  shift
		  setInterfaceName='1'
		  ;;
		--loader)
		  shift
		  loaderMode='1'
		  ;;
		--prefer)
		  shift
		  tmpPrefer="$1"
		  shift
		  ;;
		-a|--auto)
		  shift
		  tmpINS='auto'
		  ;;
		-m|--manual)
		  shift
		  tmpINS='manual'
		  ;;
		-apt|-yum|--mirror)
		  shift
		  isMirror='1'
		  tmpMirror="$1"
		  shift
		  ;;
		-rdp)
		  shift
		  setRDP='1'
		  WinRemote="$1"
		  shift
		  ;;
		-ssl)
		  shift
		  tmpSSL="$1"
		  shift
		  ;;
		-firmware)
		  shift
		  IncFirmware="1"
		  ;;
		--ipv6)
		  shift
		  setIPv6='1'
		  ;;
		*)
		  if [[ "$1" != 'error' ]]; then echo -ne "\nInvaild option: '$1'\n\n"; fi
		  echo -ne " Usage:\n\tbash $(basename $0)\t-d/--debian [\033[33m\033[04mdists-name\033[0m]\n\t\t\t\t-u/--ubuntu [\033[04mdists-name\033[0m]\n\t\t\t\t-c/--centos [\033[33m\033[04mdists-verison\033[0m]\n\t\t\t\t-v/--ver [32/\033[33m\033[04mi386\033[0m|64/amd64]\n\t\t\t\t--ip-addr/--ip-gate/--ip-mask\n\t\t\t\t-apt/-yum/--mirror\n\t\t\t\t-dd/--image\n\t\t\t\t-a/--auto\n\t\t\t\t-m/--manual\n"
		  exit 1;
		  ;;
		esac
	  done

	[[ "$EUID" -ne '0' ]] && echo "Error:This script must be run as root!" && exit 1;

	function CheckDependence(){
	FullDependence='0';
	for BIN_DEP in `echo "$1" |sed 's/,/\n/g'`
	  do
		if [[ -n "$BIN_DEP" ]]; then
		  Founded='0';
		  for BIN_PATH in `echo "$PATH" |sed 's/:/\n/g'`
			do
			  ls $BIN_PATH/$BIN_DEP >/dev/null 2>&1;
			  if [ $? == '0' ]; then
				Founded='1';
				break;
			  fi
			done
		  if [ "$Founded" == '1' ]; then
			echo -en "[\033[32mok\033[0m]\t";
		  else
			FullDependence='1';
			echo -en "[\033[31mNot Install\033[0m]";
		  fi
		  echo -en "\t$BIN_DEP\n";
		fi
	  done
	if [ "$FullDependence" == '1' ]; then
	  echo -ne "\n\033[31mError! \033[0mPlease use '\033[33mapt-get\033[0m' or '\033[33myum\033[0m' install it.\n\n\n"
	  exit 1;
	fi
	}

	function SelectMirror(){
	  [ $# -ge 3 ] || exit 1
	  Relese="$1"
	  DIST=$(echo "$2" |sed 's/\ //g' |sed -r 's/(.*)/\L\1/')
	  VER=$(echo "$3" |sed 's/\ //g' |sed -r 's/(.*)/\L\1/')
	  New=$(echo "$4" |sed 's/\ //g')
	  [ -n "$Relese" ] || exit 1
	  [ -n "$DIST" ] || exit 1
	  [ -n "$VER" ] || exit 1
	  relese=$(echo $Relese |sed -r 's/(.*)/\L\1/')
	  if [ "$Relese" == "Debian" ] || [ "$Relese" == "Ubuntu" ]; then
		inUpdate=''; [ "$Relese" == "Ubuntu" ] && inUpdate='-updates'
		MirrorTEMP="SUB_MIRROR/dists/${DIST}${inUpdate}/main/installer-${VER}/current/images/netboot/${relese}-installer/${VER}/initrd.gz"
	  elif [ "$Relese" == "CentOS" ]; then
		MirrorTEMP="SUB_MIRROR/${DIST}/os/${VER}/isolinux/initrd.img"
	  fi
	  [ -n "$MirrorTEMP" ] || exit 1
	  MirrorStatus=0
	  declare -A MirrorBackup
	  MirrorBackup=(["Debian0"]="" ["Debian1"]="http://deb.debian.org/debian" ["Debian2"]="http://archive.debian.org/debian" ["Ubuntu0"]="" ["Ubuntu1"]="http://archive.ubuntu.com/ubuntu" ["CentOS0"]="" ["CentOS1"]="http://mirror.centos.org/centos" ["CentOS2"]="http://vault.centos.org")
	  echo "$New" |grep -q '^http://\|^https://\|^ftp://' && MirrorBackup[${Relese}0]="$New"
	  for mirror in $(echo "${!MirrorBackup[@]}" |sed 's/\ /\n/g' |sort -n |grep "^$Relese")
		do
		  CurMirror="${MirrorBackup[$mirror]}"
		  [ -n "$CurMirror" ] || continue
		  MirrorURL=`echo "$MirrorTEMP" |sed "s#SUB_MIRROR#${CurMirror}#g"`
		  wget --no-check-certificate --spider --timeout=3 -o /dev/null "$MirrorURL"
		  [ $? -eq 0 ] && MirrorStatus=1 && break
		done
	  [ $MirrorStatus -eq 1 ] && echo "$CurMirror" || exit 1
	}

	[ -n "$Relese" ] || Relese='Debian'
	linux_relese=$(echo "$Relese" |sed 's/\ //g' |sed -r 's/(.*)/\L\1/')
	clear && echo -e "\n\033[36m# Check Dependence\033[0m\n"

	if [[ "$ddMode" == '1' ]]; then
	  CheckDependence iconv;
	  linux_relese='debian';
	  tmpDIST='jessie';
	  tmpVER='amd64';
	  tmpINS='auto';
	fi

	if [[ "$Relese" == 'Debian' ]] || [[ "$Relese" == 'Ubuntu' ]]; then
	  CheckDependence wget,awk,grep,sed,cut,cat,cpio,gzip,find,dirname,basename;
	elif [[ "$Relese" == 'CentOS' ]]; then
	  CheckDependence wget,awk,grep,sed,cut,cat,cpio,gzip,find,dirname,basename,file,xz;
	fi
	[ -n "$tmpWORD" ] && CheckDependence openssl

	if [[ "$loaderMode" == "0" ]]; then
	  [[ -f '/boot/grub/grub.cfg' ]] && GRUBVER='0' && GRUBDIR='/boot/grub' && GRUBFILE='grub.cfg';
	  [[ -z "$GRUBDIR" ]] && [[ -f '/boot/grub2/grub.cfg' ]] && GRUBVER='0' && GRUBDIR='/boot/grub2' && GRUBFILE='grub.cfg';
	  [[ -z "$GRUBDIR" ]] && [[ -f '/boot/grub/grub.conf' ]] && GRUBVER='1' && GRUBDIR='/boot/grub' && GRUBFILE='grub.conf';
	  [ -z "$GRUBDIR" -o -z "$GRUBFILE" ] && echo -ne "Error! \nNot Found grub.\n" && exit 1;
	else
	  tmpINS='auto'
	fi

	if [[ -n "$tmpVER" ]]; then
	  tmpVER="$(echo "$tmpVER" |sed -r 's/(.*)/\L\1/')";
	  if  [[ "$tmpVER" == '32' ]] || [[ "$tmpVER" == 'i386' ]] || [[ "$tmpVER" == 'x86' ]]; then
		VER='i386';
	  fi
	  if  [[ "$tmpVER" == '64' ]] || [[ "$tmpVER" == 'amd64' ]] || [[ "$tmpVER" == 'x86_64' ]] || [[ "$tmpVER" == 'x64' ]]; then
		if [[ "$Relese" == 'Debian' ]] || [[ "$Relese" == 'Ubuntu' ]]; then
		  VER='amd64';
		elif [[ "$Relese" == 'CentOS' ]]; then
		  VER='x86_64';
		fi
	  fi
	fi
	[ -z "$VER" ] && VER='amd64'

	if [[ -z "$tmpDIST" ]]; then
	  [ "$Relese" == 'Debian' ] && tmpDIST='jessie' && DIST='jessie';
	  [ "$Relese" == 'Ubuntu' ] && tmpDIST='bionic' && DIST='bionic';
	  [ "$Relese" == 'CentOS' ] && tmpDIST='6.10' && DIST='6.10';
	fi

	if [[ -z "$DIST" ]]; then
	  if [[ "$Relese" == 'Debian' ]]; then
		SpikCheckDIST='0'
		DIST="$(echo "$tmpDIST" |sed -r 's/(.*)/\L\1/')";
		echo "$DIST" |grep -q '[0-9]';
		[[ $? -eq '0' ]] && {
		  isDigital="$(echo "$DIST" |grep -o '[\.0-9]\{1,\}' |sed -n '1h;1!H;$g;s/\n//g;$p' |cut -d'.' -f1)";
		  [[ -n $isDigital ]] && {
			[[ "$isDigital" == '7' ]] && DIST='wheezy';
			[[ "$isDigital" == '8' ]] && DIST='jessie';
			[[ "$isDigital" == '9' ]] && DIST='stretch';
			[[ "$isDigital" == '10' ]] && DIST='buster';
		  }
		}
		LinuxMirror=$(SelectMirror "$Relese" "$DIST" "$VER" "$tmpMirror")
	  fi
	  if [[ "$Relese" == 'Ubuntu' ]]; then
		SpikCheckDIST='0'
		DIST="$(echo "$tmpDIST" |sed -r 's/(.*)/\L\1/')";
		echo "$DIST" |grep -q '[0-9]';
		[[ $? -eq '0' ]] && {
		  isDigital="$(echo "$DIST" |grep -o '[\.0-9]\{1,\}' |sed -n '1h;1!H;$g;s/\n//g;$p')";
		  [[ -n $isDigital ]] && {
			[[ "$isDigital" == '12.04' ]] && DIST='precise';
			[[ "$isDigital" == '14.04' ]] && DIST='trusty';
			[[ "$isDigital" == '16.04' ]] && DIST='xenial';
			[[ "$isDigital" == '18.04' ]] && DIST='bionic';
		  }
		}
		LinuxMirror=$(SelectMirror "$Relese" "$DIST" "$VER" "$tmpMirror")
	  fi
	  if [[ "$Relese" == 'CentOS' ]]; then
		SpikCheckDIST='1'
		DISTCheck="$(echo "$tmpDIST" |grep -o '[\.0-9]\{1,\}')";
		LinuxMirror=$(SelectMirror "$Relese" "$DISTCheck" "$VER" "$tmpMirror")
		ListDIST="$(wget --no-check-certificate -qO- "$LinuxMirror/dir_sizes" |cut -f2 |grep '^[0-9]')"
		DIST="$(echo "$ListDIST" |grep "^$DISTCheck" |head -n1)"
		[[ -z "$DIST" ]] && {
		  echo -ne '\nThe dists version not found in this mirror, Please check it! \n\n'
		  bash $0 error;
		  exit 1;
		}
		wget --no-check-certificate -qO- "$LinuxMirror/$DIST/os/$VER/.treeinfo" |grep -q 'general';
		[[ $? != '0' ]] && {
			echo -ne "\nThe version not found in this mirror, Please change mirror try again! \n\n";
			exit 1;
		}
	  fi
	fi

	if [[ -z "$LinuxMirror" ]]; then
	  echo -ne "\033[31mError! \033[0mInvaild mirror! \n"
	  [ "$Relese" == 'Debian' ] && echo -en "\033[33mexample:\033[0m http://deb.debian.org/debian\n\n";
	  [ "$Relese" == 'Ubuntu' ] && echo -en "\033[33mexample:\033[0m http://archive.ubuntu.com/ubuntu\n\n";
	  [ "$Relese" == 'CentOS' ] && echo -en "\033[33mexample:\033[0m http://mirror.centos.org/centos\n\n";
	  bash $0 error;
	  exit 1;
	fi

	if [[ "$SpikCheckDIST" == '0' ]]; then
	  DistsList="$(wget --no-check-certificate -qO- "$LinuxMirror/dists/" |grep -o 'href=.*/"' |cut -d'"' -f2 |sed '/-\|old\|Debian\|experimental\|stable\|test\|sid\|devel/d' |grep '^[^/]' |sed -n '1h;1!H;$g;s/\n//g;s/\//\;/g;$p')";
	  for CheckDEB in `echo "$DistsList" |sed 's/;/\n/g'`
		do
		  [[ "$CheckDEB" == "$DIST" ]] && FindDists='1' && break;
		done
	  [[ "$FindDists" == '0' ]] && {
		echo -ne '\nThe dists version not found, Please check it! \n\n'
		bash $0 error;
		exit 1;
	  }
	fi

	[[ "$ddMode" == '1' ]] && {
	  export SSL_SUPPORT='https://moeclub.org/get/wget_udeb_amd64';
	  if [[ -n "$tmpURL" ]]; then
		DDURL="$tmpURL"
		echo "$DDURL" |grep -q '^http://\|^ftp://\|^https://';
		[[ $? -ne '0' ]] && echo 'Please input vaild URL,Only support http://, ftp:// and https:// !' && exit 1;
		[[ -n "$tmpSSL" ]] && SSL_SUPPORT="$tmpSSL";
	  else
		echo 'Please input vaild image URL! ';
		exit 1;
	  fi
	}

	[[ -n "$tmpINS" ]] && {
	  [[ "$tmpINS" == 'auto' ]] && inVNC='n';
	  [[ "$tmpINS" == 'manual' ]] && inVNC='y';
	}

	[ -n "$ipAddr" ] && [ -n "$ipMask" ] && [ -n "$ipGate" ] && setNet='1';
	[[ -n "$tmpWORD" ]] && myPASSWORD="$(openssl passwd -1 "$tmpWORD")";
	[[ -z "$myPASSWORD" ]] && myPASSWORD='$1$4BJZaD0A$y1QykUnJ6mXprENfwpseH0';

	if [[ -n "$interface" ]]; then
	  IFETH="$interface"
	else
	  if [[ "$linux_relese" == 'centos' ]]; then
		IFETH="link"
	  else
		IFETH="auto"
	  fi
	fi

	clear && echo -e "\n\033[36m# Install\033[0m\n"

	ASKVNC(){
	  inVNC='y';
	  [[ "$ddMode" == '0' ]] && {
		echo -ne "\033[34mDo you want to install os manually?\033[0m\e[33m[\e[32my\e[33m/n]\e[0m "
		read tmpinVNC
		[[ -n "$inVNCtmp" ]] && inVNC="$tmpinVNC"
	  }
	  [ "$inVNC" == 'y' -o "$inVNC" == 'Y' ] && inVNC='y';
	  [ "$inVNC" == 'n' -o "$inVNC" == 'N' ] && inVNC='n';
	}

	[ "$inVNC" == 'y' -o "$inVNC" == 'n' ] || ASKVNC;
	[[ "$ddMode" == '0' ]] && { 
	  [[ "$inVNC" == 'y' ]] && echo -e "\033[34mManual Mode\033[0m insatll [\033[33m$Relese\033[0m] [\033[33m$DIST\033[0m] [\033[33m$VER\033[0m] in VNC. "
	  [[ "$inVNC" == 'n' ]] && echo -e "\033[34mAuto Mode\033[0m insatll [\033[33m$Relese\033[0m] [\033[33m$DIST\033[0m] [\033[33m$VER\033[0m]. "
	}
	[[ "$ddMode" == '1' ]] && {
	  echo -ne "\033[34mAuto Mode\033[0m insatll \033[33mWindows\033[0m\n[\033[33m$DDURL\033[0m]\n"
	}

	if [[ "$linux_relese" == 'centos' ]]; then
	  if [[ "$DIST" != "$UNVER" ]]; then
		awk 'BEGIN{print '${UNVER}'-'${DIST}'}' |grep -q '^-'
		if [ $? != '0' ]; then
		  UNKNOWHW='1';
		  echo -en "\033[33mThe version lower then \033[31m$UNVER\033[33m may not support in auto mode! \033[0m\n";
		  if [[ "$inVNC" == 'n' ]]; then
			echo -en "\033[35mYou can connect VNC with \033[32mPublic IP\033[35m and port \033[32m1\033[35m/\033[32m5901\033[35m in vnc viewer.\033[0m\n"
			read -n 1 -p "Press Enter to continue..." INP
			[[ "$INP" != '' ]] && echo -ne '\b \n\n';
		  fi
		fi
		awk 'BEGIN{print '${UNVER}'-'${DIST}'+0.59}' |grep -q '^-'
		if [ $? == '0' ]; then
		  echo -en "\n\033[31mThe version higher then \033[33m6.10 \033[31mis not support in current! \033[0m\n\n"
		  exit 1;
		fi
	  fi
	fi

	echo -e "\n[\033[33m$Relese\033[0m] [\033[33m$DIST\033[0m] [\033[33m$VER\033[0m] Downloading..."

	if [[ "$linux_relese" == 'debian' ]] || [[ "$linux_relese" == 'ubuntu' ]]; then
	  inUpdate=''; [ "$linux_relese" == 'ubuntu' ] && inUpdate='-updates'
	  wget --no-check-certificate -qO '/boot/initrd.img' "${LinuxMirror}/dists/${DIST}${inUpdate}/main/installer-${VER}/current/images/netboot/${linux_relese}-installer/${VER}/initrd.gz"
	  [[ $? -ne '0' ]] && echo -ne "\033[31mError! \033[0mDownload 'initrd.img' for \033[33m$linux_relese\033[0m failed! \n" && exit 1
	  wget --no-check-certificate -qO '/boot/vmlinuz' "${LinuxMirror}/dists/${DIST}${inUpdate}/main/installer-${VER}/current/images/netboot/${linux_relese}-installer/${VER}/linux"
	  [[ $? -ne '0' ]] && echo -ne "\033[31mError! \033[0mDownload 'vmlinuz' for \033[33m$linux_relese\033[0m failed! \n" && exit 1
	  MirrorHost="$(echo "$LinuxMirror" |awk -F'://|/' '{print $2}')";
	  MirrorFolder="$(echo "$LinuxMirror" |awk -F''${MirrorHost}'' '{print $2}')";
	elif [[ "$linux_relese" == 'centos' ]]; then
	  wget --no-check-certificate -qO '/boot/initrd.img' "${LinuxMirror}/${DIST}/os/${VER}/isolinux/initrd.img"
	  [[ $? -ne '0' ]] && echo -ne "\033[31mError! \033[0mDownload 'initrd.img' for \033[33m$linux_relese\033[0m failed! \n" && exit 1
	  wget --no-check-certificate -qO '/boot/vmlinuz' "${LinuxMirror}/${DIST}/os/${VER}/isolinux/vmlinuz"
	  [[ $? -ne '0' ]] && echo -ne "\033[31mError! \033[0mDownload 'vmlinuz' for \033[33m$linux_relese\033[0m failed! \n" && exit 1
	else
	  bash $0 error;
	  exit 1;
	fi
	if [[ "$linux_relese" == 'debian' ]]; then
	  if [[ "$IncFirmware" == '1' ]]; then
		wget --no-check-certificate -qO '/boot/firmware.cpio.gz' "http://cdimage.debian.org/cdimage/unofficial/non-free/firmware/${DIST}/current/firmware.cpio.gz"
		[[ $? -ne '0' ]] && echo -ne "\033[31mError! \033[0mDownload 'firmware' for \033[33m$linux_relese\033[0m failed! \n" && exit 1
	  fi
	  if [[ "$ddMode" == '1' ]]; then
		vKernel_udeb=$(wget --no-check-certificate -qO- "http://$DISTMirror/dists/$DIST/main/installer-$VER/current/images/udeb.list" |grep '^acpi-modules' |head -n1 |grep -o '[0-9]\{1,2\}.[0-9]\{1,2\}.[0-9]\{1,2\}-[0-9]\{1,2\}' |head -n1)
		[[ -z "vKernel_udeb" ]] && vKernel_udeb="3.16.0-6"
	  fi
	fi

	[[ "$setNet" == '1' ]] && {
	  IPv4="$ipAddr";
	  MASK="$ipMask";
	  GATE="$ipGate";
	} || {
	  DEFAULTNET="$(ip route show |grep -o 'default via [0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.*' |head -n1 |sed 's/proto.*\|onlink.*//g' |awk '{print $NF}')";
	  [[ -n "$DEFAULTNET" ]] && IPSUB="$(ip addr |grep ''${DEFAULTNET}'' |grep 'global' |grep 'brd' |head -n1 |grep -o '[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}/[0-9]\{1,2\}')";
	  IPv4="$(echo -n "$IPSUB" |cut -d'/' -f1)";
	  NETSUB="$(echo -n "$IPSUB" |grep -o '/[0-9]\{1,2\}')";
	  GATE="$(ip route show |grep -o 'default via [0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}' |head -n1 |grep -o '[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}')";
	  [[ -n "$NETSUB" ]] && MASK="$(echo -n '128.0.0.0/1,192.0.0.0/2,224.0.0.0/3,240.0.0.0/4,248.0.0.0/5,252.0.0.0/6,254.0.0.0/7,255.0.0.0/8,255.128.0.0/9,255.192.0.0/10,255.224.0.0/11,255.240.0.0/12,255.248.0.0/13,255.252.0.0/14,255.254.0.0/15,255.255.0.0/16,255.255.128.0/17,255.255.192.0/18,255.255.224.0/19,255.255.240.0/20,255.255.248.0/21,255.255.252.0/22,255.255.254.0/23,255.255.255.0/24,255.255.255.128/25,255.255.255.192/26,255.255.255.224/27,255.255.255.240/28,255.255.255.248/29,255.255.255.252/30,255.255.255.254/31,255.255.255.255/32' |grep -o '[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}'${NETSUB}'' |cut -d'/' -f1)";
	}

	[[ -n "$GATE" ]] && [[ -n "$MASK" ]] && [[ -n "$IPv4" ]] || {
	echo "Not found \`ip command\`, It will use \`route command\`."
	ipNum() {
	  local IFS='.';
	  read ip1 ip2 ip3 ip4 <<<"$1";
	  echo $((ip1*(1<<24)+ip2*(1<<16)+ip3*(1<<8)+ip4));
	}

	SelectMax(){
	ii=0;
	for IPITEM in `route -n |awk -v OUT=$1 '{print $OUT}' |grep '[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}'`
	  do
		NumTMP="$(ipNum $IPITEM)";
		eval "arrayNum[$ii]='$NumTMP,$IPITEM'";
		ii=$[$ii+1];
	  done
	echo ${arrayNum[@]} |sed 's/\s/\n/g' |sort -n -k 1 -t ',' |tail -n1 |cut -d',' -f2;
	}

	[[ -z $IPv4 ]] && IPv4="$(ifconfig |grep 'Bcast' |head -n1 |grep -o '[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}' |head -n1)";
	[[ -z $GATE ]] && GATE="$(SelectMax 2)";
	[[ -z $MASK ]] && MASK="$(SelectMax 3)";

	[[ -n "$GATE" ]] && [[ -n "$MASK" ]] && [[ -n "$IPv4" ]] || {
	  echo "Error! Not configure network. ";
	  exit 1;
	}
	}

	[[ "$setNet" != '1' ]] && [[ -f '/etc/network/interfaces' ]] && {
	  [[ -z "$(sed -n '/iface.*inet static/p' /etc/network/interfaces)" ]] && AutoNet='1' || AutoNet='0';
	  [[ -d /etc/network/interfaces.d ]] && {
		ICFGN="$(find /etc/network/interfaces.d -name '*.cfg' |wc -l)" || ICFGN='0';
		[[ "$ICFGN" -ne '0' ]] && {
		  for NetCFG in `ls -1 /etc/network/interfaces.d/*.cfg`
			do 
			  [[ -z "$(cat $NetCFG | sed -n '/iface.*inet static/p')" ]] && AutoNet='1' || AutoNet='0';
			  [[ "$AutoNet" -eq '0' ]] && break;
			done
		}
	  }
	}

	[[ "$setNet" != '1' ]] && [[ -d '/etc/sysconfig/network-scripts' ]] && {
	  ICFGN="$(find /etc/sysconfig/network-scripts -name 'ifcfg-*' |grep -v 'lo'|wc -l)" || ICFGN='0';
	  [[ "$ICFGN" -ne '0' ]] && {
		for NetCFG in `ls -1 /etc/sysconfig/network-scripts/ifcfg-* |grep -v 'lo$' |grep -v ':[0-9]\{1,\}'`
		  do 
			[[ -n "$(cat $NetCFG | sed -n '/BOOTPROTO.*[dD][hH][cC][pP]/p')" ]] && AutoNet='1' || {
			  AutoNet='0' && . $NetCFG;
			  [[ -n $NETMASK ]] && MASK="$NETMASK";
			  [[ -n $GATEWAY ]] && GATE="$GATEWAY";
			}
			[[ "$AutoNet" -eq '0' ]] && break;
		  done
	  }
	}

	if [[ "$loaderMode" == "0" ]]; then
	  [[ ! -f $GRUBDIR/$GRUBFILE ]] && echo "Error! Not Found $GRUBFILE. " && exit 1;

	  [[ ! -f $GRUBDIR/$GRUBFILE.old ]] && [[ -f $GRUBDIR/$GRUBFILE.bak ]] && mv -f $GRUBDIR/$GRUBFILE.bak $GRUBDIR/$GRUBFILE.old;
	  mv -f $GRUBDIR/$GRUBFILE $GRUBDIR/$GRUBFILE.bak;
	  [[ -f $GRUBDIR/$GRUBFILE.old ]] && cat $GRUBDIR/$GRUBFILE.old >$GRUBDIR/$GRUBFILE || cat $GRUBDIR/$GRUBFILE.bak >$GRUBDIR/$GRUBFILE;
	else
	  GRUBVER='2'
	fi

	[[ "$GRUBVER" == '0' ]] && {
	  READGRUB='/tmp/grub.read'
	  cat $GRUBDIR/$GRUBFILE |sed -n '1h;1!H;$g;s/\n/%%%%%%%/g;$p' |grep -om 1 'menuentry\ [^{]*{[^}]*}%%%%%%%' |sed 's/%%%%%%%/\n/g' >$READGRUB
	  LoadNum="$(cat $READGRUB |grep -c 'menuentry ')"
	  if [[ "$LoadNum" -eq '1' ]]; then
		cat $READGRUB |sed '/^$/d' >/tmp/grub.new;
	  elif [[ "$LoadNum" -gt '1' ]]; then
		CFG0="$(awk '/menuentry /{print NR}' $READGRUB|head -n 1)";
		CFG2="$(awk '/menuentry /{print NR}' $READGRUB|head -n 2 |tail -n 1)";
		CFG1="";
		for tmpCFG in `awk '/}/{print NR}' $READGRUB`
		  do
			[ "$tmpCFG" -gt "$CFG0" -a "$tmpCFG" -lt "$CFG2" ] && CFG1="$tmpCFG";
		  done
		[[ -z "$CFG1" ]] && {
		  echo "Error! read $GRUBFILE. ";
		  exit 1;
		}

		sed -n "$CFG0,$CFG1"p $READGRUB >/tmp/grub.new;
		[[ -f /tmp/grub.new ]] && [[ "$(grep -c '{' /tmp/grub.new)" -eq "$(grep -c '}' /tmp/grub.new)" ]] || {
		  echo -ne "\033[31mError! \033[0mNot configure $GRUBFILE. \n";
		  exit 1;
		}
	  fi
	  [ ! -f /tmp/grub.new ] && echo "Error! $GRUBFILE. " && exit 1;
	  sed -i "/menuentry.*/c\menuentry\ \'Install OS \[$DIST\ $VER\]\'\ --class debian\ --class\ gnu-linux\ --class\ gnu\ --class\ os\ \{" /tmp/grub.new
	  sed -i "/echo.*Loading/d" /tmp/grub.new;
	  INSERTGRUB="$(awk '/menuentry /{print NR}' $GRUBDIR/$GRUBFILE|head -n 1)"
	}

	[[ "$GRUBVER" == '1' ]] && {
	  CFG0="$(awk '/title[\ ]|title[\t]/{print NR}' $GRUBDIR/$GRUBFILE|head -n 1)";
	  CFG1="$(awk '/title[\ ]|title[\t]/{print NR}' $GRUBDIR/$GRUBFILE|head -n 2 |tail -n 1)";
	  [[ -n $CFG0 ]] && [ -z $CFG1 -o $CFG1 == $CFG0 ] && sed -n "$CFG0,$"p $GRUBDIR/$GRUBFILE >/tmp/grub.new;
	  [[ -n $CFG0 ]] && [ -z $CFG1 -o $CFG1 != $CFG0 ] && sed -n "$CFG0,$[$CFG1-1]"p $GRUBDIR/$GRUBFILE >/tmp/grub.new;
	  [[ ! -f /tmp/grub.new ]] && echo "Error! configure append $GRUBFILE. " && exit 1;
	  sed -i "/title.*/c\title\ \'Install OS \[$DIST\ $VER\]\'" /tmp/grub.new;
	  sed -i '/^#/d' /tmp/grub.new;
	  INSERTGRUB="$(awk '/title[\ ]|title[\t]/{print NR}' $GRUBDIR/$GRUBFILE|head -n 1)"
	}

	if [[ "$loaderMode" == "0" ]]; then
	[[ -n "$(grep 'linux.*/\|kernel.*/' /tmp/grub.new |awk '{print $2}' |tail -n 1 |grep '^/boot/')" ]] && Type='InBoot' || Type='NoBoot';

	LinuxKernel="$(grep 'linux.*/\|kernel.*/' /tmp/grub.new |awk '{print $1}' |head -n 1)";
	[[ -z "$LinuxKernel" ]] && echo "Error! read grub config! " && exit 1;
	LinuxIMG="$(grep 'initrd.*/' /tmp/grub.new |awk '{print $1}' |tail -n 1)";
	[ -z "$LinuxIMG" ] && sed -i "/$LinuxKernel.*\//a\\\tinitrd\ \/" /tmp/grub.new && LinuxIMG='initrd';

	if [[ "$setInterfaceName" == "1" ]]; then
	  Add_OPTION="net.ifnames=0 biosdevname=0";
	else
	  Add_OPTION="";
	fi

	if [[ "$setIPv6" == "1" ]]; then
	  Add_OPTION="$Add_OPTION ipv6.disable=1";
	fi

	if [[ "$linux_relese" == 'debian' ]] || [[ "$linux_relese" == 'ubuntu' ]]; then
	  BOOT_OPTION="auto=true $Add_OPTION hostname=$linux_relese domain= -- quiet"
	elif [[ "$linux_relese" == 'centos' ]]; then
	  BOOT_OPTION="ks=file://ks.cfg $Add_OPTION ksdevice=$IFETH"
	fi

	[[ "$Type" == 'InBoot' ]] && {
	  sed -i "/$LinuxKernel.*\//c\\\t$LinuxKernel\\t\/boot\/vmlinuz $BOOT_OPTION" /tmp/grub.new;
	  sed -i "/$LinuxIMG.*\//c\\\t$LinuxIMG\\t\/boot\/initrd.img" /tmp/grub.new;
	}

	[[ "$Type" == 'NoBoot' ]] && {
	  sed -i "/$LinuxKernel.*\//c\\\t$LinuxKernel\\t\/vmlinuz $BOOT_OPTION" /tmp/grub.new;
	  sed -i "/$LinuxIMG.*\//c\\\t$LinuxIMG\\t\/initrd.img" /tmp/grub.new;
	}

	sed -i '$a\\n' /tmp/grub.new;
	fi

	[[ "$inVNC" == 'n' ]] && {
	GRUBPATCH='0';

	if [[ "$loaderMode" == "0" ]]; then
	[ -f '/etc/network/interfaces' -o -d '/etc/sysconfig/network-scripts' ] || {
	  echo "Error, Not found interfaces config.";
	  exit 1;
	}

	sed -i ''${INSERTGRUB}'i\\n' $GRUBDIR/$GRUBFILE;
	sed -i ''${INSERTGRUB}'r /tmp/grub.new' $GRUBDIR/$GRUBFILE;
	[[ -f  $GRUBDIR/grubenv ]] && sed -i 's/saved_entry/#saved_entry/g' $GRUBDIR/grubenv;
	fi

	[[ -d /tmp/boot ]] && rm -rf /tmp/boot;
	mkdir -p /tmp/boot;
	cd /tmp/boot;
	if [[ "$linux_relese" == 'debian' ]] || [[ "$linux_relese" == 'ubuntu' ]]; then
	  COMPTYPE="gzip";
	elif [[ "$linux_relese" == 'centos' ]]; then
	  COMPTYPE="$(file /boot/initrd.img |grep -o ':.*compressed data' |cut -d' ' -f2 |sed -r 's/(.*)/\L\1/' |head -n1)"
	  [[ -z "$COMPTYPE" ]] && echo "Detect compressed type fail." && exit 1;
	fi
	CompDected='0'
	for ListCOMP in `echo -en 'gzip\nlzma\nxz'`
	  do
		if [[ "$COMPTYPE" == "$ListCOMP" ]]; then
		  CompDected='1'
		  if [[ "$COMPTYPE" == 'gzip' ]]; then
			NewIMG="initrd.img.gz"
		  else
			NewIMG="initrd.img.$COMPTYPE"
		  fi
		  mv -f "/boot/initrd.img" "/tmp/$NewIMG"
		  break;
		fi
	  done
	[[ "$CompDected" != '1' ]] && echo "Detect compressed type not support." && exit 1;
	[[ "$COMPTYPE" == 'lzma' ]] && UNCOMP='xz --format=lzma --decompress';
	[[ "$COMPTYPE" == 'xz' ]] && UNCOMP='xz --decompress';
	[[ "$COMPTYPE" == 'gzip' ]] && UNCOMP='gzip -d';

	$UNCOMP < /tmp/$NewIMG | cpio --extract --verbose --make-directories --no-absolute-filenames >>/dev/null 2>&1

	if [[ "$linux_relese" == 'debian' ]] || [[ "$linux_relese" == 'ubuntu' ]]; then
	cat >/tmp/boot/preseed.cfg<<EOF
		d-i debian-installer/locale string en_US
		d-i console-setup/layoutcode string us

		d-i keyboard-configuration/xkb-keymap string us

		d-i netcfg/choose_interface select $IFETH

		d-i netcfg/disable_autoconfig boolean true
		d-i netcfg/dhcp_failed note
		d-i netcfg/dhcp_options select Configure network manually
		d-i netcfg/get_ipaddress string $IPv4
		d-i netcfg/get_netmask string $MASK
		d-i netcfg/get_gateway string $GATE
		d-i netcfg/get_nameservers string 8.8.8.8
		d-i netcfg/no_default_route boolean true
		d-i netcfg/confirm_static boolean true

		d-i hw-detect/load_firmware boolean true

		d-i mirror/country string manual
		d-i mirror/http/hostname string $MirrorHost
		d-i mirror/http/directory string $MirrorFolder
		d-i mirror/http/proxy string
		d-i apt-setup/services-select multiselect

		d-i passwd/root-login boolean ture
		d-i passwd/make-user boolean false
		d-i passwd/root-password-crypted password $myPASSWORD
		d-i user-setup/allow-password-weak boolean true
		d-i user-setup/encrypt-home boolean false

		d-i clock-setup/utc boolean true
		d-i time/zone string US/Eastern
		d-i clock-setup/ntp boolean true

		d-i preseed/early_command string anna-install libfuse2-udeb fuse-udeb ntfs-3g-udeb fuse-modules-${vKernel_udeb}-amd64-di
		d-i partman/early_command string \
		debconf-set partman-auto/disk "\$(list-devices disk |head -n1)"; \
		wget -qO- '$DDURL' |gunzip -dc |/bin/dd of=\$(list-devices disk |head -n1); \
		mount.ntfs-3g \$(list-devices partition |head -n1) /mnt; \
		cd '/mnt/ProgramData/Microsoft/Windows/Start Menu/Programs'; \
		cd Start* || cd start*; \
		cp -f '/net.bat' './net.bat'; \
		/sbin/reboot; \
		debconf-set grub-installer/bootdev string "\$(list-devices disk |head -n1)"; \
		umount /media || true; \

		d-i partman/mount_style select uuid
		d-i partman-auto/init_automatically_partition select Guided - use entire disk
		d-i partman-auto/method string regular
		d-i partman-lvm/device_remove_lvm boolean true
		d-i partman-md/device_remove_md boolean true
		d-i partman-auto/choose_recipe select atomic
		d-i partman-partitioning/confirm_write_new_label boolean true
		d-i partman/choose_partition select finish
		d-i partman-lvm/confirm boolean true
		d-i partman-lvm/confirm_nooverwrite boolean true
		d-i partman/confirm boolean true
		d-i partman/confirm_nooverwrite boolean true

		d-i debian-installer/allow_unauthenticated boolean true

		tasksel tasksel/first multiselect minimal
		d-i pkgsel/update-policy select none
		d-i pkgsel/include string openssh-server
		d-i pkgsel/upgrade select none

		popularity-contest popularity-contest/participate boolean false

		d-i grub-installer/only_debian boolean true
		d-i grub-installer/bootdev string default
		d-i finish-install/reboot_in_progress note
		d-i debian-installer/exit/reboot boolean true
		d-i preseed/late_command string	\
		sed -ri 's/^#?PermitRootLogin.*/PermitRootLogin yes/g' /target/etc/ssh/sshd_config; \
		sed -ri 's/^#?PasswordAuthentication.*/PasswordAuthentication yes/g' /target/etc/ssh/sshd_config;
EOF

	[[ "$loaderMode" != "0" ]] && AutoNet='1'

	[[ "$setNet" == '0' ]] && [[ "$AutoNet" == '1' ]] && {
	  sed -i '/netcfg\/disable_autoconfig/d' /tmp/boot/preseed.cfg
	  sed -i '/netcfg\/dhcp_options/d' /tmp/boot/preseed.cfg
	  sed -i '/netcfg\/get_.*/d' /tmp/boot/preseed.cfg
	  sed -i '/netcfg\/confirm_static/d' /tmp/boot/preseed.cfg
	}

	[[ "$DIST" == 'trusty' ]] && GRUBPATCH='1'
	[[ "$DIST" == 'wily' ]] && GRUBPATCH='1'
	[[ "$DIST" == 'xenial' ]] && {
	  sed -i 's/^d-i\ clock-setup\/ntp\ boolean\ true/d-i\ clock-setup\/ntp\ boolean\ false/g' /tmp/boot/preseed.cfg
	}

	[[ "$GRUBPATCH" == '1' ]] && {
	  sed -i 's/^d-i\ grub-installer\/bootdev\ string\ default//g' /tmp/boot/preseed.cfg
	}
	[[ "$GRUBPATCH" == '0' ]] && {
	  sed -i 's/debconf-set\ grub-installer\/bootdev.*\"\;//g' /tmp/boot/preseed.cfg
	}

	[[ "$linux_relese" == 'debian' ]] && {
	  sed -i '/user-setup\/allow-password-weak/d' /tmp/boot/preseed.cfg
	  sed -i '/user-setup\/encrypt-home/d' /tmp/boot/preseed.cfg
	  sed -i '/pkgsel\/update-policy/d' /tmp/boot/preseed.cfg
	  sed -i 's/umount\ \/media.*true\;\ //g' /tmp/boot/preseed.cfg
	}
	[[ "$linux_relese" == 'debian' ]] && [[ -f '/boot/firmware.cpio.gz' ]] && {
	  gzip -d < /boot/firmware.cpio.gz | cpio --extract --verbose --make-directories --no-absolute-filenames >>/dev/null 2>&1
	}

	[[ "$ddMode" == '1' ]] && {
	WinNoDHCP(){
	  echo -ne "for\0040\0057f\0040\0042tokens\00753\0052\0042\0040\0045\0045i\0040in\0040\0050\0047netsh\0040interface\0040show\0040interface\0040\0136\0174more\0040\00533\0040\0136\0174findstr\0040\0057I\0040\0057R\0040\0042本地\0056\0052\0040以太\0056\0052\0040Local\0056\0052\0040Ethernet\0042\0047\0051\0040do\0040\0050set\0040EthName\0075\0045\0045j\0051\r\nnetsh\0040\0055c\0040interface\0040ip\0040set\0040address\0040name\0075\0042\0045EthName\0045\0042\0040source\0075static\0040address\0075$IPv4\0040mask\0075$MASK\0040gateway\0075$GATE\r\nnetsh\0040\0055c\0040interface\0040ip\0040add\0040dnsservers\0040name\0075\0042\0045EthName\0045\0042\0040address\00758\00568\00568\00568\0040index\00751\0040validate\0075no\r\n\r\n" >>'/tmp/boot/net.tmp';
	}
	WinRDP(){
	  echo -ne "netsh\0040firewall\0040set\0040portopening\0040protocol\0075ALL\0040port\0075$WinRemote\0040name\0075RDP\0040mode\0075ENABLE\0040scope\0075ALL\0040profile\0075ALL\r\nnetsh\0040firewall\0040set\0040portopening\0040protocol\0075ALL\0040port\0075$WinRemote\0040name\0075RDP\0040mode\0075ENABLE\0040scope\0075ALL\0040profile\0075CURRENT\r\nreg\0040add\0040\0042HKLM\0134SYSTEM\0134CurrentControlSet\0134Control\0134Network\0134NewNetworkWindowOff\0042\0040\0057f\r\nreg\0040add\0040\0042HKLM\0134SYSTEM\0134CurrentControlSet\0134Control\0134Terminal\0040Server\0042\0040\0057v\0040fDenyTSConnections\0040\0057t\0040reg\0137dword\0040\0057d\00400\0040\0057f\r\nreg\0040add\0040\0042HKLM\0134SYSTEM\0134CurrentControlSet\0134Control\0134Terminal\0040Server\0134Wds\0134rdpwd\0134Tds\0134tcp\0042\0040\0057v\0040PortNumber\0040\0057t\0040reg\0137dword\0040\0057d\0040$WinRemote\0040\0057f\r\nreg\0040add\0040\0042HKLM\0134SYSTEM\0134CurrentControlSet\0134Control\0134Terminal\0040Server\0134WinStations\0134RDP\0055Tcp\0042\0040\0057v\0040PortNumber\0040\0057t\0040reg\0137dword\0040\0057d\0040$WinRemote\0040\0057f\r\nreg\0040add\0040\0042HKLM\0134SYSTEM\0134CurrentControlSet\0134Control\0134Terminal\0040Server\0134WinStations\0134RDP\0055Tcp\0042\0040\0057v\0040UserAuthentication\0040\0057t\0040reg\0137dword\0040\0057d\00400\0040\0057f\r\nFOR\0040\0057F\0040\0042tokens\00752\0040delims\0075\0072\0042\0040\0045\0045i\0040in\0040\0050\0047SC\0040QUERYEX\0040TermService\0040\0136\0174FINDSTR\0040\0057I\0040\0042PID\0042\0047\0051\0040do\0040TASKKILL\0040\0057F\0040\0057PID\0040\0045\0045i\r\nFOR\0040\0057F\0040\0042tokens\00752\0040delims\0075\0072\0042\0040\0045\0045i\0040in\0040\0050\0047SC\0040QUERYEX\0040UmRdpService\0040\0136\0174FINDSTR\0040\0057I\0040\0042PID\0042\0047\0051\0040do\0040TASKKILL\0040\0057F\0040\0057PID\0040\0045\0045i\r\nSC\0040START\0040TermService\r\n\r\n" >>'/tmp/boot/net.tmp';
	}
	  echo -ne "\0100ECHO\0040OFF\r\n\r\ncd\0056\0076\0045WINDIR\0045\0134GetAdmin\r\nif\0040exist\0040\0045WINDIR\0045\0134GetAdmin\0040\0050del\0040\0057f\0040\0057q\0040\0042\0045WINDIR\0045\0134GetAdmin\0042\0051\0040else\0040\0050\r\necho\0040CreateObject\0136\0050\0042Shell\0056Application\0042\0136\0051\0056ShellExecute\0040\0042\0045\0176s0\0042\0054\0040\0042\0045\0052\0042\0054\0040\0042\0042\0054\0040\0042runas\0042\0054\00401\0040\0076\0076\0040\0042\0045temp\0045\0134Admin\0056vbs\0042\r\n\0042\0045temp\0045\0134Admin\0056vbs\0042\r\ndel\0040\0057f\0040\0057q\0040\0042\0045temp\0045\0134Admin\0056vbs\0042\r\nexit\0040\0057b\00402\0051\r\n\r\n" >'/tmp/boot/net.tmp';
	  [[ "$setNet" == '1' ]] && WinNoDHCP;
	  [[ "$setNet" == '0' ]] && [[ "$AutoNet" == '0' ]] && WinNoDHCP;
	  [[ "$setRDP" == '1' ]] && [[ -n "$WinRemote" ]] && WinRDP
	  echo -ne "ECHO\0040SELECT\0040VOLUME\0075\0045\0045SystemDrive\0045\0045\0040\0076\0040\0042\0045SystemDrive\0045\0134diskpart\0056extend\0042\r\nECHO\0040EXTEND\0040\0076\0076\0040\0042\0045SystemDrive\0045\0134diskpart\0056extend\0042\r\nSTART\0040/WAIT\0040DISKPART\0040\0057S\0040\0042\0045SystemDrive\0045\0134diskpart\0056extend\0042\r\nDEL\0040\0057f\0040\0057q\0040\0042\0045SystemDrive\0045\0134diskpart\0056extend\0042\r\n\r\n" >>'/tmp/boot/net.tmp';
	  echo -ne "cd\0040\0057d\0040\0042\0045ProgramData\0045\0057Microsoft\0057Windows\0057Start\0040Menu\0057Programs\0057Startup\0042\r\ndel\0040\0057f\0040\0057q\0040net\0056bat\r\n\r\n\r\n" >>'/tmp/boot/net.tmp';
	  iconv -f 'UTF-8' -t 'GBK' '/tmp/boot/net.tmp' -o '/tmp/boot/net.bat'
	  rm -rf '/tmp/boot/net.tmp'
	  echo "$DDURL" |grep -q '^https://'
	  [[ $? -eq '0' ]] && {
		echo -ne '\nAdd ssl support...\n'
		[[ -n $SSL_SUPPORT ]] && {
		  wget --no-check-certificate -qO- "$SSL_SUPPORT" |tar -x
		  [[ ! -f  /tmp/boot/usr/bin/wget ]] && echo 'Error! SSL_SUPPORT.' && exit 1;
		  sed -i 's/wget\ -qO-/\/usr\/bin\/wget\ --no-check-certificate\ --retry-connrefused\ --tries=7\ --continue\ -qO-/g' /tmp/boot/preseed.cfg
		  [[ $? -eq '0' ]] && echo -ne 'Success! \n\n'
		} || {
		echo -ne 'Not ssl support package! \n\n';
		exit 1;
		}
	  }
	}

	[[ "$ddMode" == '0' ]] && {
	  sed -i '/anna-install/d' /tmp/boot/preseed.cfg
	  sed -i 's/wget.*\/sbin\/reboot\;\ //g' /tmp/boot/preseed.cfg
	}

	elif [[ "$linux_relese" == 'centos' ]]; then
	cat >/tmp/boot/ks.cfg<<EOF
		#platform=x86, AMD64, or Intel EM64T
		firewall --enabled --ssh
		install
		url --url="$LinuxMirror/$DIST/os/$VER/"
		rootpw --iscrypted $myPASSWORD
		auth --useshadow --passalgo=sha512
		firstboot --disable
		lang en_US
		keyboard us
		selinux --disabled
		logging --level=info
		reboot
		text
		unsupported_hardware
		vnc
		skipx
		timezone --isUtc Asia/Hong_Kong
		#ONDHCP network --bootproto=dhcp --onboot=on
		#NODHCP network --bootproto=static --ip=$IPv4 --netmask=$MASK --gateway=$GATE --nameserver=8.8.8.8 --onboot=on
		bootloader --location=mbr --append="rhgb quiet crashkernel=auto"
		zerombr
		clearpart --all --initlabel 
		autopart

		%packages
		@base
		%end

		%post --interpreter=/bin/bash
		rm -rf /root/anaconda-ks.cfg
		rm -rf /root/install.*log
		%end
EOF

	[[ "$setNet" == '0' ]] && [[ "$AutoNet" == '1' ]] && {
	  sed -i 's/#ONDHCP\ //g' /tmp/boot/ks.cfg
	} || {
	  sed -i 's/#NODHCP\ //g' /tmp/boot/ks.cfg
	}
	[[ "$UNKNOWHW" == '1' ]] && sed -i 's/^unsupported_hardware/#unsupported_hardware/g' /tmp/boot/ks.cfg
	[[ "$(echo "$DIST" |grep -o '^[0-9]\{1\}')" == '5' ]] && sed -i '0,/^%end/s//#%end/' /tmp/boot/ks.cfg
	fi

	find . | cpio -H newc --create --verbose | gzip -9 > /boot/initrd.img;
	rm -rf /tmp/boot;
	}

	[[ "$inVNC" == 'y' ]] && {
	  sed -i '$i\\n' $GRUBDIR/$GRUBFILE
	  sed -i '$r /tmp/grub.new' $GRUBDIR/$GRUBFILE
	  echo -e "\n\033[33m\033[04mIt will reboot! \nPlease connect VNC! \nSelect\033[0m\033[32m Install OS [$DIST $VER] \033[33m\033[4mto install system.\033[04m\n\n\033[31m\033[04mThere is some information for you.\nDO NOT CLOSE THE WINDOW! \033[0m\n"
	  echo -e "\033[35mIPv4\t\tNETMASK\t\tGATEWAY\033[0m"
	  echo -e "\033[36m\033[04m$IPv4\033[0m\t\033[36m\033[04m$MASK\033[0m\t\033[36m\033[04m$GATE\033[0m\n\n"

	  read -n 1 -p "Press Enter to reboot..." INP
	  [[ "$INP" != '' ]] && echo -ne '\b \n\n';
	}

	chown root:root $GRUBDIR/$GRUBFILE
	chmod 444 $GRUBDIR/$GRUBFILE

	if [[ "$loaderMode" == "0" ]]; then
	  sleep 3 && reboot >/dev/null 2>&1
	else
	  rm -rf "$HOME/loader"
	  mkdir -p "$HOME/loader"
	  cp -rf "/boot/initrd.img" "$HOME/loader/initrd.img"
	  cp -rf "/boot/vmlinuz" "$HOME/loader/vmlinuz"
	  [[ -f "/boot/initrd.img" ]] && rm -rf "/boot/initrd.img"
	  [[ -f "/boot/vmlinuz" ]] && rm -rf "/boot/vmlinuz"
	  echo && ls -AR1 "$HOME/loader"
	fi
}

#系统性能测试
test_sys(){
	#ipv4与ipv6测试
	ibench(){
		#!/usr/bin/env bash
		#
		# Description: Auto test download & I/O speed script
		#
		# Copyright (C) 2015 - 2019 Teddysun <i@teddysun.com>
		#
		# Thanks: LookBack <admin@dwhd.org>
		#
		# URL: https://teddysun.com/444.html
		#

		if  [ ! -e '/usr/bin/wget' ]; then
			echo "Error: wget command not found. You must be install wget command at first."
			exit 1
		fi

		# Colors
		RED='\033[0;31m'
		GREEN='\033[0;32m'
		YELLOW='\033[0;33m'
		BLUE='\033[0;36m'
		PLAIN='\033[0m'

		get_opsy() {
			[ -f /etc/redhat-release ] && awk '{print ($1,$3~/^[0-9]/?$3:$4)}' /etc/redhat-release && return
			[ -f /etc/os-release ] && awk -F'[= "]' '/PRETTY_NAME/{print $3,$4,$5}' /etc/os-release && return
			[ -f /etc/lsb-release ] && awk -F'[="]+' '/DESCRIPTION/{print $2}' /etc/lsb-release && return
		}

		next() {
			printf "%-70s\n" "-" | sed 's/\s/-/g'
		}

		speed_test_v4() {
			local output=$(LANG=C wget -4O /dev/null -T300 $1 2>&1)
			local speedtest=$(printf '%s' "$output" | awk '/\/dev\/null/ {speed=$3 $4} END {gsub(/\(|\)/,"",speed); print speed}')
			local ipaddress=$(printf '%s' "$output" | awk -F'|' '/Connecting to .*\|([^\|]+)\|/ {print $2}')
			local nodeName=$2
			printf "${YELLOW}%-32s${GREEN}%-24s${RED}%-14s${PLAIN}\n" "${nodeName}" "${ipaddress}" "${speedtest}"
		}

		speed_test_v6() {
			local output=$(LANG=C wget -6O /dev/null -T300 $1 2>&1)
			local speedtest=$(printf '%s' "$output" | awk '/\/dev\/null/ {speed=$3 $4} END {gsub(/\(|\)/,"",speed); print speed}')
			local ipaddress=$(printf '%s' "$output" | awk -F'|' '/Connecting to .*\|([^\|]+)\|/ {print $2}')
			local nodeName=$2
			printf "${YELLOW}%-32s${GREEN}%-24s${RED}%-14s${PLAIN}\n" "${nodeName}" "${ipaddress}" "${speedtest}"
		}

		speed_v4() {
			speed_test_v4 'http://cachefly.cachefly.net/100mb.test' 'CacheFly'
			speed_test_v4 'http://speedtest.tokyo2.linode.com/100MB-tokyo2.bin' 'Linode, Tokyo2, JP'
			speed_test_v4 'http://speedtest.singapore.linode.com/100MB-singapore.bin' 'Linode, Singapore, SG'
			speed_test_v4 'http://speedtest.london.linode.com/100MB-london.bin' 'Linode, London, UK'
			speed_test_v4 'http://speedtest.frankfurt.linode.com/100MB-frankfurt.bin' 'Linode, Frankfurt, DE'
			speed_test_v4 'http://speedtest.fremont.linode.com/100MB-fremont.bin' 'Linode, Fremont, CA'
			speed_test_v4 'http://speedtest.dal05.softlayer.com/downloads/test100.zip' 'Softlayer, Dallas, TX'
			speed_test_v4 'http://speedtest.sea01.softlayer.com/downloads/test100.zip' 'Softlayer, Seattle, WA'
			speed_test_v4 'http://speedtest.fra02.softlayer.com/downloads/test100.zip' 'Softlayer, Frankfurt, DE'
			speed_test_v4 'http://speedtest.sng01.softlayer.com/downloads/test100.zip' 'Softlayer, Singapore, SG'
			speed_test_v4 'http://speedtest.hkg02.softlayer.com/downloads/test100.zip' 'Softlayer, HongKong, CN'
		}

		speed_v6() {
			speed_test_v6 'http://speedtest.atlanta.linode.com/100MB-atlanta.bin' 'Linode, Atlanta, GA'
			speed_test_v6 'http://speedtest.dallas.linode.com/100MB-dallas.bin' 'Linode, Dallas, TX'
			speed_test_v6 'http://speedtest.newark.linode.com/100MB-newark.bin' 'Linode, Newark, NJ'
			speed_test_v6 'http://speedtest.singapore.linode.com/100MB-singapore.bin' 'Linode, Singapore, SG'
			speed_test_v6 'http://speedtest.tokyo2.linode.com/100MB-tokyo2.bin' 'Linode, Tokyo2, JP'
			speed_test_v6 'http://speedtest.sjc03.softlayer.com/downloads/test100.zip' 'Softlayer, San Jose, CA'
			speed_test_v6 'http://speedtest.wdc01.softlayer.com/downloads/test100.zip' 'Softlayer, Washington, WA'
			speed_test_v6 'http://speedtest.par01.softlayer.com/downloads/test100.zip' 'Softlayer, Paris, FR'
			speed_test_v6 'http://speedtest.sng01.softlayer.com/downloads/test100.zip' 'Softlayer, Singapore, SG'
			speed_test_v6 'http://speedtest.tok02.softlayer.com/downloads/test100.zip' 'Softlayer, Tokyo, JP'
		}

		io_test() {
			(LANG=C dd if=/dev/zero of=test_$$ bs=64k count=16k conv=fdatasync && rm -f test_$$ ) 2>&1 | awk -F, '{io=$NF} END { print io}' | sed 's/^[ \t]*//;s/[ \t]*$//'
		}

		calc_disk() {
			local total_size=0
			local array=$@
			for size in ${array[@]}
			do
				[ "${size}" == "0" ] && size_t=0 || size_t=`echo ${size:0:${#size}-1}`
				[ "`echo ${size:(-1)}`" == "K" ] && size=0
				[ "`echo ${size:(-1)}`" == "M" ] && size=$( awk 'BEGIN{printf "%.1f", '$size_t' / 1024}' )
				[ "`echo ${size:(-1)}`" == "T" ] && size=$( awk 'BEGIN{printf "%.1f", '$size_t' * 1024}' )
				[ "`echo ${size:(-1)}`" == "G" ] && size=${size_t}
				total_size=$( awk 'BEGIN{printf "%.1f", '$total_size' + '$size'}' )
			done
			echo ${total_size}
		}

		cname=$( awk -F: '/model name/ {name=$2} END {print name}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//' )
		cores=$( awk -F: '/model name/ {core++} END {print core}' /proc/cpuinfo )
		freq=$( awk -F'[ :]' '/cpu MHz/ {print $4;exit}' /proc/cpuinfo )
		tram=$( free -m | awk '/Mem/ {print $2}' )
		uram=$( free -m | awk '/Mem/ {print $3}' )
		swap=$( free -m | awk '/Swap/ {print $2}' )
		uswap=$( free -m | awk '/Swap/ {print $3}' )
		up=$( awk '{a=$1/86400;b=($1%86400)/3600;c=($1%3600)/60} {printf("%d days, %d hour %d min\n",a,b,c)}' /proc/uptime )
		load=$( w | head -1 | awk -F'load average:' '{print $2}' | sed 's/^[ \t]*//;s/[ \t]*$//' )
		opsy=$( get_opsy )
		arch=$( uname -m )
		lbit=$( getconf LONG_BIT )
		kern=$( uname -r )
		#ipv6=$( wget -qO- -t1 -T2 ipv6.icanhazip.com )
		disk_size1=($( LANG=C df -hPl | grep -wvE '\-|none|tmpfs|devtmpfs|by-uuid|chroot|Filesystem|udev|docker' | awk '{print $2}' ))
		disk_size2=($( LANG=C df -hPl | grep -wvE '\-|none|tmpfs|devtmpfs|by-uuid|chroot|Filesystem|udev|docker' | awk '{print $3}' ))
		disk_total_size=$( calc_disk "${disk_size1[@]}" )
		disk_used_size=$( calc_disk "${disk_size2[@]}" )

		clear
		next
		echo -e "CPU model            : ${BLUE}$cname${PLAIN}"
		echo -e "Number of cores      : ${BLUE}$cores${PLAIN}"
		echo -e "CPU frequency        : ${BLUE}$freq MHz${PLAIN}"
		echo -e "Total size of Disk   : ${BLUE}$disk_total_size GB ($disk_used_size GB Used)${PLAIN}"
		echo -e "Total amount of Mem  : ${BLUE}$tram MB ($uram MB Used)${PLAIN}"
		echo -e "Total amount of Swap : ${BLUE}$swap MB ($uswap MB Used)${PLAIN}"
		echo -e "System uptime        : ${BLUE}$up${PLAIN}"
		echo -e "Load average         : ${BLUE}$load${PLAIN}"
		echo -e "OS                   : ${BLUE}$opsy${PLAIN}"
		echo -e "Arch                 : ${BLUE}$arch ($lbit Bit)${PLAIN}"
		echo -e "Kernel               : ${BLUE}$kern${PLAIN}"
		next
		io1=$( io_test )
		echo -e "I/O speed(1st run)   : ${YELLOW}$io1${PLAIN}"
		io2=$( io_test )
		echo -e "I/O speed(2nd run)   : ${YELLOW}$io2${PLAIN}"
		io3=$( io_test )
		echo -e "I/O speed(3rd run)   : ${YELLOW}$io3${PLAIN}"
		ioraw1=$( echo $io1 | awk 'NR==1 {print $1}' )
		[ "`echo $io1 | awk 'NR==1 {print $2}'`" == "GB/s" ] && ioraw1=$( awk 'BEGIN{print '$ioraw1' * 1024}' )
		ioraw2=$( echo $io2 | awk 'NR==1 {print $1}' )
		[ "`echo $io2 | awk 'NR==1 {print $2}'`" == "GB/s" ] && ioraw2=$( awk 'BEGIN{print '$ioraw2' * 1024}' )
		ioraw3=$( echo $io3 | awk 'NR==1 {print $1}' )
		[ "`echo $io3 | awk 'NR==1 {print $2}'`" == "GB/s" ] && ioraw3=$( awk 'BEGIN{print '$ioraw3' * 1024}' )
		ioall=$( awk 'BEGIN{print '$ioraw1' + '$ioraw2' + '$ioraw3'}' )
		ioavg=$( awk 'BEGIN{printf "%.1f", '$ioall' / 3}' )
		echo -e "Average I/O speed    : ${YELLOW}$ioavg MB/s${PLAIN}"
		next
		printf "%-32s%-24s%-14s\n" "Node Name" "IPv4 address" "Download Speed"
		speed_v4 && next
		#if [[ "$ipv6" != "" ]]; then
		#    printf "%-32s%-24s%-14s\n" "Node Name" "IPv6 address" "Download Speed"
		#    speed_v6 && next
		#fi
	}
	
	#国内各地检测
	cbench(){
		#!/usr/bin/env bash
		#
		# Description: Auto system info & I/O test & network to China script
		#
		# Copyright (C) 2017 - 2018 Oldking <oooldking@gmail.com>
		#
		# Thanks: Bench.sh <i@teddysun.com>
		#
		# URL: https://www.oldking.net/350.html
		#

		# Colors
		RED='\033[0;31m'
		GREEN='\033[0;32m'
		YELLOW='\033[0;33m'
		SKYBLUE='\033[0;36m'
		PLAIN='\033[0m'

		about() {
			echo ""
			echo " ========================================================= "
			echo " \                 Superbench.sh  Script                 / "
			echo " \       Basic system info, I/O test and speedtest       / "
			echo " \                   v1.1.5 (14 Jun 2019)                / "
			echo " \                   Created by Oldking                  / "
			echo " ========================================================= "
			echo ""
			echo " Intro: https://www.oldking.net/350.html"
			echo " Copyright (C) 2019 Oldking oooldking@gmail.com"
			echo -e " ${RED}Happy New Year!${PLAIN}"
			echo ""
		}

		cancel() {
			echo ""
			next;
			echo " Abort ..."
			echo " Cleanup ..."
			cleanup;
			echo " Done"
			exit
		}

		trap cancel SIGINT

		benchinit() {
			# check release
			if [ -f /etc/redhat-release ]; then
				release="centos"
			elif cat /etc/issue | grep -Eqi "debian"; then
				release="debian"
			elif cat /etc/issue | grep -Eqi "ubuntu"; then
				release="ubuntu"
			elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
				release="centos"
			elif cat /proc/version | grep -Eqi "debian"; then
				release="debian"
			elif cat /proc/version | grep -Eqi "ubuntu"; then
				release="ubuntu"
			elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
				release="centos"
			fi

			# check root
			[[ $EUID -ne 0 ]] && echo -e "${RED}Error:${PLAIN} This script must be run as root!" && exit 1

			# check python
			if  [ ! -e '/usr/bin/python' ]; then
					#echo -e
					#read -p "${RED}Error:${PLAIN} python is not install. You must be install python command at first.\nDo you want to install? [y/n]" is_install
					#if [[ ${is_install} == "y" || ${is_install} == "Y" ]]; then
					echo " Installing Python ..."
						if [ "${release}" == "centos" ]; then
								yum update > /dev/null 2>&1
								yum -y install python > /dev/null 2>&1
							else
								apt-get update > /dev/null 2>&1
								apt-get -y install python > /dev/null 2>&1
							fi
					#else
					#    exit
					#fi
					
			fi

			# check curl
			if  [ ! -e '/usr/bin/curl' ]; then
				#echo -e
				#read -p "${RED}Error:${PLAIN} curl is not install. You must be install curl command at first.\nDo you want to install? [y/n]" is_install
				#if [[ ${is_install} == "y" || ${is_install} == "Y" ]]; then
					echo " Installing Curl ..."
						if [ "${release}" == "centos" ]; then
							yum update > /dev/null 2>&1
							yum -y install curl > /dev/null 2>&1
						else
							apt-get update > /dev/null 2>&1
							apt-get -y install curl > /dev/null 2>&1
						fi
				#else
				#    exit
				#fi
			fi

			# check wget
			if  [ ! -e '/usr/bin/wget' ]; then
				#echo -e
				#read -p "${RED}Error:${PLAIN} wget is not install. You must be install wget command at first.\nDo you want to install? [y/n]" is_install
				#if [[ ${is_install} == "y" || ${is_install} == "Y" ]]; then
					echo " Installing Wget ..."
						if [ "${release}" == "centos" ]; then
							yum update > /dev/null 2>&1
							yum -y install wget > /dev/null 2>&1
						else
							apt-get update > /dev/null 2>&1
							apt-get -y install wget > /dev/null 2>&1
						fi
				#else
				#    exit
				#fi
			fi

			# install virt-what
			#if  [ ! -e '/usr/sbin/virt-what' ]; then
			#	echo "Installing Virt-what ..."
			#    if [ "${release}" == "centos" ]; then
			#    	yum update > /dev/null 2>&1
			#        yum -y install virt-what > /dev/null 2>&1
			#    else
			#    	apt-get update > /dev/null 2>&1
			#        apt-get -y install virt-what > /dev/null 2>&1
			#    fi      
			#fi

			# install jq
			#if  [ ! -e '/usr/bin/jq' ]; then
			# 	echo " Installing Jq ..."
			#		if [ "${release}" == "centos" ]; then
			#	    yum update > /dev/null 2>&1
			#	    yum -y install jq > /dev/null 2>&1
			#	else
			#	    apt-get update > /dev/null 2>&1
			#	    apt-get -y install jq > /dev/null 2>&1
			#	fi      
			#fi

			# install speedtest-cli
			if  [ ! -e 'speedtest.py' ]; then
				echo " Installing Speedtest-cli ..."
				wget --no-check-certificate https://raw.github.com/sivel/speedtest-cli/master/speedtest.py > /dev/null 2>&1
			fi
			chmod a+rx speedtest.py


			# install tools.py
			if  [ ! -e 'tools.py' ]; then
				echo " Installing tools.py ..."
				wget --no-check-certificate https://raw.githubusercontent.com/oooldking/script/master/tools.py > /dev/null 2>&1
			fi
			chmod a+rx tools.py

			# install fast.com-cli
			if  [ ! -e 'fast_com.py' ]; then
				echo " Installing Fast.com-cli ..."
				wget --no-check-certificate https://raw.githubusercontent.com/sanderjo/fast.com/master/fast_com.py > /dev/null 2>&1
				wget --no-check-certificate https://raw.githubusercontent.com/sanderjo/fast.com/master/fast_com_example_usage.py > /dev/null 2>&1
			fi
			chmod a+rx fast_com.py
			chmod a+rx fast_com_example_usage.py

			sleep 5

			# start
			start=$(date +%s) 
		}

		get_opsy() {
			[ -f /etc/redhat-release ] && awk '{print ($1,$3~/^[0-9]/?$3:$4)}' /etc/redhat-release && return
			[ -f /etc/os-release ] && awk -F'[= "]' '/PRETTY_NAME/{print $3,$4,$5}' /etc/os-release && return
			[ -f /etc/lsb-release ] && awk -F'[="]+' '/DESCRIPTION/{print $2}' /etc/lsb-release && return
		}

		next() {
			printf "%-70s\n" "-" | sed 's/\s/-/g' | tee -a $log
		}

		speed_test(){
			if [[ $1 == '' ]]; then
				temp=$(python speedtest.py --share 2>&1)
				is_down=$(echo "$temp" | grep 'Download')
				result_speed=$(echo "$temp" | awk -F ' ' '/results/{print $3}')
				if [[ ${is_down} ]]; then
					local REDownload=$(echo "$temp" | awk -F ':' '/Download/{print $2}')
					local reupload=$(echo "$temp" | awk -F ':' '/Upload/{print $2}')
					local relatency=$(echo "$temp" | awk -F ':' '/Hosted/{print $2}')

					temp=$(echo "$relatency" | awk -F '.' '{print $1}')
					if [[ ${temp} -gt 50 ]]; then
						relatency=" (*)"${relatency}
					fi
					local nodeName=$2

					temp=$(echo "${REDownload}" | awk -F ' ' '{print $1}')
					if [[ $(awk -v num1=${temp} -v num2=0 'BEGIN{print(num1>num2)?"1":"0"}') -eq 1 ]]; then
						printf "${YELLOW}%-17s${GREEN}%-18s${RED}%-20s${SKYBLUE}%-12s${PLAIN}\n" " ${nodeName}" "${reupload}" "${REDownload}" "${relatency}" | tee -a $log
					fi
				else
					local cerror="ERROR"
				fi
			else
				temp=$(python speedtest.py --server $1 --share 2>&1)
				is_down=$(echo "$temp" | grep 'Download') 
				if [[ ${is_down} ]]; then
					local REDownload=$(echo "$temp" | awk -F ':' '/Download/{print $2}')
					local reupload=$(echo "$temp" | awk -F ':' '/Upload/{print $2}')
					local relatency=$(echo "$temp" | awk -F ':' '/Hosted/{print $2}')
					#local relatency=$(pingtest $3)
					#temp=$(echo "$relatency" | awk -F '.' '{print $1}')
					#if [[ ${temp} -gt 1000 ]]; then
						relatency=" - "
					#fi
					local nodeName=$2

					temp=$(echo "${REDownload}" | awk -F ' ' '{print $1}')
					if [[ $(awk -v num1=${temp} -v num2=0 'BEGIN{print(num1>num2)?"1":"0"}') -eq 1 ]]; then
						printf "${YELLOW}%-17s${GREEN}%-18s${RED}%-20s${SKYBLUE}%-12s${PLAIN}\n" " ${nodeName}" "${reupload}" "${REDownload}" "${relatency}" | tee -a $log
					fi
				else
					local cerror="ERROR"
				fi
			fi
		}

		print_speedtest() {
			printf "%-18s%-18s%-20s%-12s\n" " Node Name" "Upload Speed" "Download Speed" "Latency" | tee -a $log
			speed_test '' 'Speedtest.net'
			speed_fast_com
			speed_test '17251' 'Guangzhou CT'
			speed_test '23844' 'Wuhan     CT'
			speed_test '7509' 'Hangzhou  CT'
			speed_test '3973' 'Lanzhou   CT'
			speed_test '24447' 'Shanghai  CU'
			speed_test '5724' "Heifei    CU"
			speed_test '5726' 'Chongqing CU'
			speed_test '17228' 'Xinjiang  CM'
			speed_test '18444' 'Xizang    CM'
			 
			rm -rf speedtest.py
		}

		print_speedtest_fast() {
			printf "%-18s%-18s%-20s%-12s\n" " Node Name" "Upload Speed" "Download Speed" "Latency" | tee -a $log
			speed_test '' 'Speedtest.net'
			speed_fast_com
			speed_test '7509' 'Hangzhou  CT'
			speed_test '24447' 'Shanghai  CU'
			speed_test '18444' 'Xizang    CM'
			 
			rm -rf speedtest.py
		}

		speed_fast_com() {
			temp=$(python fast_com_example_usage.py 2>&1)
			is_down=$(echo "$temp" | grep 'Result') 
				if [[ ${is_down} ]]; then
					temp1=$(echo "$temp" | awk -F ':' '/Result/{print $2}')
					temp2=$(echo "$temp1" | awk -F ' ' '/Mbps/{print $1}')
					local REDownload="$temp2 Mbit/s"
					local reupload="0.00 Mbit/s"
					local relatency="-"
					local nodeName="Fast.com"

					printf "${YELLOW}%-18s${GREEN}%-18s${RED}%-20s${SKYBLUE}%-12s${PLAIN}\n" " ${nodeName}" "${reupload}" "${REDownload}" "${relatency}" | tee -a $log
				else
					local cerror="ERROR"
				fi
			rm -rf fast_com_example_usage.py
			rm -rf fast_com.py

		}

		io_test() {
			(LANG=C dd if=/dev/zero of=test_file_$$ bs=512K count=$1 conv=fdatasync && rm -f test_file_$$ ) 2>&1 | awk -F, '{io=$NF} END { print io}' | sed 's/^[ \t]*//;s/[ \t]*$//'
		}

		calc_disk() {
			local total_size=0
			local array=$@
			for size in ${array[@]}
			do
				[ "${size}" == "0" ] && size_t=0 || size_t=`echo ${size:0:${#size}-1}`
				[ "`echo ${size:(-1)}`" == "K" ] && size=0
				[ "`echo ${size:(-1)}`" == "M" ] && size=$( awk 'BEGIN{printf "%.1f", '$size_t' / 1024}' )
				[ "`echo ${size:(-1)}`" == "T" ] && size=$( awk 'BEGIN{printf "%.1f", '$size_t' * 1024}' )
				[ "`echo ${size:(-1)}`" == "G" ] && size=${size_t}
				total_size=$( awk 'BEGIN{printf "%.1f", '$total_size' + '$size'}' )
			done
			echo ${total_size}
		}

		power_time() {

			result=$(smartctl -a $(result=$(cat /proc/mounts) && echo $(echo "$result" | awk '/data=ordered/{print $1}') | awk '{print $1}') 2>&1) && power_time=$(echo "$result" | awk '/Power_On/{print $10}') && echo "$power_time"
		}

		install_smart() {
			# install smartctl
			if  [ ! -e '/usr/sbin/smartctl' ]; then
				echo "Installing Smartctl ..."
				if [ "${release}" == "centos" ]; then
					yum update > /dev/null 2>&1
					yum -y install smartmontools > /dev/null 2>&1
				else
					apt-get update > /dev/null 2>&1
					apt-get -y install smartmontools > /dev/null 2>&1
				fi      
			fi
		}

		ip_info(){
			# use jq tool
			result=$(curl -s 'http://ip-api.com/json')
			country=$(echo $result | jq '.country' | sed 's/\"//g')
			city=$(echo $result | jq '.city' | sed 's/\"//g')
			isp=$(echo $result | jq '.isp' | sed 's/\"//g')
			as_tmp=$(echo $result | jq '.as' | sed 's/\"//g')
			asn=$(echo $as_tmp | awk -F ' ' '{print $1}')
			org=$(echo $result | jq '.org' | sed 's/\"//g')
			countryCode=$(echo $result | jq '.countryCode' | sed 's/\"//g')
			region=$(echo $result | jq '.regionName' | sed 's/\"//g')
			if [ -z "$city" ]; then
				city=${region}
			fi

			echo -e " ASN & ISP            : ${SKYBLUE}$asn, $isp${PLAIN}" | tee -a $log
			echo -e " Organization         : ${YELLOW}$org${PLAIN}" | tee -a $log
			echo -e " Location             : ${SKYBLUE}$city, ${YELLOW}$country / $countryCode${PLAIN}" | tee -a $log
			echo -e " Region               : ${SKYBLUE}$region${PLAIN}" | tee -a $log
		}

		ip_info2(){
			# no jq
			country=$(curl -s https://ipapi.co/country_name/)
			city=$(curl -s https://ipapi.co/city/)
			asn=$(curl -s https://ipapi.co/asn/)
			org=$(curl -s https://ipapi.co/org/)
			countryCode=$(curl -s https://ipapi.co/country/)
			region=$(curl -s https://ipapi.co/region/)

			echo -e " ASN & ISP            : ${SKYBLUE}$asn${PLAIN}" | tee -a $log
			echo -e " Organization         : ${SKYBLUE}$org${PLAIN}" | tee -a $log
			echo -e " Location             : ${SKYBLUE}$city, ${GREEN}$country / $countryCode${PLAIN}" | tee -a $log
			echo -e " Region               : ${SKYBLUE}$region${PLAIN}" | tee -a $log
		}

		ip_info3(){
			# use python tool
			country=$(python ip_info.py country)
			city=$(python ip_info.py city)
			isp=$(python ip_info.py isp)
			as_tmp=$(python ip_info.py as)
			asn=$(echo $as_tmp | awk -F ' ' '{print $1}')
			org=$(python ip_info.py org)
			countryCode=$(python ip_info.py countryCode)
			region=$(python ip_info.py regionName)

			echo -e " ASN & ISP            : ${SKYBLUE}$asn, $isp${PLAIN}" | tee -a $log
			echo -e " Organization         : ${GREEN}$org${PLAIN}" | tee -a $log
			echo -e " Location             : ${SKYBLUE}$city, ${GREEN}$country / $countryCode${PLAIN}" | tee -a $log
			echo -e " Region               : ${SKYBLUE}$region${PLAIN}" | tee -a $log

			rm -rf ip_info.py
		}

		ip_info4(){
			ip_date=$(curl -4 -s http://api.ip.la/en?json)
			echo $ip_date > ip_json.json
			isp=$(python tools.py geoip isp)
			as_tmp=$(python tools.py geoip as)
			asn=$(echo $as_tmp | awk -F ' ' '{print $1}')
			org=$(python tools.py geoip org)
			if [ -z "ip_date" ]; then
				echo $ip_date
				echo "hala"
				country=$(python tools.py ipip country_name)
				city=$(python tools.py ipip city)
				countryCode=$(python tools.py ipip country_code)
				region=$(python tools.py ipip province)
			else
				country=$(python tools.py geoip country)
				city=$(python tools.py geoip city)
				countryCode=$(python tools.py geoip countryCode)
				region=$(python tools.py geoip regionName)	
			fi
			if [ -z "$city" ]; then
				city=${region}
			fi

			echo -e " ASN & ISP            : ${SKYBLUE}$asn, $isp${PLAIN}" | tee -a $log
			echo -e " Organization         : ${YELLOW}$org${PLAIN}" | tee -a $log
			echo -e " Location             : ${SKYBLUE}$city, ${YELLOW}$country / $countryCode${PLAIN}" | tee -a $log
			echo -e " Region               : ${SKYBLUE}$region${PLAIN}" | tee -a $log

			rm -rf tools.py
			rm -rf ip_json.json
		}

		virt_check(){
			if hash ifconfig 2>/dev/null; then
				eth=$(ifconfig)
			fi

			virtualx=$(dmesg) 2>/dev/null

			# check dmidecode cmd
			if  [ $(which dmidecode) ]; then
				sys_manu=$(dmidecode -s system-manufacturer) 2>/dev/null
				sys_product=$(dmidecode -s system-product-name) 2>/dev/null
				sys_ver=$(dmidecode -s system-version) 2>/dev/null
			else
				sys_manu=""
				sys_product=""
				sys_ver=""
			fi
			
			if grep docker /proc/1/cgroup -qa; then
				virtual="Docker"
			elif grep lxc /proc/1/cgroup -qa; then
				virtual="Lxc"
			elif grep -qa container=lxc /proc/1/environ; then
				virtual="Lxc"
			elif [[ -f /proc/user_beancounters ]]; then
				virtual="OpenVZ"
			elif [[ "$virtualx" == *kvm-clock* ]]; then
				virtual="KVM"
			elif [[ "$cname" == *KVM* ]]; then
				virtual="KVM"
			elif [[ "$virtualx" == *"VMware Virtual Platform"* ]]; then
				virtual="VMware"
			elif [[ "$virtualx" == *"Parallels Software International"* ]]; then
				virtual="Parallels"
			elif [[ "$virtualx" == *VirtualBox* ]]; then
				virtual="VirtualBox"
			elif [[ -e /proc/xen ]]; then
				virtual="Xen"
			elif [[ "$sys_manu" == *"Microsoft Corporation"* ]]; then
				if [[ "$sys_product" == *"Virtual Machine"* ]]; then
					if [[ "$sys_ver" == *"7.0"* || "$sys_ver" == *"Hyper-V" ]]; then
						virtual="Hyper-V"
					else
						virtual="Microsoft Virtual Machine"
					fi
				fi
			else
				virtual="Dedicated"
			fi
		}

		power_time_check(){
			echo -ne " Power time of disk   : "
			install_smart
			ptime=$(power_time)
			echo -e "${SKYBLUE}$ptime Hours${PLAIN}"
		}

		freedisk() {
			# check free space
			#spacename=$( df -m . | awk 'NR==2 {print $1}' )
			#spacenamelength=$(echo ${spacename} | awk '{print length($0)}')
			#if [[ $spacenamelength -gt 20 ]]; then
			#	freespace=$( df -m . | awk 'NR==3 {print $3}' )
			#else
			#	freespace=$( df -m . | awk 'NR==2 {print $4}' )
			#fi
			freespace=$( df -m . | awk 'NR==2 {print $4}' )
			if [[ $freespace == "" ]]; then
				$freespace=$( df -m . | awk 'NR==3 {print $3}' )
			fi
			if [[ $freespace -gt 1024 ]]; then
				printf "%s" $((1024*2))
			elif [[ $freespace -gt 512 ]]; then
				printf "%s" $((512*2))
			elif [[ $freespace -gt 256 ]]; then
				printf "%s" $((256*2))
			elif [[ $freespace -gt 128 ]]; then
				printf "%s" $((128*2))
			else
				printf "1"
			fi
		}

		print_io() {
			if [[ $1 == "fast" ]]; then
				writemb=$((128*2))
			else
				writemb=$(freedisk)
			fi
			
			writemb_size="$(( writemb / 2 ))MB"
			if [[ $writemb_size == "1024MB" ]]; then
				writemb_size="1.0GB"
			fi

			if [[ $writemb != "1" ]]; then
				echo -n " I/O Speed( $writemb_size )   : " | tee -a $log
				io1=$( io_test $writemb )
				echo -e "${YELLOW}$io1${PLAIN}" | tee -a $log
				echo -n " I/O Speed( $writemb_size )   : " | tee -a $log
				io2=$( io_test $writemb )
				echo -e "${YELLOW}$io2${PLAIN}" | tee -a $log
				echo -n " I/O Speed( $writemb_size )   : " | tee -a $log
				io3=$( io_test $writemb )
				echo -e "${YELLOW}$io3${PLAIN}" | tee -a $log
				ioraw1=$( echo $io1 | awk 'NR==1 {print $1}' )
				[ "`echo $io1 | awk 'NR==1 {print $2}'`" == "GB/s" ] && ioraw1=$( awk 'BEGIN{print '$ioraw1' * 1024}' )
				ioraw2=$( echo $io2 | awk 'NR==1 {print $1}' )
				[ "`echo $io2 | awk 'NR==1 {print $2}'`" == "GB/s" ] && ioraw2=$( awk 'BEGIN{print '$ioraw2' * 1024}' )
				ioraw3=$( echo $io3 | awk 'NR==1 {print $1}' )
				[ "`echo $io3 | awk 'NR==1 {print $2}'`" == "GB/s" ] && ioraw3=$( awk 'BEGIN{print '$ioraw3' * 1024}' )
				ioall=$( awk 'BEGIN{print '$ioraw1' + '$ioraw2' + '$ioraw3'}' )
				ioavg=$( awk 'BEGIN{printf "%.1f", '$ioall' / 3}' )
				echo -e " Average I/O Speed    : ${YELLOW}$ioavg MB/s${PLAIN}" | tee -a $log
			else
				echo -e " ${RED}Not enough space!${PLAIN}"
			fi
		}

		print_system_info() {
			echo -e " CPU Model            : ${SKYBLUE}$cname${PLAIN}" | tee -a $log
			echo -e " CPU Cores            : ${YELLOW}$cores Cores ${SKYBLUE}@ $freq MHz $arch${PLAIN}" | tee -a $log
			echo -e " CPU Cache            : ${SKYBLUE}$corescache ${PLAIN}" | tee -a $log
			echo -e " OS                   : ${SKYBLUE}$opsy ($lbit Bit) ${YELLOW}$virtual${PLAIN}" | tee -a $log
			echo -e " Kernel               : ${SKYBLUE}$kern${PLAIN}" | tee -a $log
			echo -e " Total Space          : ${SKYBLUE}$disk_used_size GB / ${YELLOW}$disk_total_size GB ${PLAIN}" | tee -a $log
			echo -e " Total RAM            : ${SKYBLUE}$uram MB / ${YELLOW}$tram MB ${SKYBLUE}($bram MB Buff)${PLAIN}" | tee -a $log
			echo -e " Total SWAP           : ${SKYBLUE}$uswap MB / $swap MB${PLAIN}" | tee -a $log
			echo -e " Uptime               : ${SKYBLUE}$up${PLAIN}" | tee -a $log
			echo -e " Load Average         : ${SKYBLUE}$load${PLAIN}" | tee -a $log
			echo -e " TCP CC               : ${YELLOW}$tcpctrl${PLAIN}" | tee -a $log
		}

		print_end_time() {
			end=$(date +%s) 
			time=$(( $end - $start ))
			if [[ $time -gt 60 ]]; then
				min=$(expr $time / 60)
				sec=$(expr $time % 60)
				echo -ne " Finished in  : ${min} min ${sec} sec" | tee -a $log
			else
				echo -ne " Finished in  : ${time} sec" | tee -a $log
			fi
			#echo -ne "\n Current time : "
			#echo $(date +%Y-%m-%d" "%H:%M:%S)
			printf '\n' | tee -a $log
			#utc_time=$(date -u '+%F %T')
			#bj_time=$(date +%Y-%m-%d" "%H:%M:%S -d '+8 hours')
			bj_time=$(curl -s http://cgi.im.qq.com/cgi-bin/cgi_svrtime)
			#utc_time=$(date +"$bj_time" -d '-8 hours')

			if [[ $(echo $bj_time | grep "html") ]]; then
				bj_time=$(date -u +%Y-%m-%d" "%H:%M:%S -d '+8 hours')
			fi
			echo " Timestamp    : $bj_time GMT+8" | tee -a $log
			#echo " Finished!"
			echo " Results      : $log"
		}

		get_system_info() {
			cname=$( awk -F: '/model name/ {name=$2} END {print name}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//' )
			cores=$( awk -F: '/model name/ {core++} END {print core}' /proc/cpuinfo )
			freq=$( awk -F: '/cpu MHz/ {freq=$2} END {print freq}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//' )
			corescache=$( awk -F: '/cache size/ {cache=$2} END {print cache}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//' )
			tram=$( free -m | awk '/Mem/ {print $2}' )
			uram=$( free -m | awk '/Mem/ {print $3}' )
			bram=$( free -m | awk '/Mem/ {print $6}' )
			swap=$( free -m | awk '/Swap/ {print $2}' )
			uswap=$( free -m | awk '/Swap/ {print $3}' )
			up=$( awk '{a=$1/86400;b=($1%86400)/3600;c=($1%3600)/60} {printf("%d days %d hour %d min\n",a,b,c)}' /proc/uptime )
			load=$( w | head -1 | awk -F'load average:' '{print $2}' | sed 's/^[ \t]*//;s/[ \t]*$//' )
			opsy=$( get_opsy )
			arch=$( uname -m )
			lbit=$( getconf LONG_BIT )
			kern=$( uname -r )
			#ipv6=$( wget -qO- -t1 -T2 ipv6.icanhazip.com )
			disk_size1=($( LANG=C df -hPl | grep -wvE '\-|none|tmpfs|overlay|shm|udev|devtmpfs|by-uuid|chroot|Filesystem' | awk '{print $2}' ))
			disk_size2=($( LANG=C df -hPl | grep -wvE '\-|none|tmpfs|overlay|shm|udev|devtmpfs|by-uuid|chroot|Filesystem' | awk '{print $3}' ))
			disk_total_size=$( calc_disk ${disk_size1[@]} )
			disk_used_size=$( calc_disk ${disk_size2[@]} )
			#tcp congestion control
			tcpctrl=$( sysctl net.ipv4.tcp_congestion_control | awk -F ' ' '{print $3}' )

			#tmp=$(python tools.py disk 0)
			#disk_total_size=$(echo $tmp | sed s/G//)
			#tmp=$(python tools.py disk 1)
			#disk_used_size=$(echo $tmp | sed s/G//)

			virt_check
		}

		print_intro() {
			printf ' Superbench.sh -- https://www.oldking.net/350.html\n' | tee -a $log
			printf " Mode  : \e${GREEN}%s\e${PLAIN}    Version : \e${GREEN}%s${PLAIN}\n" $mode_name 1.1.5 | tee -a $log
			printf ' Usage : wget -qO- git.io/superbench.sh | bash\n' | tee -a $log
		}

		sharetest() {
			echo " Share result:" | tee -a $log
			echo " · $result_speed" | tee -a $log
			log_preupload
			case $1 in
			'ubuntu')
				share_link=$( curl -v --data-urlencode "content@$log_up" -d "poster=superbench.sh" -d "syntax=text" "https://paste.ubuntu.com" 2>&1 | \
					grep "Location" | awk '{print $3}' );;
			'haste' )
				share_link=$( curl -X POST -s -d "$(cat $log)" https://hastebin.com/documents | awk -F '"' '{print "https://hastebin.com/"$4}' );;
			'clbin' )
				share_link=$( curl -sF 'clbin=<-' https://clbin.com < $log );;
			'ptpb' )
				share_link=$( curl -sF c=@- https://ptpb.pw/?u=1 < $log );;
			esac

			# print result info
			echo " · $share_link" | tee -a $log
			next
			echo ""
			rm -f $log_up

		}

		log_preupload() {
			log_up="$HOME/superbench_upload.log"
			true > $log_up
			$(cat superbench.log 2>&1 | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g" > $log_up)
		}

		get_ip_whois_org_name(){
			#ip=$(curl -s ip.sb)
			result=$(curl -s https://rest.db.ripe.net/search.json?query-string=$(curl -s ip.sb))
			#org_name=$(echo $result | jq '.objects.object.[1].attributes.attribute.[1].value' | sed 's/\"//g')
			org_name=$(echo $result | jq '.objects.object[1].attributes.attribute[1]' | sed 's/\"//g')
			echo $org_name;
		}

		pingtest() {
			local ping_ms=$( ping -w 1 -c 1 $1 | grep 'rtt' | cut -d"/" -f5 )

			# get download speed and print
			if [[ $ping_ms == "" ]]; then
				printf "ping error!"  | tee -a $log
			else
				printf "%3i.%s ms" "${ping_ms%.*}" "${ping_ms#*.}"  | tee -a $log
			fi
		}

		cleanup() {
			rm -f test_file_*;
			rm -f speedtest.py;
			rm -f fast_com*;
			rm -f tools.py;
			rm -f ip_json.json
		}

		bench_all(){
			mode_name="Standard"
			about;
			benchinit;
			clear
			next;
			print_intro;
			next;
			get_system_info;
			print_system_info;
			ip_info4;
			next;
			print_io;
			next;
			print_speedtest;
			next;
			print_end_time;
			next;
			cleanup;
			sharetest ubuntu;
		}

		fast_bench(){
			mode_name="Fast"
			about;
			benchinit;
			clear
			next;
			print_intro;
			next;
			get_system_info;
			print_system_info;
			ip_info4;
			next;
			print_io fast;
			next;
			print_speedtest_fast;
			next;
			print_end_time;
			next;
			cleanup;
		}




		log="$HOME/superbench.log"
		true > $log

		case $1 in
			'info'|'-i'|'--i'|'-info'|'--info' )
				about;sleep 3;next;get_system_info;print_system_info;next;;
			'version'|'-v'|'--v'|'-version'|'--version')
				next;about;next;;
			'io'|'-io'|'--io'|'-drivespeed'|'--drivespeed' )
				next;print_io;next;;
			'speed'|'-speed'|'--speed'|'-speedtest'|'--speedtest'|'-speedcheck'|'--speedcheck' )
				about;benchinit;next;print_speedtest;next;cleanup;;
			'ip'|'-ip'|'--ip'|'geoip'|'-geoip'|'--geoip' )
				about;benchinit;next;ip_info4;next;cleanup;;
			'bench'|'-a'|'--a'|'-all'|'--all'|'-bench'|'--bench' )
				bench_all;;
			'about'|'-about'|'--about' )
				about;;
			'fast'|'-f'|'--f'|'-fast'|'--fast' )
				fast_bench;;
			'share'|'-s'|'--s'|'-share'|'--share' )
				bench_all;
				is_share="share"
				if [[ $2 == "" ]]; then
					sharetest ubuntu;
				else
					sharetest $2;
				fi
				;;
			'debug'|'-d'|'--d'|'-debug'|'--debug' )
				get_ip_whois_org_name;;
		*)
			bench_all;;
		esac



		if [[  ! $is_share == "share" ]]; then
			case $2 in
				'share'|'-s'|'--s'|'-share'|'--share' )
					if [[ $3 == '' ]]; then
						sharetest ubuntu;
					else
						sharetest $3;
					fi
					;;
			esac
		fi
	}
	
	#开始菜单
	start_menu_bench(){
		clear
		echo && echo -e " 系统性能一键测试脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
		  -- 胖波比 --
		
————————————性能测试————————————
 ${Green_font_prefix}1.${Font_color_suffix} 执行国际测试
 ${Green_font_prefix}2.${Font_color_suffix} 执行国内三网测试
 ${Green_font_prefix}3.${Font_color_suffix} 退出脚本
————————————————————————————————" && echo

		echo
		read -p " 请输入数字 [1-3]:" num
		case "$num" in
			1)
			ibench
			;;
			2)
			cbench
			;;
			3)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}:请输入正确数字 [1-3]"
			sleep 5s
			start_menu_bench
			;;
		esac
	}
	
	start_menu_bench
}

#安装Nginx
install_nginx(){
        if [[ "${release}" == "centos" ]]; then
	         setsebool -P httpd_can_network_connect 1
                 touch /etc/yum.repos.d/nginx.repo
cat <<EOF > /etc/yum.repos.d/nginx.repo
[nginx]
name=nginx repo
baseurl=http://nginx.org/packages/mainline/centos/7/\$basearch/
gpgcheck=0
enabled=1
EOF
                 yum -y install nginx
        elif [[ "${release}" == "debian" ]]; then
                 echo "deb http://nginx.org/packages/debian/ stretch nginx" >> /etc/apt/sources.list
                 echo "deb-src http://nginx.org/packages/debian/ stretch nginx" >> /etc/apt/sources.list
                 wget http://nginx.org/keys/nginx_signing.key >/dev/null 2>&1
		 apt-key add nginx_signing.key >/dev/null 2>&1
                 apt-get update
                 apt-get -y install nginx
                 rm -rf add nginx_signing.key >/dev/null 2>&1
        elif [[ "${release}" == "ubuntu" ]]; then
                 echo "deb http://nginx.org/packages/mainline/ubuntu/ bionic nginx" >> /etc/apt/sources.list
		 echo "deb http://nginx.org/packages/mainline/ubuntu/ xenial nginx" >> /etc/apt/sources.list
                 echo "deb-src http://nginx.org/packages/mainline/ubuntu/ bionic nginx" >> /etc/apt/sources.list
		 echo "deb-src http://nginx.org/packages/mainline/ubuntu/ xenial nginx" >> /etc/apt/sources.list
                 wget -N --no-check-certificate https://nginx.org/keys/nginx_signing.key >/dev/null 2>&1
		 apt-key add nginx_signing.key >/dev/null 2>&1
                 apt-get update
                 apt-get -y install nginx
                 rm -rf add nginx_signing.key >/dev/null 2>&1
	 fi
 }

#开始菜单
start_menu_main(){
	clear
	echo && echo -e " 超级VPN 一键设置脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
	  -- 胖波比 --
	  
—————————————VPN搭建——————————————
 ${Green_font_prefix}1.${Font_color_suffix} 安装 V2Ray
 ${Green_font_prefix}2.${Font_color_suffix} 安装 SSR
 ${Green_font_prefix}3.${Font_color_suffix} 安装 BBR/Lotserver(锐速)内核
 ${Green_font_prefix}4.${Font_color_suffix} 安装 Nginx
————————————服务器设置————————————
 ${Green_font_prefix}5.${Font_color_suffix} 设置SSH端口
 ${Green_font_prefix}6.${Font_color_suffix} 设置root用户密码
 ${Green_font_prefix}7.${Font_color_suffix} 重装VPS系统
 ${Green_font_prefix}8.${Font_color_suffix} 系统性能测试
————————————退出脚本——————————————
 ${Green_font_prefix}9.${Font_color_suffix} 退出脚本
—————————————————————————————————" && echo

	echo
	read -p " 请输入数字 [1-9]:" num
	case "$num" in
		1)
		install_v2ray
		;;
		2)
		install_ssr
		;;
		3)
		install_bbr
		;;
		4)
		install_nginx
		;;
		5)
		set_ssh
		;;
		6)
		set_root
		;;
		7)
		reinstall_sys
		;;
		8)
		test_sys
		;;
		9)
		exit 1
		;;
		*)
		clear
		echo -e "${Error}:请输入正确数字 [1-9]"
		sleep 5s
		start_menu_main
		;;
	esac
}

start_menu_main
