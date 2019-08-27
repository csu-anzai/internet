#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
# Thanks: LookBack <admin@dwhd.org>; Nils Steinger; Teddysun;Toyo;
# For https://www.94ish.me by Chikage



next() { printf "%-70s\n" "-" | sed 's/\s/-/g'; }
get_opsy() {
	[[ -f /etc/redhat-release ]] && awk '{print ($1,$3~/^[0-9]/?$3:$4)}' /etc/redhat-release && return
	[[ -f /etc/os-release ]] && awk -F'[= "]' '/PRETTY_NAME/{print $3,$4,$5}' /etc/os-release && return
	[[ -f /etc/lsb-release ]] && awk -F'[="]+' '/DESCRIPTION/{print $2}' /etc/lsb-release && return
}
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
	bit=$(uname -m)
}
Installation_dependency(){
	if [[ ${release} == "centos" ]]; then
		yum install curl time virt-what make -y
		if [[ ${action} == "a" ]] || [[ ${action} == "as" ]]; then
			yum install make automake gcc autoconf gcc-c++ time perl-Time-HiRes -y
		fi
		wget --no-check-certificate -N -O /usr/bin/ioping "https://raw.githubusercontent.com/chiakge/Linux-Server-Bench-Test/master/ioping" 
		chmod +x /usr/bin/ioping
	else
		apt-get update
		apt-get install curl time virt-what python make -y
		apt-get install ioping -y
		if [[ ${action} == "a" ]] || [[ ${action} == "as" ]]; then
			apt-get install make automake gcc autoconf time perl -y
		fi
	fi
	wget --no-check-certificate -N "https://raw.githubusercontent.com/chiakge/Linux-Server-Bench-Test/master/besttrace"
	chmod -R +x besttrace
}
get_info(){
	logfile="/root/test.log"
	IP=$(curl -s myip.ipip.net | awk -F ' ' '{print $2}' | awk -F '：' '{print $2}')
	IPaddr=$(curl -s myip.ipip.net | awk -F '：' '{print $3}')
	if [[ -z "$IP" ]]; then
		IP=$(curl -s ip.cn | awk -F ' ' '{print $2}' | awk -F '：' '{print $2}')
		IPaddr=$(curl -s ip.cn | awk -F '：' '{print $3}')	
	fi
	time=$(date '+%Y-%m-%d %H:%I:%S')
	backtime=$(date +%Y-%m-%d)
	vm=$(virt-what)
	[[ -z ${vm} ]] && vm="none"
	cname=$( awk -F: '/model name/ {name=$2} END {print name}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//' )
	cores=$( awk -F: '/model name/ {core++} END {print core}' /proc/cpuinfo )
	freq=$( awk -F: '/cpu MHz/ {freq=$2} END {print freq}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//' )
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
	ipv6=$( wget -qO- -t1 -T2 ipv6.icanhazip.com )
	disk_size1=($( LANG=C df -ahPl | grep -wvE '\-|none|tmpfs|devtmpfs|by-uuid|chroot|Filesystem' | awk '{print $2}' ))
	disk_size2=($( LANG=C df -ahPl | grep -wvE '\-|none|tmpfs|devtmpfs|by-uuid|chroot|Filesystem' | awk '{print $3}' ))
	disk_total_size=$( calc_disk ${disk_size1[@]} )
	disk_used_size=$( calc_disk ${disk_size2[@]} )
}
system_info(){
	clear
	echo "========== 开始记录测试信息 ==========" > $logfile
	echo "测试时间：$time" | tee -a $logfile
	next | tee -a $logfile
	echo "CPU model            : $cname" | tee -a $logfile
	echo "Number of cores      : $cores" | tee -a $logfile
	echo "CPU frequency        : $freq MHz" | tee -a $logfile
	echo "Total size of Disk   : $disk_total_size GB ($disk_used_size GB Used)" | tee -a $logfile
	echo "Total amount of Mem  : $tram MB ($uram MB Used)" | tee -a $logfile
	echo "Total amount of Swap : $swap MB ($uswap MB Used)" | tee -a $logfile
	echo "System uptime        : $up" | tee -a $logfile
	echo "Load average         : $load" | tee -a $logfile
	echo "OS                   : $opsy" | tee -a $logfile
	echo "Arch                 : $arch ($lbit Bit)" | tee -a $logfile
	echo "Kernel               : $kern" | tee -a $logfile
	echo "ip                   : $IP"
	echo "ipaddr               : $IPaddr" | tee -a $logfile
	echo "vm                   : $vm" | tee -a $logfile
	next | tee -a $logfile
}
ioping() {
		echo "===== 开始硬盘性能测试 =====" | tee -a $logfile
        printf 'ioping: seek rate\n    ' | tee -a $logfile
        /usr/bin/ioping -R -w 5 . | tail -n 1 | tee -a $logfile
        printf 'ioping: sequential speed\n    ' | tee -a $logfile
        /usr/bin/ioping -RL -w 5 . | tail -n 2 | head -n 1 | tee -a $logfile
		echo "===== 硬盘性能测试完成 =====" | tee -a $logfile
	next | tee -a $logfile
}
calc_disk() {
	local total_size=0
	local array=$@
	for size in ${array[@]}
	do
		[[ "${size}" == "0" ]] && size_t=0 || size_t=$(echo ${size:0:${#size}-1})
		[[ "$(echo ${size:(-1)})" == "M" ]] && size=$( awk 'BEGIN{printf "%.1f", '$size_t' / 1024}' )
		[[ "$(echo ${size:(-1)})" == "T" ]] && size=$( awk 'BEGIN{printf "%.1f", '$size_t' * 1024}' )
		[[ "$(echo ${size:(-1)})" == "G" ]] && size=${size_t}
		total_size=$( awk 'BEGIN{printf "%.1f", '$total_size' + '$size'}' )
	done
	echo ${total_size}
}
speed_test() {
	local speedtest=$( curl  -m 12 -Lo /dev/null -skw "%{speed_download}\n" "$1" )
	local host=$(awk -F':' '{print $1}' <<< `awk -F'/' '{print $3}' <<< $1`)
	local ipaddress=$(ping -c1 -n ${host} | awk -F'[()]' '{print $2;exit}')
	local nodeName=$2
	printf "%-32s%-24s%-14s\n" "${nodeName}:" "${ipaddress}:" "$(FormatBytes $speedtest)"
}
FormatBytes() {
	bytes=${1%.*}
	local Mbps=$( printf "%s" "$bytes" | awk '{ printf "%.2f", $0 / 1024 / 1024 * 8 } END { if (NR == 0) { print "error" } }' )
	if [[ $bytes -lt 1000 ]]; then
		printf "%8i B/s |      N/A     "  $bytes
	elif [[ $bytes -lt 1000000 ]]; then
		local KiBs=$( printf "%s" "$bytes" | awk '{ printf "%.2f", $0 / 1024 } END { if (NR == 0) { print "error" } }' )
		printf "%7s KiB/s | %7s Mbps" "$KiBs" "$Mbps"
	else
		# awk way for accuracy
		local MiBs=$( printf "%s" "$bytes" | awk '{ printf "%.2f", $0 / 1024 / 1024 } END { if (NR == 0) { print "error" } }' )
		printf "%7s MiB/s | %7s Mbps" "$MiBs" "$Mbps"

		# bash way
		# printf "%4s MiB/s | %4s Mbps""$(( bytes / 1024 / 1024 ))" "$(( bytes / 1024 / 1024 * 8 ))"
	fi
}
speed() {
	printf "%-32s%-31s%-14s\n" "Node Name:" "IPv4 address:" "Download Speed"
	speed_test 'http://cachefly.cachefly.net/100mb.test' 'CacheFly'
    	speed_test 'http://speedtest.tokyo.linode.com/100MB-tokyo.bin' 'Linode, Tokyo, JP'
	speed_test 'http://speedtest.tokyo2.linode.com/100MB-tokyo2.bin' 'Linode, Tokyo2, JP'
	speed_test 'http://speedtest.singapore.linode.com/100MB-singapore.bin' 'Linode, Singapore, SG'
	speed_test 'http://speedtest.fremont.linode.com/100MB-fremont.bin' 'Linode, Fremont, CA'
	speed_test 'http://speedtest.newark.linode.com/100MB-newark.bin' 'Linode, Newark, NJ'
	speed_test 'http://speedtest.london.linode.com/100MB-london.bin' 'Linode, London, UK'
	speed_test 'http://speedtest.frankfurt.linode.com/100MB-frankfurt.bin' 'Linode, Frankfurt, DE'
	speed_test 'http://speedtest.tok02.softlayer.com/downloads/test100.zip' 'Softlayer, Tokyo, JP'
	speed_test 'http://speedtest.sng01.softlayer.com/downloads/test100.zip' 'Softlayer, Singapore, SG'
	speed_test 'http://speedtest.sng01.softlayer.com/downloads/test100.zip' 'Softlayer, Seoul, KR'
	speed_test 'http://speedtest.hkg02.softlayer.com/downloads/test100.zip' 'Softlayer, HongKong, CN'
	speed_test 'http://speedtest.dal13.softlayer.com/downloads/test100.zip' 'Softlayer, Dallas, TX'
	speed_test 'http://speedtest.sea01.softlayer.com/downloads/test100.zip' 'Softlayer, Seattle, WA'
	speed_test 'http://speedtest.fra02.softlayer.com/downloads/test100.zip' 'Softlayer, Frankfurt, DE'
	speed_test 'http://speedtest.par01.softlayer.com/downloads/test100.zip' 'Softlayer, Paris, FR'
	speed_test 'http://mirror.hk.leaseweb.net/speedtest/100mb.bin' 'Leaseweb, HongKong, CN'
	speed_test 'http://mirror.sg.leaseweb.net/speedtest/100mb.bin' 'Leaseweb, Singapore, SG'
	speed_test 'http://mirror.wdc1.us.leaseweb.net/speedtest/100mb.bin' 'Leaseweb, Washington D.C., US'
	speed_test 'http://mirror.sfo12.us.leaseweb.net/speedtest/100mb.bin' 'Leaseweb, San Francisco, US'
	speed_test 'http://mirror.nl.leaseweb.net/speedtest/100mb.bin' 'Leaseweb, Netherlands, NL'
	speed_test 'http://proof.ovh.ca/files/100Mio.dat' 'OVH, Montreal, CA'
	speed_test 'http://tpdb.speed2.hinet.net/test_100m.zip' 'Hinet, Taiwan, TW'
	next
}
speedchina(){
	printf "%-32s%-31s%-14s\n" "节点名称:" "IP地址:" "下载速度"
	speed_test 'http://speedtest1.ah163.com:8080/download?size=100000000' '安徽合肥电信'
	speed_test 'http://4gnanjing1.speedtest.jsinfo.net:8080/download?size=100000000' '江苏南京电信'
	speed_test 'http://swxwyzx.f3322.net:8080/download?size=100000000' '江西南昌电信'
	speed_test 'http://61.128.107.242:8080/download?size=100000000' '新疆昌吉电信'
	speed_test 'http://112.122.10.26:8080/download?size=100000000' '安徽合肥联通'
	speed_test 'http://speedtest.jnltwy.com:8080/download?size=100000000' '山东济南联通'
	speed_test 'http://speedtest1.jlinfo.jl.cn:8080/download?size=100000000' '吉林长春联通'
	speed_test 'http://113.57.249.2:8080/download?size=100000000' '湖北武汉联通'
	speed_test 'http://221.13.70.244:8080/download?size=100000000' '西藏拉萨联通'
	speed_test 'http://speedtest1.online.ln.cn:8080/download?size=100000000' '辽宁沈阳联通'
	speed_test 'http://speedtest.sxunicomjzjk.cn:8080/download?size=100000000' '山西太原联通'
	speed_test 'http://speedtest02.js165.com:8080/download?size=100000000' '江苏南京联通'
	speed_test 'http://4gtest.ahydnet.com:8080/download?size=100000000' '安徽合肥移动'
	speed_test 'http://sp.sx.chinamobile.com:8080/download?size=100000000' '山西太原移动'
	speed_test 'http://183.221.247.9:8080/download?size=100000000' '四川成都移动'
	speed_test 'http://speedtest5.xj.chinamobile.com:8080/download?size=100000000' '新疆昌吉移动'
	speed_test 'http://speedtest2.jl.chinamobile.com:8080/download?size=100000000' '吉林长春移动'
	speed_test 'http://speedtest1.xz.chinamobile.com:8080/download?size=100000000' '西藏拉萨移动'
	speed_test 'http://speedtest1.ln.chinamobile.com:8080/download?size=100000000' '辽宁沈阳移动'
	speed_test 'http://speedtest1.hb.chinamobile.com:8080/download?size=100000000' '湖北武汉移动'
	speed_test 'http://sp1.uestc.edu.cn:8080/download?size=100000000' '四川成都教育网'
	next
}
speed_test_cli(){
	echo "===== 开始speedtest =====" 
	wget -q --no-check-certificate https://raw.githubusercontent.com/sivel/speedtest-cli/master/speedtest.py && 
	python speedtest.py --share 
	echo -e "===== speedtest完成 =====" 
	rm -rf speedtest.py
	next 
}

mtrback(){
	echo "===== 测试 [$2] 的回程路由 =====" | tee -a $logfile
	./besttrace -q 1 $1 | tee -a $logfile
	echo -e "===== 回程 [$2] 路由测试结束 =====" | tee -a $logfile	
}

backtracetest(){
	mtrback "speedtest1.ah163.com" "安徽合肥电信"
	mtrback "4gnanjing1.speedtest.jsinfo.net" "江苏南京电信"
	mtrback "swxwyzx.f3322.net" "江西南昌电信"
	mtrback "61.128.107.242" "新疆昌吉电信"
	mtrback "112.122.10.26" "安徽合肥联通"
	mtrback "speedtest.jnltwy.com" "山东济南联通"
	mtrback "113.57.249.2" "湖北武汉联通"
	mtrback "221.13.70.244" "西藏拉萨联通"
	mtrback "speedtest1.online.ln.cn" "辽宁沈阳联通"
	mtrback "speedtest.sxunicomjzjk.cn" "山西太原联通"
	mtrback "speedtest02.js165.com" "江苏南京联通"
	mtrback "4gtest.ahydnet.com" "安徽合肥移动"
	mtrback "sp.sx.chinamobile.com" "山西太原移动"
	mtrback "183.221.247.9" "四川成都移动"
	mtrback "speedtest5.xj.chinamobile.com" "新疆昌吉移动"
	mtrback "speedtest2.jl.chinamobile.com" "吉林长春移动"
	mtrback "speedtest1.xz.chinamobile.com" "西藏拉萨移动"
	mtrback "speedtest1.ln.chinamobile.com" "辽宁沈阳移动"
	mtrback "speedtest1.hb.chinamobile.com" "湖北武汉移动"
	mtrback "sp1.uestc.edu.cn" "四川成都教育网"
	rm -rf besttrace
	next | tee -a $logfile
}
shping(){
	ping $1 -c 10 > /tmp/$1.txt
	echo 【$2】 - $1
	tail -2 /tmp/$1.txt
	next
}
mping(){
	shping "speedtest1.ah163.com" "安徽合肥电信"
	shping "4gnanjing1.speedtest.jsinfo.net" "江苏南京电信"
	shping "swxwyzx.f3322.net" "江西南昌电信"
	shping "61.128.107.242" "新疆昌吉电信"
	shping "112.122.10.26" "安徽合肥联通"
	shping "speedtest.jnltwy.com" "山东济南联通"
	shping "113.57.249.2" "湖北武汉联通"
	shping "221.13.70.244" "西藏拉萨联通"
	shping "speedtest1.online.ln.cn" "辽宁沈阳联通"
	shping "speedtest.sxunicomjzjk.cn" "山西太原联通"
	shping "speedtest02.js165.com" "江苏南京联通"
	shping "4gtest.ahydnet.com" "安徽合肥移动"
	shping "sp.sx.chinamobile.com" "山西太原移动"
	shping "183.221.247.9" "四川成都移动"
	shping "speedtest5.xj.chinamobile.com" "新疆昌吉移动"
	shping "speedtest2.jl.chinamobile.com" "吉林长春移动"
	shping "speedtest1.xz.chinamobile.com" "西藏拉萨移动"
	shping "speedtest1.ln.chinamobile.com" "辽宁沈阳移动"
	shping "speedtest1.hb.chinamobile.com" "湖北武汉移动"
	shping "sp1.uestc.edu.cn" "四川成都教育网"
	echo "min:最低延迟"
	echo "avg:平均延迟"
	echo "max:最高延迟"
	echo "mdev:平均偏差"
	next
}

benchtest(){
	if ! wget -qc https://raw.githubusercontent.com/chiakge/Linux-Server-Bench-Test/master/UnixBench5.1.3.tgz; then
		echo "UnixBench 5.1.3.tgz 下载失败" && exit 1
	fi
	tar -xzf UnixBench5.1.3.tgz
	cd UnixBench/
	make
	echo "===== 开始UnixBench测试 =====" | tee -a $logfile
	./Run
	benchfile=$(ls results/ | grep -v '\.html' | grep -v '\.log')
	cat results/${benchfile} >> $logfile
	echo "===== UnixBench测试结束 =====" | tee -a $logfile
	cd ..
	rm -rf UnixBench5.1.3.tgz UnixBench
	next | tee -a $logfile
}
sharetest() {
	share_link=$( curl -v --data-urlencode "content@$logfile" -d "poster=linuxtest.log" -d "syntax=text" "https://paste.ubuntu.com" 2>&1 | grep "Location" | awk '{print $3}' )

	echo "分享链接是:    ""$share_link"
}
go(){
	check_sys
	Installation_dependency
	get_info
	system_info
	ioping
	speed_test_cli
	speed | tee -a $logfile
	speedchina | tee -a $logfile
	backtracetest
	mping | tee -a $logfile
	
	case $action in
	'a' )
		benchtest;;
	's' )
		sharetest;;
	'as' )
		benchtest
		sharetest;;
	esac
	echo "测试脚本执行完毕！日志文件: ${logfile}"
	echo "就是爱生活：www.94ish.me by Chikage"
	rm -rf linuxtest.sh
}
action=$1
cd /root
go
