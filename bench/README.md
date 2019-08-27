## 千影大佬的LNIUXTEST.sh

### 运行（不含UnixBench）
```
wget https://raw.githubusercontent.com/chiakge/Linux-Server-Bench-Test/master/linuxtest.sh -N --no-check-certificate && bash linuxtest.sh
```
### 运行（含UnixBench）
```
wget https://raw.githubusercontent.com/chiakge/Linux-Server-Bench-Test/master/linuxtest.sh -N --no-check-certificate && bash linuxtest.sh a
```

## 1、秋水逸冰大佬的ibench.sh脚本

特点：

显示当前测试的各种系统信息；

取自世界多处的知名数据中心的测试点，下载测试比较全面；

支持 IPv6 下载测速；

IO 测试三次，并显示平均值。

## 2、老鬼大佬的cbench.sh测试脚本

这个脚本是在基于秋水大佬脚本的基础上

加入了独服通电时间，服务器虚拟化架构等内容

特点：

改进了显示的模式，基本参数添加了颜色，方面区分与查找。

I/O测试，更改了原来默认的测试的内容

采用小文件，中等文件，大文件，分别测试IO性能，然后取平均值。

速度测试替换成了 Superspeed 里面的测试

第一个默认节点是，Speedtest 默认，

其他分别测试到中国电信，联通，移动，各三个不同地区的速度。

## 3、pbench

脚本由漏水和kirito，基于Oldking大佬 的 SuperBench

然后加入Ping以及路由测试的功能，

还能生成测评报告，分享给其他人查看测评数据
