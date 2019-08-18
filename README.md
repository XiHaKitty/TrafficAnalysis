## 介绍

基于 C语言 网络流量在线分析系统

## 实验环境

> 1.操作系统：ubuntu

> 2.编程语言：C语言

> 3.网络数据包捕获函数包：libpcap

## 运行程序

> 进入项目目录，在终端中运行下面的命令

```bash
sudo su
gcc -o catch pcap_catch.c -l pcap
./catch
gcc -o analysis pcap_analysis.c -l pcap
./analysis
```


## 实现功能
- [x] 实时抓取还有问题，希望有人可以改进
- [x] 离线存储网络中的数据包
- [x] 分析各个网络协议格式
- [x] 采用Hash链表的形式将网络数据以连接（双向流）的形式存储
- [x] 计算并显示固定时间间隔内网络连接（双向流）的统计量
