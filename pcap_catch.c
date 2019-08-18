
//  网络流量在线分析系统
//  pcap_catch.c
//  抓取网络数据包
 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <time.h>

/* 数据包 IP 地址及端口 */
typedef struct _netset
{
    u_int       sip;
    u_int       dip;
    u_short     sport;
    u_short     dport;
    u_char      protocol;
}netset;
//ip回调函数,解析ip包和mac帧回调函数，解析Mac包
void  callback(u_char *dumpfile, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    

    static int id = 1;
    struct ether_header *eptr = (struct ether_header*)packet; // 得到以太网字头
    struct ip *ipptr = (struct ip*)(packet+sizeof(struct ether_header)); // 得到 IP 报头
    struct tcphdr *tcpptr = (struct tcphdr*)(packet+sizeof(struct ether_header)+sizeof(struct ip)); // 得到 TCP 包头
    struct udphdr *udpptr = (struct udphdr*)(packet+sizeof(struct ether_header)+sizeof(struct ip)); // 得到 UDP 包头
    u_char *ptr;
    int i;

    pcap_dump(dumpfile, pkthdr, packet);
    
    printf( "\n**************************开始**************************\n");
    printf( "捕获第%d个网络数据包\n", id++);
    printf("数据包长度：%d\n", pkthdr->len);
    printf( "实际捕获包长度：%d\n", pkthdr->caplen);
    printf( "时间：%s", ctime((const time_t *)&pkthdr->ts.tv_sec));
    
    printf("-----------------数据链路层 解析以太网帧-----------------\n");
    ptr = eptr->ether_dhost;
    i = ETHER_ADDR_LEN;
    printf( "目的 MAC 地址：");
    do
    {
        printf( "%s%x", (i == ETHER_ADDR_LEN)?"":":", *ptr++);
    } while(--i>0);
    printf("\n");
    
    ptr = eptr->ether_shost;
    i = ETHER_ADDR_LEN;
    printf("源   MAC 地址：");
    do
    {
        printf("%s%x", (i == ETHER_ADDR_LEN)?"":":", *ptr++);
    } while(--i>0);
    printf( "\n");
    
    printf( "以太网帧类型：%x\n", ntohs(eptr->ether_type));
    
    printf( "-----------------数据链路层 解析 IP 报头-----------------\n");
    printf( "版本号：%d\n", ipptr->ip_v);
    printf( "首部长度：%d\n", ipptr->ip_hl);
    printf( "服务类型：%hhu\n", ipptr->ip_tos);
    printf( "报文总长度：%d\n", ntohs(ipptr->ip_len));
    printf( "标识：%d\n", ntohs(ipptr->ip_id));
    printf( "片偏移：%d\n", ntohs(ipptr->ip_off));
    printf("生存时间：%hhu\n", ipptr->ip_ttl);
    printf( "协议类型：%hhu\n", ipptr->ip_p);
    printf( "首部校验和：%d\n", ntohs(ipptr->ip_sum));
    printf( "源地址：%s\n", inet_ntoa(ipptr->ip_src));
    printf( "目的地址：%s\n", inet_ntoa(ipptr->ip_dst));
}

int main()
{
    char *device; // 网络设备
    char errbuf[PCAP_ERRBUF_SIZE]; // 错误信息
    bpf_u_int32 net; // 网络号   执行嗅探的设备的IP地址
    bpf_u_int32 mask; // 掩码  执行嗅探的设备的网络掩码
    struct in_addr addr;
    pcap_t *handle; // 会话句柄
    struct bpf_program filter; /* 已经编译好的过滤器 */
    char filter_app[] = "ip"; /* 过滤表达式 */
    
    /* 网络设备名   pcap_lookupdev()函數用于返回pcap_lookupnet()要调用的网络设备名指针*/
    device = pcap_lookupdev(errbuf);
    if(device == NULL)
    {
        printf("pcap_lookupdev:%s\n",errbuf);
        exit(1);
    }
    printf("网络设备：%s\n", device);
    
    /* 获得指定网络设备的网络号和掩码  探查设备属性  */
    if(pcap_lookupnet(device, &net, &mask, errbuf) == -1){
        printf("error\n");
        exit(1);
    }
    
    addr.s_addr = net;
    printf("网络号：%s\n", inet_ntoa(addr));
    
    addr.s_addr = mask;
    printf("网络掩码：%s\n", inet_ntoa(addr));
    
    /* 设置抓取时长 */
    int to_ms;
    printf("请输入抓取时长(s）：");
    scanf("%d", &to_ms);
    to_ms *= 1000; // 秒数转换为毫秒数
    
    /* 以混杂模式打开会话 pcap_open_live()获得用于捕获网络数据包的数据包捕获描述字   */
    handle = pcap_open_live(device, 65535, 1, to_ms, errbuf);
    if(handle == NULL)
    {
        printf("pcap_open_live:%s\n",errbuf);
        exit(1);
    }
    
    /* 编译并应用过滤器 */
    if (pcap_compile(handle, &filter, filter_app, 1, mask) <0 )
    {
        printf("Unable to compile the packet filter\n");
        return 0;
    }
     /*过滤表达式被编译之后进入...*/
    if (pcap_setfilter(handle, &filter) < 0)
    {
        printf("Error setting the filter.\n");
        exit(1);
    }
    
    /* 离线存储数据包 */
    pcap_dumper_t *dumpfile;
    dumpfile = pcap_dump_open(handle, "packet.data");
    if(dumpfile == NULL){
        printf("Error opening output file\n");
        exit(1);
    }
    
    /* 抓取网络数据包 */
    pcap_dispatch(handle, 0, callback, (u_char *)dumpfile);
    
    printf("\n数据包抓取成功\n");
    
    /* 关闭 dumpfile */
    pcap_dump_close(dumpfile);
    /* 关闭会话 */
    pcap_close(handle);
    
    return 0;
}

