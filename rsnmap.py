import json
import nmap
from rsio import nmapData2Excel
def rsNmap(nmapInfo):
    '''
    nampInfo字典有三个一级子字典，分别是host,arguments和portRange，
    其中portRange在调用进来之前就以-p xxx的形式整合到arguments参数里了
    '''
    host = nmapInfo['host']     
    arguments = nmapInfo['arguments']
    scan = nmap.PortScanner()       
    
    print('nmap正在扫描host:',end='')
    print(nmapInfo['host'])
    print('使用参数:',end='')
    print(nmapInfo['arguments'])
    
    scan_result = scan.scan(hosts=host,arguments=arguments)     #创建一次扫描，并行执行，取出结果
    print("执行命令:" + scan.command_line())    #不知道为啥，这个选项就是会返回多余的-oX - 例如u'nmap -oX - -p 22,80 -sV 192.168.209.121-122'
    
    print('scan_result:')
    print(scan_result,end='\n\n')

    tcpInfo = {}
    #hostname = scan_result['scan'][host]['hostnames'][0]['name'] #主机名,可能有很多主机名此处取第一个
    address = scan_result['scan'][host]['addresses']['ipv4']    #主机ip地址
    status = scan_result['scan'][host]['status']['state']   #主机状态:up或者down

    tcpInfo = {}
    udpInfo = {}
    ports_count = 0
    tcp_ports = []
    udp_ports = []
    ip_ports = []
    sctp_ports = []
    all_protocols = scan[host].all_protocols()
    for protocol in all_protocols:
        tcp_ports = scan[host].all_tcp() #所有tcp端口列表
        udp_ports = scan[host].all_udp() #
        ip_ports = scan[host].all_ip() #
        sctp_ports = scan[host].all_sctp() #
    ports_count = len(tcp_ports) + len(udp_ports) + len(ip_ports) + len(sctp_ports)
    
    if(ports_count > len(tcp_ports)):
        print('发现除TCP外别的端口' + '\n\n')
    else:
        print('只有TCP端口')
    
    print('%s 主机端口数量为 %d' % (host,ports_count))
    if ports_count == 0:
        print('%s 无端口，跳过该IP' % (host))      #masscan发现端口，但是nmap扫描的时候又没有发现此端口
        return 
        
        
    if ports_count > 1000:
        print("%s端口太多可能有waf",host)
    
    print(len(tcp_ports))
    print(len(udp_ports))
    
    #写入TCP信息

    print('line132')
    if len(tcp_ports) > 0:
        for tcp_port in tcp_ports:
            tcp_port_info = scan[host]['tcp'][tcp_port]
            
            #tcpInfo[host][tcp_port] = {}
            #print('tcp_port_info:')
            #print(tcp_port_info)       #字典类型带大括号
           
            tcpInfo[tcp_port] = tcp_port_info
            #info[host]["ports_nmap"]["ports"] = info[host]["ports_nmap"]["ports"].update(tcp_port,tcp_port_info)
        #针对每一个host
        print('%s的TCP端口信息为'%(host),end='\n')
        print(tcpInfo,end='\n\n')
        nmapData2Excel(host,tcpInfo,'Tcp')
    
    #写入UDP信息
    if len(udp_ports) > 0:
        for udp_port in udp_ports:
            udp_port_info = scan[host]['udp'][udp_port]
            udpInfo[udp_port] = udp_port_info
        print('%s的UDP端口信息为'%(host),end='\n')
        print(udpInfo,end='\n\n')
        nmapData2Excel(host,udpInfo,'Udp')
            
