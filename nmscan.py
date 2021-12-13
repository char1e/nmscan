import subprocess   
import json
import nmap  
from concurrent.futures import ThreadPoolExecutor,ProcessPoolExecutor
import os
import openpyxl 
import time
import sys
from optparse import OptionParser
from config import *
from rsmasscan import *

'''
需要安装nmap与masscan并设为环境变量，windows还需要加上后缀名.exe
需提前执行命令安装依赖：sudo pip3 install subprocess.run python_nmap openpyxl 或sudo pip install subprocess.run python_nmap openpyxl 
虚拟机运行建议增大内存，调高处理器数量

参考
    源代码
    https://blog.csdn.net/weixin_42613339/article/details/105396193?utm_medium=distribute.pc_relevant_t0.none-task-blog-BlogCommendFromMachineLearnPai2-1.edu_weight&depth_1-utm_source=distribute.pc_relevant_t0.none-task-blog-BlogCommendFromMachineLearnPai2-1.edu_weight
    
    run方法找不到returncode
    https://www.cnblogs.com/my_captain/p/9589200.html
    
    subprocess.run()
    https://www.cnblogs.com/itwhite/p/12329916.html
    https://www.cnblogs.com/zhou2019/p/10582716.html

    openpyxl
    https://www.cnblogs.com/valorchang/p/11590652.html
    
    portScanner
    https://www.cnblogs.com/-qing-/p/10900033.html

'''


    
if __name__ == "__main__":
    #debug()    #调试excel函数时使用函数，正式使用的时候可以删除
    

    parser = OptionParser()
    parser.add_option('-f', '--file', dest='targetsFile', type='string', help='list of ip')
    parser.add_option('-i', '--ip-addr', dest='ip', type='string', help='which specific ip to be scanned')
    parser.add_option('-r', '--rate', dest='masscanRate', type='string', help='rate of masscan')
    parser.add_option('-t', '--threads', dest='nmapThreads', type='int', help='threads of nmap')
    parser.add_option('-p', '--ports' ,dest='masscanPortRange', type='string', help='port range of masscan')
    options, args = parser.parse_args()
    print(options)
    print(type(options))
    if options.targetsFile:
        cmdTargets = '-iL ' + options.targetsFile
        while True:
            if os.path.exists(targetsFile):
                break
            else:
                print('Invalid targetsFile\n')
                targetsFile = input = ("please input targetsFile")
    elif options.ip:
        cmdTargets = options.ip
    if options.masscanRate:
        masscanRate = ' --rate ' + options.masscanRate
    if options.nmapThreads:
        nmapThreads = options.nmapThreads
    if options.masscanPortRange:
        masscanPortRange = ' -p ' + options.masscanPortRange


    


    
    print(nmapThreads)
    """
    #设置nmap线程，多线程调用nmap
    nmapThreads = 20
    #设置扫描端口
    masscanPortRange = ' -p1-65535'
    #masscanPortRange = ' -p 20,21,22,23,25,53,80,81,82,90,99,110,111,120,121,123,135,137,139,143,161,180,211,212,238,389,443,444,445,465,500,514,515,520,523,548,623,636,646,806,810,873,876,902,987,999,1000,1001,1002,1005,1010,1022,1024,1040,1080,1099,1100,1111,1226,1234,1433,1443,1521,1604,1645,1701,1720,1811,1883,1886,1900,2000,2003,2049,2080,2133,2134,2135,2136,2137,2138,2139,2140,2141,2142,2143,2144,2181,2375,2379,2425,3128,3306,3307,3366,3389,3478,4000,4001,4002,4003,4362,4401,4402,4403,4405,4730,5000,5001,5009,5060,5061,5065,5140,5141,5222,5280,5351,5353,5370,5410,5432,5555,5566,5600,5601,5640,5672,5683,5890,5900,5938,5984,6000-10000,10001,10021,10050,10051,10052,10086,10087,10088,10110,10111,10153,10210,10886,11027,11086,11111,11211,12121,12122,12181,12222,12345,13000,13001,13280,13306,14001,15010,15011,15012,15015,15672,16775,17051,17102,17502,17602,18000,18001,18003,18009,18010,18080,18081,18082,18083,18443,18689,18888,19091,19101,20000,20001,20010,20022,20051,20052,21370,21380,21674,22021,23809,27017,28020,28080,28081,28082,28083,29022,29090,30051,30052,31943,32229,35007,35663,36379,37021,37777,38080,38091,38517,39001,39002,40443,41028,50000,50021,50070,50080,50100,50658,52713,60001,60002,60003,60004,60005,61616'
    #masscanPortRange = ' -p 1-10000,10001,10021,10050,10051,10052,10086,10087,10088,10110,10111,10153,10210,10886,11027,11086,11111,11211,12121,12122,12181,12222,12345,13000,13001,13280,13306,14001,15010,15011,15012,15015,15672,16775,17051,17102,17502,17602,18000,18001,18003,18009,18010,18080,18081,18082,18083,18443,18689,18888,19091,19101,20000,20001,20010,20022,20051,20052,21370,21380,21674,22021,23809,27017,28020,28080,28081,28082,28083,29022,29090,30051,30052,31943,32229,35007,35663,36379,37021,37777,38080,38091,38517,39001,39002,40443,41028,50000,50021,50070,50080,50100,50658,52713,60001,60002,60003,60004,60005,61616'
    #设置masscan扫描器速率，建议不要超过6000，否则容易漏扫端口
    masscanRate = '--rate 1500'
    #masscan执行命令和选项,如果masscan不是环境变量请修改开头的masscan
    masscanCmd = 'masscan -iL ' + targetsFile + masscanPortRange + ' -oJ masscan.json ' + masscanRate   
    #nmap选项,这里没有指定端口（-p） 指定端口选项在下方的代码指定
    nmapParam = ' -sV -sS -Pn --min-hostgroup 200 --min-parallelism 500 -T4 -v --script="http-title"'
    """
    #masscan执行命令和选项,如果masscan不是环境变量请修改开头的masscan
    masscanCmd = 'masscan ' + cmdTargets + masscanPortRange + ' -oJ masscan.json ' + masscanRate

    
    
    #设置masscan扫描端口:常用端口
    #masscanPortRange =' -p 21,22,23,25,53,53,80,81,110,111,123,123,135,137,139,161,389,443,445,465,500,515,520,523,548,623,636,873,902,1080,1099,1433,1521,1604,1645,1701,1883,1900,2049,2181,2375,2379,2425,3128,3306,3389,4730,5060,5222,5351,5353,5432,5555,5601,5672,5683,5900,5938,5984,6000,6379,7001,7077,8000-9000,9042,9092,9100,9200,9418,9999,11211,27017,37777,50000,50070,61616'
    #设置masscan扫描端口范围:全端口
    
    #masscanPortRange = ' -p 20,21,22,23,25,53,80,81,82,90,99,110,111,120,121,123,135,137,139,143,161,180,211,212,238,389,443,444,445,465,500,514,515,520,523,548,623,636,646,806,810,873,876,902,987,999,1000,1001,1002,1005,1010,1022,1024,1040,1080,1099,1100,1111,1226,1234,1433,1443,1521,1604,1645,1701,1720,1811,1883,1886,1900,2000,2003,2049,2080,2133,2134,2135,2136,2137,2138,2139,2140,2141,2142,2143,2144,2181,2375,2379,2425,3128,3306,3307,3366,3389,3478,4000,4001,4002,4003,4362,4401,4402,4403,4405,4730,5000,5001,5009,5060,5061,5065,5140,5141,5222,5280,5351,5353,5370,5410,5432,5555,5566,5600,5601,5640,5672,5683,5890,5900,5938,5984,6000,6001,6002,6003,6350,6351,6379,6510,6789,6812,7001,7002,7003,7008,7015,7020,7031,7077,7080,7088,7089,7090,7098,7099,7898,7100,7300,7380,7421,7788,7890,7891,7892,8000-8999,9000,9001,9002,9003,9004,9008,9024,9025,9026,9035,9042,9051,9078,9080,9081,9085,9088,9090,9091,9092,9097,9098,9099,9100,9101,9124,9189,9200,9223,9372,9393,9418,9443,9444,9445,9446,9453,9595,9980,9999,10001,10021,10050,10051,10052,10086,10087,10088,10110,10111,10153,10210,10886,11027,11086,11111,11211,12121,12122,12181,12222,12345,13000,13001,13280,13306,14001,15010,15011,15012,15015,15672,16775,17051,17102,17502,17602,18000,18001,18003,18009,18010,18080,18081,18082,18083,18443,18689,18888,19091,19101,20000,20001,20010,20022,20051,20052,21370,21380,21674,22021,23809,27017,28020,28080,28081,28082,28083,29022,29090,30051,30052,31943,32229,35007,35663,36379,37021,37777,38080,38091,38517,39001,39002,40443,41028,50000,50021,50070,50080,50100,50658,52713,60001,60002,60003,60004,60005,61616'
    #masscanPortRange = ' -p 1-10000,10001,10021,10050,10051,10052,10086,10087,10088,10110,10111,10153,10210,10886,11027,11086,11111,11211,12121,12122,12181,12222,12345,13000,13001,13280,13306,14001,15010,15011,15012,15015,15672,16775,17051,17102,17502,17602,18000,18001,18003,18009,18010,18080,18081,18082,18083,18443,18689,18888,19091,19101,20000,20001,20022,20051,20052,21370,21380,21674,23809,27017,28020,28080,28081,28082,28083,29022,29090,30051,30052,32229,35007,35663,36379,37777,38080,38091,38517,39001,39002,40443,41028,50000,50021,50070,50100,50658,52713,60001,60002,60003,60004,60005,61616'

    
    
    #显示开始时间
    startTimeStamp = time.time()
    startTime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) 
    print("扫描开始，时间:"+ startTime,end='\n\n')
    
    #设置输入文件路径和masscan命令
    masscanOutputDict = rsMasscan(masscanCmd)    #masscan扫描出的信息存放在info（字典类型）
    
    #massscan结束时显示时间
    masscanOverTimeStamp = time.time()
    masscanOverTime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    print('masscan扫描结束时间:' + masscanOverTime)
    passTime = int(time.time())-int(startTimeStamp)
    print('masscan扫描耗时: %d小时%d分钟%d秒' % (passTime // 3600, passTime % 3600 // 60, passTime % 3600 % 60),end='\n\n')
    
    
    print('开始进行nmap扫描,线程: %d ' % (nmapThreads))
    #设置线程，为nmap扫描hosts数组做准备
    thread_pool = ThreadPoolExecutor(nmapThreads)    #nmapThreads线程池的线程数量
    if not os.path.exists("./nmscanOutput"):
        os.makedirs("./nmscanOutput")
    
    #从返回的masscanOutputDict(字典中取出host列表)
    hosts = []
    for host,ports in masscanOutputDict.items():
        hosts.append(host)    
        
    print('masscan发现的host列表:')
    print(hosts,end='\n\n')
    
    #调用nmap
    for host in hosts:      #针对每一个host进行一次扫描
        nmapFuncParam = {}           #初始化     
        nmapFuncParam['host'] = host.strip()
        nmapFuncParam['portRange'] = list(masscanOutputDict[host].keys())   #取出全端口
        nmapPortsParam = ' -p ' + str(nmapFuncParam['portRange']).strip('[').strip(']').replace(' ','') #nmap只扫描masscan发现的端口，拼接成-p xxx的选项
        #nmapPortsParam = ' -p 1-65535' #nmap全端口扫描
        nmapFuncParam['arguments'] = nmapParam + nmapPortsParam     #最终nmap执行的选项
        thread_pool.submit(rsNmap,nmapFuncParam)
    
    # 线程池可以看做容纳线程的容器；
    #一个应用程序最多只能有一个线程池，每排入一个工作函数，就相当于请求创建一个线程；
    #理解为调用rsNmap函数，传入参数nmapFuncParam
    
    #显示结束时间
    #passTime = int(time.time()) - int(masscanOverTimeStamp)
    #if passTime >= 0:
    #    print('nmap扫描耗时: %d小时%d分钟%d秒' % (passTime // 3600, passTime % 3600 // 60, passTime % 3600))
    #print('结束')
    




