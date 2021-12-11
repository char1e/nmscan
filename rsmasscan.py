
from rsnmap import *
import subprocess   

def rsMasscan(targetsFile,cmdMasscan):
    print("Masscan执行命令:",end='')
    print(cmdMasscan)
    result = subprocess.run(cmdMasscan,shell=True)
           #subprocess生成新的进程
           #subprocess.run()
           #Python 3.5中新增的函数。执行指定的命令，等待命令执行完成后返回一个包含执行结果的CompletedProcess类的实例。
           #subprocess.run(args, *, stdin=None, input=None, stdout=None, stderr=None, shell=False, timeout=None, check=False, universal_newlines=False)
           #returncode: 执行完子进程状态，通常返回状态为0则表明它已经运行完毕，若值为负值 "-N",表明子进程被终。
    
    #print('subprocess.run调用返回结果result.stdout:')
    #print(result.stdout)

    #上面用subprocess调用命令行的形式，最终将结果保存在.json中，然后从json中取出数据传到masscanOutputInfo中，作为给nmap的数据
    masscanOutputInfo = {}          #初始化
    if not result.returncode:       #运行完毕，未被中断
        with open('masscan.json','r+') as f: 
            for line in f.readlines():
                if line.startswith("{"):        #一行一个IP/端口
                    tempLine = line + ','       #最后加逗号修复json
                    portInfo = json.loads(tempLine.strip()[:-1])    #ports:该IP的所有端口
                    #print('portInfo:')
                    #print(portInfo)
                    ip = portInfo["ip"]
                    port = portInfo["ports"][0]["port"]     #由于多个了一个[]的特殊结构，所以要加上索引0，因为一行只有一个端口，所以完全OK
                    portALLInfo = portInfo["ports"]

                    if ip not in masscanOutputInfo:
                        masscanOutputInfo[ip] = {}       #如果IP没有在masscanOutputInfo中出现过，就初始化一个masscanOutputInfo[ip]

                    masscanOutputInfo[ip][port] = portALLInfo  #ip的ports_masscan（所有结果）中的某一个端口的，这个端口的全部信息
    print('masscanOutputInfo:')
    print(masscanOutputInfo)
    return masscanOutputInfo