### 概述

调用masscan和nmap的python库实现端口扫描，由masscan扫出端口后，nmap针对端口识别出服务。

### 配置

1. 需要linux/unix系统
2. 安装python3+，
3. 安装masscan，并将masscan设为环境变量，也就是设置成直接输入masscan即可调用的状态
4. 通过pip安装所需库

```
sudo pip3 install subprocess.run python_nmap openpyxl
```

 

 

### 使用方法

```
python3 nmscan.py 
	-f 指定目标文件的路径
	-i 指定要扫描的ip地址
	-p masscan端口扫描范围，若不指定则采用config文件里的值
	-r masscan扫描速率，若不指定则采用config文件里的值
	-t nmap线程数，若不指定则采用config文件里的值
```

例如

```
python3 nmscan.py -f targets.txt -p 1-65535 -r 1500 -t 20

```

注意目标ip文件的格式必须符合masscan的目标ip文件输入格式

支持格式有

192.168.1.0/24

192.168.1.1-192.168.1.255

不支持

192.168.1.1-255





### 输出

 会在目标文件的同目录下生成nmscanOutput文件夹，里面存放以IP命名的端口扫结果，可以使用concatExcel.py脚本将所有结果汇总到一起

```
python3 concatExcel.py nmscanOutput/
```



### 注意事项

虚拟机运行建议增大内存，调高处理器数量

2021.12.11 by rhaps

 