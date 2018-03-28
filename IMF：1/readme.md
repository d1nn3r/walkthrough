# IMF VulnHub Walkthrough
## download
https://www.vulnhub.com/entry/imf-1,162/
## 服务器扫描

使用nmap扫描可发现该主机只开放了80端口

```
root@kali:~# nmap -T4 -A -v 192.168.56.101

Starting Nmap 7.60 ( https://nmap.org ) at 2018-03-28 07:26 EDT
NSE: Loaded 146 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 07:26
Completed NSE at 07:26, 0.00s elapsed
Initiating NSE at 07:26
Completed NSE at 07:26, 0.00s elapsed
Initiating ARP Ping Scan at 07:26
Scanning 192.168.56.101 [1 port]
Completed ARP Ping Scan at 07:26, 0.04s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 07:26
Completed Parallel DNS resolution of 1 host. at 07:26, 16.56s elapsed
Initiating SYN Stealth Scan at 07:26
Scanning 192.168.56.101 [1000 ports]
Discovered open port 80/tcp on 192.168.56.101
Completed SYN Stealth Scan at 07:26, 5.42s elapsed (1000 total ports)
Initiating Service scan at 07:26
Scanning 1 service on 192.168.56.101
Completed Service scan at 07:27, 6.08s elapsed (1 service on 1 host)
Initiating OS detection (try #1) against 192.168.56.101
NSE: Script scanning 192.168.56.101.
Initiating NSE at 07:27
Completed NSE at 07:27, 0.20s elapsed
Initiating NSE at 07:27
Completed NSE at 07:27, 0.00s elapsed
Nmap scan report for 192.168.56.101
Host is up (0.00055s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: IMF - Homepage
MAC Address: 08:00:27:A1:F5:E7 (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.10 - 4.8, Linux 3.16 - 4.6, Linux 3.2 - 4.8, Linux 4.4
Uptime guess: 0.298 days (since Wed Mar 28 00:17:32 2018)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: All zeros

TRACEROUTE
HOP RTT     ADDRESS
1   0.55 ms 192.168.56.101

NSE: Script Post-scanning.
Initiating NSE at 07:27
Completed NSE at 07:27, 0.00s elapsed
Initiating NSE at 07:27
Completed NSE at 07:27, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.39 seconds
           Raw packets sent: 2043 (92.396KB) | Rcvd: 13 (652B)
```

访问http://192.168.56.101可以看到界面

![52223728596](C:\Users\ADMINI~1\AppData\Local\Temp\1522237285965.png)

## Flag1

在contact页面右键源代码可以看到flag

![52223827440](C:\Users\ADMINI~1\AppData\Local\Temp\1522238274405.png)

```
root@kali:~# echo 'YWxsdGhlZmlsZXM='| base64 -d
allthefiles
```

allthefiles提示我们第二个flag在其他文件中或者与文件相关

## Flag2
## Flag3
## Flag4
## Flag5
## Flag6
## 收获



