## Proving Grounds - Amaterasu writeup - 192.168.206.249 


### Enumeration

> Nmap shows us port 21 is open and anonymous login is allowed.
> port 21 running vsftpd 3.0.3
> port 25022 is open and running OpenSSH 8.6 (protocol 2.0)
> port 33414 is open and looks to be running web framework Werkzeug/2.2.3 Python/3.9.13
> port 40080 is open and running Apache httpd 2.4.53 (Fedora)


#### Nmap scan results

	Nmap scan report for 192.168.206.249
	Host is up, received echo-reply ttl 61 (0.053s latency).
	Scanned at 2025-01-10 17:43:34 CST for 124s

	PORT      STATE  SERVICE          REASON         VERSION
	21/tcp    open   ftp              syn-ack ttl 61 vsftpd 3.0.3
	| ftp-anon: Anonymous FTP login allowed (FTP code 230)
	|_Can't get directory listing: TIMEOUT
	| ftp-syst: 
	|   STAT: 
	| FTP server status:
	|      Connected to 192.168.45.247
	|      Logged in as ftp
	|      TYPE: ASCII
	|      No session bandwidth limit
	|      Session timeout in seconds is 300
	|      Control connection is plain text
	|      Data connections will be plain text
	|      At session startup, client count was 2
	|      vsFTPd 3.0.3 - secure, fast, stable
	|_End of status
	22/tcp    closed ssh              reset ttl 61
	111/tcp   closed rpcbind          reset ttl 61
	139/tcp   closed netbios-ssn      reset ttl 61
	443/tcp   closed https            reset ttl 61
	445/tcp   closed microsoft-ds     reset ttl 61
	2049/tcp  closed nfs              reset ttl 61
	10000/tcp closed snet-sensor-mgmt reset ttl 61
	25022/tcp open   ssh              syn-ack ttl 61 OpenSSH 8.6 (protocol 2.0)
	| ssh-hostkey: 
	|   256 68:c6:05:e8:dc:f2:9a:2a:78:9b:ee:a1:ae:f6:38:1a (ECDSA)
	| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBD6xv/PZkusP5TZdYJWDT8TTNY2xojo5b2DU/zrXm1tP4kkjNCGmwq8UwFrjo5EbEbk3wMmgHBnE73XwgnqaPd4=
	|   256 e9:89:cc:c2:17:14:f3:bc:62:21:06:4a:5e:71:80:ce (ED25519)
	|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRX3RvvSVPY3FJV9u7N2xIQbLJgQoEMkmRMey39/Jxz
	33414/tcp open   unknown          syn-ack ttl 61
	| fingerprint-strings: 
	|   GetRequest, HTTPOptions: 
	|     HTTP/1.1 404 NOT FOUND
	|     Server: Werkzeug/2.2.3 Python/3.9.13
	|     Date: Fri, 10 Jan 2025 23:43:41 GMT
	|     Content-Type: text/html; charset=utf-8
	|     Content-Length: 207
	|     Connection: close
	|     <!doctype html>
	|     <html lang=en>
	|     <title>404 Not Found</title>
	|     <h1>Not Found</h1>
	|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
	|   Help: 
	|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
	|     "http://www.w3.org/TR/html4/strict.dtd">
	|     <html>
	|     <head>
	|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
	|     <title>Error response</title>
	|     </head>
	|     <body>
	|     <h1>Error response</h1>
	|     <p>Error code: 400</p>
	|     <p>Message: Bad request syntax ('HELP').</p>
	|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
	|     </body>
	|     </html>
	|   RTSPRequest: 
	|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
	|     "http://www.w3.org/TR/html4/strict.dtd">
	|     <html>
	|     <head>
	|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
	|     <title>Error response</title>
	|     </head>
	|     <body>
	|     <h1>Error response</h1>
	|     <p>Error code: 400</p>
	|     <p>Message: Bad request version ('RTSP/1.0').</p>
	|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
	|     </body>
	|_    </html>
	40080/tcp open   http             syn-ack ttl 61 Apache httpd 2.4.53 ((Fedora))
	|_http-title: My test page
	| http-methods: 
	|   Supported Methods: HEAD GET POST OPTIONS TRACE
	|_  Potentially risky methods: TRACE
	|_http-server-header: Apache/2.4.53 (Fedora)
	1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
	SF-Port33414-TCP:V=7.94SVN%I=7%D=1/10%Time=6781B0AC%P=aarch64-unknown-linu
	SF:x-gnu%r(GetRequest,184,"HTTP/1\.1\x20404\x20NOT\x20FOUND\r\nServer:\x20
	SF:Werkzeug/2\.2\.3\x20Python/3\.9\.13\r\nDate:\x20Fri,\x2010\x20Jan\x2020
	SF:25\x2023:43:41\x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r
	SF:\nContent-Length:\x20207\r\nConnection:\x20close\r\n\r\n<!doctype\x20ht
	SF:ml>\n<html\x20lang=en>\n<title>404\x20Not\x20Found</title>\n<h1>Not\x20
	SF:Found</h1>\n<p>The\x20requested\x20URL\x20was\x20not\x20found\x20on\x20
	SF:the\x20server\.\x20If\x20you\x20entered\x20the\x20URL\x20manually\x20pl
	SF:ease\x20check\x20your\x20spelling\x20and\x20try\x20again\.</p>\n")%r(HT
	SF:TPOptions,184,"HTTP/1\.1\x20404\x20NOT\x20FOUND\r\nServer:\x20Werkzeug/
	SF:2\.2\.3\x20Python/3\.9\.13\r\nDate:\x20Fri,\x2010\x20Jan\x202025\x2023:
	SF:43:41\x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent
	SF:-Length:\x20207\r\nConnection:\x20close\r\n\r\n<!doctype\x20html>\n<htm
	SF:l\x20lang=en>\n<title>404\x20Not\x20Found</title>\n<h1>Not\x20Found</h1
	SF:>\n<p>The\x20requested\x20URL\x20was\x20not\x20found\x20on\x20the\x20se
	SF:rver\.\x20If\x20you\x20entered\x20the\x20URL\x20manually\x20please\x20c
	SF:heck\x20your\x20spelling\x20and\x20try\x20again\.</p>\n")%r(RTSPRequest
	SF:,1F4,"<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN
	SF:\"\n\x20\x20\x20\x20\x20\x20\x20\x20\"http://www\.w3\.org/TR/html4/stri
	SF:ct\.dtd\">\n<html>\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x2
	SF:0\x20<meta\x20http-equiv=\"Content-Type\"\x20content=\"text/html;charse
	SF:t=utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<title>Error\x20response</t
	SF:itle>\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x2
	SF:0\x20\x20\x20\x20<h1>Error\x20response</h1>\n\x20\x20\x20\x20\x20\x20\x
	SF:20\x20<p>Error\x20code:\x20400</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>
	SF:Message:\x20Bad\x20request\x20version\x20\('RTSP/1\.0'\)\.</p>\n\x20\x2
	SF:0\x20\x20\x20\x20\x20\x20<p>Error\x20code\x20explanation:\x20HTTPStatus
	SF:\.BAD_REQUEST\x20-\x20Bad\x20request\x20syntax\x20or\x20unsupported\x20
	SF:method\.</p>\n\x20\x20\x20\x20</body>\n</html>\n")%r(Help,1EF,"<!DOCTYP
	SF:E\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x
	SF:20\x20\x20\x20\x20\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<h
	SF:tml>\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20
	SF:http-equiv=\"Content-Type\"\x20content=\"text/html;charset=utf-8\">\n\x
	SF:20\x20\x20\x20\x20\x20\x20\x20<title>Error\x20response</title>\n\x20\x2
	SF:0\x20\x20</head>\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\
	SF:x20<h1>Error\x20response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error
	SF:\x20code:\x20400</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Ba
	SF:d\x20request\x20syntax\x20\('HELP'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x2
	SF:0\x20<p>Error\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\x20-\x
	SF:20Bad\x20request\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x
	SF:20\x20\x20</body>\n</html>\n");
	OS fingerprint not ideal because: Didn't receive UDP response. Please try again with -sSU
	Aggressive OS guesses: Linux 5.0 (92%), Linux 5.0 - 5.4 (92%), Linux 4.15 - 5.8 (89%), HP P2000 G3 NAS device (89%), Linux 5.3 - 5.4 (89%), Linux 2.6.32 (89%), Infomir MAG-250 set-top box (88%), Ubiquiti AirMax NanoStation WAP (Linux 2.6.32) (88%), Linux 5.0 - 5.5 (88%), Linux 5.1 (88%)
	No exact OS matches for host (test conditions non-ideal).
	TCP/IP fingerprint:
	SCAN(V=7.94SVN%E=4%D=1/10%OT=21%CT=22%CU=%PV=Y%DS=4%DC=T%G=N%TM=6781B122%P=aarch64-unknown-linux-gnu)
	SEQ(SP=105%GCD=1%ISR=10D%TI=Z%CI=Z%TS=A)
	SEQ(SP=105%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)
	OPS(O1=M578ST11NW7%O2=M578ST11NW7%O3=M578NNT11NW7%O4=M578ST11NW7%O5=M578ST11NW7%O6=M578ST11)
	WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)
	ECN(R=Y%DF=Y%TG=40%W=FAF0%O=M578NNSNW7%CC=Y%Q=)
	T1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
	T2(R=N)
	T3(R=N)
	T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
	T5(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
	T6(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
	T7(R=N)
	U1(R=N)
	IE(R=Y%DFI=N%TG=40%CD=S)

	Uptime guess: 30.975 days (since Tue Dec 10 18:22:16 2024)
	Network Distance: 4 hops
	TCP Sequence Prediction: Difficulty=261 (Good luck!)
	IP ID Sequence Generation: All zeros
	Service Info: OS: Unix

	TRACEROUTE (using port 22/tcp)
	HOP RTT      ADDRESS
	1   54.13 ms 192.168.45.1
	2   54.10 ms 192.168.45.254
	3   55.49 ms 192.168.251.1
	4   55.54 ms 192.168.206.249

	Read data files from: /usr/bin/../share/nmap
	OS and Service detection performed.


#### Port 33414 werkzueg directory scan.

> After running a feroxbuster scan on port 33414 I can see the following directories. 

![feroxbuster](/Amaterasu/images/feroxbuster-33414.png) 


1. /help
2. /info
3. /file-upload


### Initial Foothold

> Viewing the /help directory it looks like we might be able to read files on the server with the following.

> "GET /file-list?dir=/tmp : List of the files"
> Through some enumeration we can see there is an internal user named alfredo, but I wasn't able to read his SSH key.

![Website](/Amaterasu/images/help.png) 

![Website](/Amaterasu/images/dir.png) 

> I can't grab Alfredo's SSH key but maybe I can upload my SSH key into Alfredo's .ssh directory. I'll use the ssh-keygen command to generate ssh keys and name them id_alfredo. 


> I generated the SSH keys and just used a NULL password. Let's try and use curl to POST the files to the /file-upload endpoint.

![Website](/Amaterasu/images/keygen.png) 

> There is now an authorized_keys file in Alfredo's .ssh directory we should be able to SSH into the target now using the private key. 


![Website](/Amaterasu/images/upload.png) 

> We are able to SSH in as Alfredo and can grab the local.txt flag. 

![Website](/Amaterasu/images/ssh.png) 


### Priv Esc


![Website](/Amaterasu/images/cron.png) 


> running the cat /etc/cron* command we can see a bash script /usr/local/bin/backup-flask.sh that's running as a cronjob as root on the host machine. 

	#!/bin/sh
	export PATH="/home/alfredo/restapi:$PATH"
	cd /home/alfredo/restapi
	tar czf /tmp/flask.tar.gz *

> Analyzing the bash script it's adding /home/alfredo/restapi to the PATH value, then it's changing to the /home alfredo/restapi directory and finally its running the tar command to create a gzip file of everything located in the /home/alfredo/restapi which is what the * wildcard indicates and outputting the tar gzip file at /tmp/flask.tar.gz.

> I found a helpful resource online about abusing [tar with wildcards for privilege escalation](https://medium.com/@polygonben/linux-privilege-escalation-wildcards-with-tar-f79ab9e407fa). 

> First we need to create 2 files in the restapi directory called '--checkpoint=1' and '--checkpoint-action=exec=sh privesc.sh. I just did this with the touch command you chould also do it with the echo command. 


![Website](/Amaterasu/images/touch.png) 

> Next we need to add our current use alfredo to the /etc/sudoers file to be able to run any command as sudo with the following. echo 'alfredo ALL=(root) NOPASSWD: ALL' > /etc/sudoers. But this needs to be in our privesc.sh script so first we'll have to echo '#!/bin/bash to tell the interpreter it's a bash script. 

> I used vi to run the echo command to put our user alfredo into the sudoers file to be able to execute all commands with sudo. Once the cronjob runs we should be able to just run sudo su and it should give us root privileges on the target machine. If we run the sudo -l command we will be able to tell if it's worked or not.

![Website](/Amaterasu/images/root.png) 

> Our exploit script worked and we are now root and can grab the proof.txt file from /root directory.

![Website](/Amaterasu/images/pwned.png) 

> Remember to cleanup after ourselves when we are finished. 

![Website](/Amaterasu/images/cleanup.png) 
