# ClearShot

## Introduction

Welcome to this CTF challenge, where you'll exploit CVE-2023-32315 in Openfire, a messaging and group chat server. This vulnerability allows an authentication bypass via a path traversal attack, granting unauthorized access to application files and enabling Remote Code Execution (RCE). Your goal is to exploit this flaw, gain access, and capture the flag.

## Skills Required
Basic Linux

Basic Network Enumeration

Running scripts

## Skills Learned
Identifying vulnerable services

XMPP Enumeration and Exploitation 

Remote Code Execution

## Info for HTB

### Access

Passwords:

| User  | Password                            |
| ----- | ----------------------------------- |
|openfire| AdminNotHerehtb#2024 |



## Key Processes

Openfire
The core process of the Openfire server, responsible for managing XMPP communications, user authentication, message routing, and group chat functionality.

Ports:

9090: HTTP port for the Openfire Admin Console.

9091: HTTPS port for the Openfire Admin Console.

5222: Client-to-Server communication port.

5223: Secure Client-to-Server communication port.

5269: Server-to-Server communication port.

5005: JVM Debugging port.




## Docker

This docker image is being used with some slight modification.
```
git clone https://github.com/luzifer-docker/openfire
```

DockerFile
```
FROM alpine

LABEL maintainer Knut Ahlers <knut@ahlers.me>

ENV OPENFIRE_VERSION=4_7_4

RUN set -ex \
 && apk --no-cache add \
      bash \
      ca-certificates \
      curl \
      openjdk11 \
 && mkdir -p /opt \
 && curl -sSfL "https://www.igniterealtime.org/downloadServlet?filename=openfire/openfire_${OPENFIRE_VERSION}.tar.gz" | \
      tar -xz -C /opt \
 && curl -sSfLo /usr/local/bin/dumb-init https://github.com/Yelp/dumb-init/releases/download/v1.2.1/dumb-init_1.2.1_amd64 \
 && chmod +x /usr/local/bin/dumb-init

ADD start.sh /usr/local/bin/start.sh

EXPOSE 9090 9091 5222 5223 5269
VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/start.sh", "-remotedebug"]

```

start.sh 
```
#!/usr/local/bin/dumb-init /bin/bash
set -euo pipefail

# init configuration
[ -e "/data/security/keystore" ] || {
        mkdir -p /data/security
        mv /opt/openfire/resources/security/keystore /data/security/keystore
}

[ -d "/data/embedded-db" ] || { mkdir -p /data/embedded-db; }
[ -d "/data/conf" ] || { mv /opt/openfire/conf /data/conf; }

ln -sfn /data/security/keystore /opt/openfire/resources/security/keystore
ln -sfn /data/embedded-db /opt/openfire/embedded-db
rm -rf /opt/openfire/conf && ln -sfn /data/conf /opt/openfire/conf

# start openfire
/opt/openfire/bin/openfire start

# let openfire start
echo "Waiting for Openfire to start..."
count=0
while [ ! -e /opt/openfire/logs/stdoutt.log ]; do
        if [ $count -eq 60 ]; then
                echo "Error starting Openfire. Exiting"
                exit 1
        fi
        count=$((count + 1))
        sleep 1
done

# tail the log
tail -F /opt/openfire/logs/*.log
```


# Writeup

# Enumeration
## Nmap
We start things off by performing an nmap scan against the target IP address.
```
nmap <target-ip>
```
By performing the nmap scan, we get the following result.
![image](https://github.com/WhitewolfX01/Test/assets/126961828/2ec2a322-7757-4af0-9c62-5ca6316a4ed4)

From the scan result, we found out that a admin page is running on port 9090. So let's go to this page.
```
http://<target-ip>:9090
```
![image](https://github.com/WhitewolfX01/Test/assets/126961828/68970234-171d-4b4f-b2f6-6ebf32fba545)

On the admin page, we tried to login using default credentials, but we were unsuccessful. But we found out that the Openfire is of version 4.7.4.
Performing a quick search on google, we found out that it is vulnerable to path traversal attack, that leads to Remote Code Execution(RCE).



# Foothold

For initial foothold, we will use a publicly available script for getting the intial access. Clone this repo and move into it.
```
https://github.com/miko550/CVE-2023-32315.git
cd CVE-2023-32315
```

Now install all the requirements for the script.
```
pip3 install -r requirements.txt
```

Now use the script to get a username and password to login into the admin panel.
```
python3 CVE-2023-32315.py -t http://<target-ip>:9090
```
Running the script, we will get the following output with a random username and password for login to the admin panel.
![image](https://github.com/WhitewolfX01/Test/assets/126961828/4de5e1a5-52c8-4cb6-b271-65784556735c)
Note: Your username and password will differ from the one generated here.

Now let's login into the admin panel with the generated username and password.
Congratulations! We have successfully logged into the admin panel.
![image](https://github.com/WhitewolfX01/Test/assets/126961828/64e9bf38-acb5-44e0-a6e5-7061aa959a69)


# Privilege Escalation
We have accessed the admin panel, but we do not have the access to the server. Now we have to gain access of the server that is hosting the Openfire.
While exploring the panel, we got across the plugins option.
The plugins feature is used to upload custom plugins for use. 
![image](https://github.com/WhitewolfX01/Test/assets/126961828/4c42219f-6e50-420e-82d3-d3ef8c91e524)

Now upload the openfire-management-tool-plugin.jar (present is the directory that you cloned from github) to the panel by clicking on Browse button, and select the .jar file and click Upload Plugin.
It will be successfully uploaded.
![image](https://github.com/WhitewolfX01/Test/assets/126961828/75fcc54e-f8d0-46a1-af91-c087c01939f5)

Then click on Server option on the top and select Server Settings.
![image](https://github.com/WhitewolfX01/Test/assets/126961828/e14a6781-cbe7-4f54-bc16-aa748759a6d4)

From the left side menu, select Management Tools, and we got a screen like this.
![image](https://github.com/WhitewolfX01/Test/assets/126961828/e42b8b4f-4a68-471b-b668-03c02b3a8c61)

It will ask for password, enter "123" as password. You will get into management section.

From the top menu, select System Command.
![image](https://github.com/WhitewolfX01/Test/assets/126961828/fac40486-a665-4b99-9da7-75a20881647b)

Then you will get a screen like this.
![image](https://github.com/WhitewolfX01/Test/assets/126961828/3f4015b3-42a6-494d-bf66-58d37840fa57)

Now enter ```whoami``` to check which user you are.
![image](https://github.com/WhitewolfX01/Test/assets/126961828/b63d9303-b6ae-466c-9372-0e21a76ea357)
We see that we have root user access.

Now for the final step, we have to get the root flag.
The flag is in the root directory. Find it and your challenge is completed.

