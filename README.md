# Network-Testing
## Summary
I am using Nmap to enumerate services ports and operating systems of a device in my lab lan network. Everything performed in this repo was done in a controlled lab environment with authorization.

## Environment Setup
- wifi router
-  nmap (host device)
-  Lab PC (Host)

## Commands and Ip ranges
- **Host IP**: using Ipconfig i got my ip 192.198.*.*
- **Basic Scan**: nmap 192.198.
- **Service Version Detection**: nmap -sV 192.198.*.*
- **OS Detection**: nmap -O 192.198.*.*

## Observations
### Basic-Scan
From the Basic scan results i discovered 4 open ports as seen in the image below
![basic](Scans/Basic-Scan.PNG)
### Service Version
Next I run the following command to detect the Service version. nmap -sV 192.168.30 The image below shows the result of the scan. 
![SV](Scans/Service-Detect.PNG)
### OS Detection
Next i want to detect the Operating System of the device. I run the following command to detect the Operating system. nmap -O 192.168.

![OS](Scans/OS-Detect.PNG)
