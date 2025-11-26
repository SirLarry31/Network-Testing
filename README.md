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
From the scan results i discovered 4 open ports as seen in the image below
