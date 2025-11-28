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
- From the image above Nmap (Network Mapper) shows the target device is actively connected to the network and responding to probes.
- The Not shown: 996 closed tcp ports (reset) 
Nmap scans a large range of common ports by default (usually the top 1000 most common).
Closed tcp ports (reset): The target device explicitly responded to 996 port probes with a TCP 'RST' (reset) packet, confirming those specific services are not running or are explicitly blocked. 
## Open Ports and Services
- This is the most critical section. "Open" ports indicate that a service is actively listening for connections on the network.
- Port 135/tcp is associated with MSRPC (Microsoft Remote Procedure Call), which serves as the endpoint mapper for RPC services. This port allows clients to bind to a remote computer and enumerate available services or request specific service ports. While it is essential for certain Windows functionalities, having it open can pose security risks, as it may be exploited by attackers to gain unauthorized access to services on the system.
## Security Implications and vulnerability of TCP Port 135
- While TCP Port 135 is essential for Windows RPC services, it is also one of the most frequently targeted network ports due to its association with RPC services and DCOM communication. These protocols are fundamental to Windows-based networks, but their design leaves room for exploitation, making Windows Port 135 a prime attack vector for cybercriminals. One of the biggest risks associated with TCP 135 is its history of being exploited in major cyberattacks. 
- Beyond malware propagation, network Port 135 is often exploited in denial-of-service (DoS) attacks. Attackers can overwhelm TCP 135 with excessive requests and RPC-dependent services to slow down or crash entirely. A targeted attack on Windows Port 135 could disrupt an entire organization’s workflow and leave systems inaccessible across the board. Because the TCP 135 Port is used for facilitating remote connect ports in Windows-based networks, attackers may also exploit it to execute unauthorized commands or escalate privileges within a system. If a hacker gains access through an exposed Windows RPC Port, they can move laterally across the network, install malicious software, or extract sensitive data without the victim’s knowledge.
## How To Secure TCP Port 135
- Due to its extensive reach, securing TCP port 135 requires checking multiple boxes to minimize the chances of DoS attacks, unauthorized access, malware infections, and other security risks. Typically, setting up firewall rules, port restrictions, and updating security patches must be done and observe regularly.
- One of the most effective ways to secure TCP 135 is by using firewall configurations to limit or block access. Windows and third-party firewalls allow administrators to create custom rules that prevent external threats from exploiting Port 135 RPC. If Windows RPC services are not required for specific operations, the best practice is to close network Port 135 entirely to eliminate any potential attack surface.
- For businesses that rely on Windows RPC Port for essential services like Active Directory and Microsoft Exchange Server, it’s recommended to restrict access to internal, trusted networks. To prevent remote attacks and access from untrusted sources, firewalls should be configured to allow TCP 135 traffic only from authorized IP addresses.
- Disable RPC Services When Not Needed
- Since TCP 135 Port is used for remote procedure calls, disabling Windows RPC services can significantly reduce security risks in environments where they are not essential. If a system does not rely on network Port 135, administrators can disable DCOM and RPC services through the Windows Registry or Group Policy settings. This approach ensures that attackers cannot exploit Port 135 vulnerabilities to gain unauthorized access.
## Thoughts on TCP 135
- TCP Port 135 is a crucial part of Windows-based networks, but its importance comes with significant security risks. Attackers frequently target Windows Port 135 to exploit RPC vulnerabilities, launch denial-of-service attacks, and gain unauthorized access to systems.

History has shown what happens when network Port 135 is left exposed. Attacks like WannaCry and Blaster Wormspread rapidly and cause major security issues for organizations. That’s why securing Windows RPC Port isn’t optional. Organizations must take proactive measures, from restricting access with firewalls to disabling RPC services when unnecessary and keeping systems patched.

- A strong security posture isn’t just about locking down a single remote connect port; it’s about building a network that’s resilient to threats. Regular updates, monitoring, and controlled access are key to reducing risks and keeping systems protected.
However, before disabling Windows Port 135 RPC, it’s important to assess the impact on business applications and network operations. Some services may require remote connect ports for communication, and disabling RPC without proper planning could disrupt critical workflows
- I have confirmed something about TCP port 135:

Anyone can connect to TCP port 135 then get RPC interfaces list without any permission.
### Service Version
Next I run the following command to detect the Service version. nmap -sV 192.168.30 The image below shows the result of the scan. 
![SV](Scans/Service-Detect.PNG)
### OS Detection
Next i want to detect the Operating System of the device. I run the following command to detect the Operating system. nmap -O 192.168.

![OS](Scans/OS-Detect.PNG)
