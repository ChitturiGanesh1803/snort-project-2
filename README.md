# snort-project-2
PROJECT 2 – ATTACK DETECTION, BLOCKING, AND TUNING
================================================


1. SSH Brute Force Detection
---------------------------
Snort Rule:
alert tcp any any -> any 22 (msg:"SSH Brute Force Attempt"; flow:to_server,established; detection_filter:track by_src, count 5, seconds 60; sid:1000004; rev:1;)

Attacker Command:
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<KALI_IP>

Expected Result:
Snort triggers an alert when multiple SSH login attempts are detected from the same source within a short time window.


2. FTP Traffic Blocking
----------------------
Snort Rule:
drop tcp any any -> $HOME_NET 21 (msg:"FTP Traffic Blocked"; sid:1000006; rev:1;)

Attacker Command:
ftp <KALI_IP>

Expected Result:
FTP connection attempts are blocked and logged, preventing insecure file transfer access.


3. SMTP Traffic Rejection
------------------------
Snort Rule:
reject tcp any any -> $HOME_NET 25 (msg:"SMTP Traffic Rejected"; sid:1000007; rev:1;)

Attacker Command:
nc <KALI_IP> 25

Expected Result:
SMTP traffic is rejected and the connection is actively reset.


4. Blocking Port 9999
--------------------
Snort Rule:
block tcp any any -> $HOME_NET 9999 (msg:"Blocking traffic to port 9999"; sid:1000008; rev:1;)

Attacker Command:
nc <KALI_IP> 9999

Expected Result:
All traffic targeting port 9999 is blocked, preventing unauthorized access to non-standard services.


5. SQL Injection Detection
-------------------------
Snort Rule:
alert http any any -> $HOME_NET any (msg:"SQLi Detected"; http_uri; content:"UNION", nocase; content:"SELECT", nocase; sid:1000010; rev:7;)

Attacker Command:
curl "http://<KALI_IP>/index.php?id=1 UNION SELECT user,pass FROM users"

Expected Result:
Snort detects SQL injection patterns in HTTP request URIs and raises an alert.


6. Cross-Site Scripting (XSS) Detection
--------------------------------------
Snort Rule:
alert http any any -> $HOME_NET any (msg:"XSS Detected"; http_uri; content:"<script>"; sid:1000011; rev:11;)

Attacker Command:
curl "http://<KALI_IP>/search?q=<script>alert(1)</script>"

Expected Result:
Snort alerts on suspicious script tags embedded in HTTP requests.


7. Reverse Shell Detection
-------------------------
Snort Rule:
alert http any any -> $HOME_NET any (msg:"Reverse Shell Attempt Detected"; http_raw_request; content:"/bin/bash"; sid:1000012; rev:3;)

Attacker Command:
curl "http://<KALI_IP>/test?cmd=/bin/bash"

Expected Result:
Snort detects command execution attempts commonly used in reverse shell attacks.


RULE TUNING AND OPTIMIZATION
===========================

1. ICMP False Positive Reduction
-------------------------------
Snort Rule:
alert icmp any any -> $HOME_NET any (msg:"Excessive ICMP Ping Detected"; itype:8; detection_filter:track by_src, count 5, seconds 10; sid:1000020; rev:1;)

Attacker Command:
ping <KALI_IP>
ping -i 0.2 <KALI_IP>

Purpose:
Reduces false positives by alerting only when excessive ICMP echo requests occur.


2. HTTP Traffic Logging
----------------------
Snort Rule:
log tcp any any -> $HOME_NET 80 (msg:"HTTP Traffic Logged"; sid:1000021; rev:1;)

Purpose:
Logs HTTP traffic for analysis without triggering alerts, improving visibility while reducing noise.


3. Performance-Optimized Scan Detection
---------------------------------------
Snort Rule:
alert tcp any any -> $HOME_NET [20:1024] (msg:"Possible TCP SYN Scan Detected"; flags:S; detection_filter:track by_src, count 10, seconds 5; sid:1000022; rev:1;)

Attacker Command:
nmap -sS <KALI_IP>

Purpose:
Efficiently detects SYN-based port scans while minimizing performance overhead.


Summary
-------
Project 2 focuses on detecting active attacks, blocking insecure services, and tuning Snort rules to reduce false positives and improve performance. 
The implemented rules demonstrate real-world intrusion detection, prevention techniques, and optimization strategies used in SOC environments.
