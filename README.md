# PCAP-Network-Traffic-Analysis-Report
## 1. Executive Summary

Analysis of network traffic from LAN segment `10.11.11.0/24` identified a **Windows 7** host (`10.11.11.203`) that downloaded a Windows executable disguised as a `.tiff` file over HTTP from `acjabogados.com`. The file (SHA256: `8d5d36c8ffb0a9c81b145aa40c1ff3475702fb0b5f9e08e0577bdc405087e635`) was confirmed malicious via VirusTotal with a detection rate of **49/70**.

Following the download, the infected host attempted repeated outbound TCP connections to two public IP addresses (`5.188.108.58` and `138.201.6.195`) with no server response, consistent with **C2 beaconing**.

The host was identified via Kerberos traffic as **`Tucker-Win7-PC`**, used by domain account **`candice.tucker`**. Six additional non-Windows devices on the segment were fingerprinted via HTTP User-Agent and MAC OUI analysis to build a full picture of the environment.

## 2. Scope and Environment

| Item | Value |
|------|-------|
| LAN Segment | `10.11.11.0/24` |
| Domain | `okay-boomer.info` |
| Domain Controller | `10.11.11.11` |
| Gateway | `10.11.11.1` |
| Broadcast | `10.11.11.255` |
| Capture File | `2019-11-12-traffic-analysis-exercise.pcap` |

## 3. Methodology

1. Loaded the PCAP in Wireshark and reviewed **Statistics → Protocol Hierarchy** and **Statistics → Conversations** to get an overview of traffic volume and protocols in use. **Show Image**

2. Filtered HTTP requests per host (`http.request and ip.addr eq <ip>`) and followed TCP streams to extract User-Agent strings for OS/device fingerprinting. **Show Image**

3. Reviewed MAC address vendor prefixes (Ethernet II source field) for devices without identifiable HTTP traffic.

4. Filtered `kerberos.CNameString` traffic to map Windows hostnames and domain usernames to IP addresses. **Show Image**

5. Identified the malicious download using `ip contains "This program"` to catch the **"MZ / This program cannot be run in DOS mode"** signature of a PE executable inside HTTP traffic.

6. Exported the object (**File → Export Objects → HTTP**) and computed its SHA256 hash with `shasum -a 256`.

7. Checked the hash against **VirusTotal** for detection results.

8. Filtered traffic using:
   ```text
   ip.addr eq <infected host> and !(ip.dst eq 10.11.11.1)
