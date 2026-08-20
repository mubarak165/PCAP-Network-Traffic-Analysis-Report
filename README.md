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

1. Loaded the PCAP in Wireshark and reviewed **Statistics → Protocol Hierarchy** and **Statistics → Conversations** to get an overview of traffic volume and protocols in use.


    <img width="3840" height="2160" alt="image" src="https://github.com/user-attachments/assets/941a9d75-162a-42f9-a056-91a5c5c6a080" />
 **Statistics → Protocol Hierarchy**
   
   <img width="3840" height="2160" alt="image" src="https://github.com/user-attachments/assets/a0238d9b-a2e7-47e2-a797-0440e0556db4" />
 **Statistics → Conversations**

2. Filtered HTTP requests per host (`ip.addr==10.11.11.195 &&(httP)`) and followed TCP streams to extract User-Agent strings for OS/device fingerprinting.
   <img width="3840" height="2160" alt="image" src="https://github.com/user-attachments/assets/6812b963-4d24-4dc5-8c83-b1b97ccbce3f" />


4. Reviewed MAC address vendor prefixes (Ethernet II source field) for devices without identifiable HTTP traffic.
   <img width="3800" height="1795" alt="image" src="https://github.com/user-attachments/assets/bc26cc0a-fe23-45c6-a062-a7869a6f4fbe" />


5. Filtered `kerberos.CNameString` traffic to map Windows hostnames and domain usernames to IP addresses.
   <img width="3832" height="1900" alt="image" src="https://github.com/user-attachments/assets/2c64a531-6f11-4ec0-bd7f-586f74d3ca98" />


6. Identified the malicious download using `ip contains "This program"` to catch the **"MZ / This program cannot be run in DOS mode"** signature of a PE executable inside HTTP traffic.
   <img width="3815" height="1945" alt="image" src="https://github.com/user-attachments/assets/935c4c43-9220-4e89-87cf-d1e606c5894b" />


7. Exported the object (**File → Export Objects → HTTP**) and computed its SHA256 hash with `shasum -a 256`,to achieve this i firstly traced the host name  of  where the executable  was  downloaded  from by clicking  follow stream.

   <img width="3770" height="1957" alt="image" src="https://github.com/user-attachments/assets/ece16db8-9a9e-47fb-a857-bdd8b3f6f52d" />

then exported the executable file

<img width="3487" height="1910" alt="image" src="https://github.com/user-attachments/assets/2326e64f-949a-4997-9617-22a8fe471a9f" />


8. Checked the hash against **VirusTotal** for detection results.

   <img width="3840" height="2160" alt="image" src="https://github.com/user-attachments/assets/4ca7a04b-18dc-487d-a321-64c82adf97cd" />


9. Filtered traffic using:
   ```text
   ip.addr eq 10.11.11.203 and !(ip.dst eq 10.11.11.0/24)

<img width="3822" height="1875" alt="image" src="https://github.com/user-attachments/assets/4779b096-2252-429a-8493-6c998a9c0656" />

