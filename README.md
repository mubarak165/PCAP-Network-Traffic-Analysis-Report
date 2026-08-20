# PCAP-Network-Traffic-Analysis-Report
## Executive Summary

Analysis of network traffic from LAN segment `10.11.11.0/24` identified a Windows host (`10.11.11.xxx`) that downloaded a malicious executable over HTTP. The file was confirmed malicious via VirusTotal with a detection rate of **XX/XX**. Post-infection traffic showed the host beaconing to `[public IP(s)]`, consistent with **[malware family/behavior, if identifiable]**. 

**Recommendation:** Block the identified IOCs and isolate the affected host for remediation.
