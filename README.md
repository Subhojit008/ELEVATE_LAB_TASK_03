# 🔍 Task 03 - Basic Vulnerability Scan on Localhost

## 🛡️ Objective
The objective of this task is to perform a basic vulnerability scan on my local machine using Nessus Essentials to identify common system vulnerabilities and document their mitigations.

---

## 🧰 Tools Used

- **Nessus Essentials** by Tenable (Free license)
- **Operating System**: Windows/Linux (localhost)
- **Browser Access**: https://localhost:8834

---

## 🎯 Target

- **IP Address**: 192.168.29.238
- **Scan Type**: Full System Vulnerability Scan
- **Port Analyzed**: TCP 15150

---

## 🔎 High-Risk Vulnerability Identified

### 1. SSL Medium Strength Cipher Suites Supported (SWEET32)

- **Plugin ID**: 42873
- **Severity**: High
- **Host**: 192.168.29.238:15150

#### 📄 Description

The remote server supports SSL cipher suites with medium strength encryption, specifically using the 3DES (Triple DES) algorithm. This makes it vulnerable to the SWEET32 attack (CVE-2016-2183), which could allow an attacker on the same network to recover sensitive information from encrypted sessions.

#### ⚠️ Impact

The use of 3DES in SSL/TLS allows statistical analysis attacks when a large amount of traffic is captured, particularly on shared networks.

#### ✅ Solution

Reconfigure the affected application to:

- **Disable 3DES and other medium-strength ciphers**
- **Use strong ciphers like AES-GCM**
- **Restrict SSL/TLS versions to TLS 1.2 or TLS 1.3**

##### Example Fix for Apache Web Server:

```apache
SSLCipherSuite HIGH:!aNULL:!MD5:!3DES
SSLProtocol All -SSLv2 -SSLv3 -TLSv1 -TLSv1.1

🧾 Files Included
File Name	Description
Nessus-Scan-Report.pdf	Detailed vulnerability report (SWEET32)
mitigation_notes.txt	Manual steps to mitigate critical findings
screenshots/	Screenshots from Nessus scan (optional)


🧠 Learning Outcome
Through this task, I gained practical experience with vulnerability scanning tools like Nessus, learned how to analyze high-risk findings, and understood mitigation strategies for real-world SSL/TLS misconfigurations such as SWEET32.
#### 🧨 Cipher Detected

