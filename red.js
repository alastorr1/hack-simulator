document.addEventListener('DOMContentLoaded', () => {
    // --- FLAT TOOL LIST (ensure all tools are present) ---
    const allTools = {
        nmap: {
            name: 'Nmap',
            guide: `<h3>Nmap</h3>
<p><b>What is it?</b><br>Nmap (Network Mapper) is a powerful open-source tool for network discovery and security auditing. It is widely used for mapping networks, discovering hosts, open ports, and services, and fingerprinting operating systems.</p>
<p><b>How does it work?</b><br>Nmap sends specially crafted packets to the target and analyzes the responses to determine what hosts are available, what services (application name and version) those hosts are offering, what operating systems (and OS versions) they are running, what type of packet filters/firewalls are in use, and other characteristics.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>nmap -A -T4 scanme.nmap.org</code> - Aggressive scan with OS and service detection</li>
  <li><code>nmap -p 1-1000 192.168.1.1</code> - Scan first 1000 ports on a host</li>
</ul>
<p><b>Typical output:</b></p>
<pre>Starting Nmap 7.93 ( https://nmap.org ) at 2024-06-01 12:00 UTC
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.10s latency).
Not shown: 995 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.7 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
</pre>`,
            commands: {
                "nmap -A -T4 scanme.nmap.org": "Starting Nmap 7.93 ( https://nmap.org ) at 2024-06-01 12:00 UTC\nNmap scan report for scanme.nmap.org (45.33.32.156)\nHost is up (0.10s latency).\nNot shown: 995 closed ports\nPORT     STATE SERVICE VERSION\n22/tcp   open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)\n80/tcp   open  http    Apache httpd 2.4.7 ((Ubuntu))\nService Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel\n",
                "nmap -p 1-1000 192.168.1.1": "Starting Nmap 7.93 ( https://nmap.org ) at 2024-06-01 12:01 UTC\nNmap scan report for 192.168.1.1\nHost is up (0.01s latency).\nPORT    STATE SERVICE\n22/tcp  open  ssh\n80/tcp  open  http\n443/tcp open  https\nNmap done: 1 IP address (1 host up) scanned in 2.12 seconds"
            },
            description: 'Network mapping, port scanning, and service enumeration.'
        },
        'recon-ng': {
            name: 'Recon-ng',
            guide: `<h3>Recon-ng</h3>
<p><b>What is it?</b><br>Recon-ng is a full-featured Web Reconnaissance framework written in Python. It provides a powerful environment for open-source intelligence (OSINT) gathering and automates many common reconnaissance tasks for penetration testers.</p>
<p><b>How does it work?</b><br>Recon-ng uses a modular framework, similar to Metasploit, where you can load modules to perform specific tasks such as domain reconnaissance, harvesting emails, or gathering credentials. It integrates with many public data sources and APIs to automate information gathering.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>recon-ng</code> - Start the Recon-ng console</li>
  <li><code>modules search domain</code> - Search for modules related to domain reconnaissance</li>
  <li><code>modules load recon/domains-hosts/google_site_web</code> - Load a specific module</li>
  <li><code>run</code> - Execute the loaded module</li>
</ul>
<p><b>Typical output:</b></p>
<pre>Welcome to Recon-ng v5.1.2
[recon-ng][default] > modules search domain
[recon-ng][default] > modules load recon/domains-hosts/google_site_web
[recon-ng][default] > run
[*] Searching Google for hosts related to example.com...
[+] Found: www.example.com
[+] Found: mail.example.com
</pre>`,
            commands: {
                "recon-ng": "Welcome to Recon-ng v5.1.2\n[recon-ng][default] > ",
                "modules search domain": "[recon-ng][default] > modules search domain\nFound 5 modules:\n- recon/domains-hosts/google_site_web\n- recon/domains-contacts/whois_pocs\n...",
                "modules load recon/domains-hosts/google_site_web": "[recon-ng][default] > modules load recon/domains-hosts/google_site_web\nModule loaded.",
                "run": "[*] Searching Google for hosts related to example.com...\n[+] Found: www.example.com\n[+] Found: mail.example.com"
            },
            description: 'Modular OSINT and reconnaissance automation.'
        },
        maltego: {
            name: 'Maltego',
            guide: `<h3>Maltego</h3>
<p><b>What is it?</b><br>Maltego is a data mining tool that allows for link analysis and visualization of relationships between people, groups, websites, domains, and other entities. It is widely used for OSINT and cyber threat intelligence.</p>
<p><b>How does it work?</b><br>Maltego uses "transforms" to automate the process of gathering related data from public sources and visualizes the results as graphs. You can start with a single entity (like a domain) and expand to see connected infrastructure, emails, or social profiles.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>maltego</code> - Launch the Maltego GUI</li>
  <li><code>add entity: Domain</code> - Add a domain entity to the graph</li>
  <li><code>run transform: To IP Address</code> - Discover IP addresses associated with the domain</li>
</ul>
<p><b>Typical output:</b></p>
<pre>Maltego GUI started.
[Graph] example.com
  |-- 93.184.216.34 (A record)
  |-- admin@example.com (Email)
  |-- www.example.com (Subdomain)
</pre>`,
            commands: {
                "maltego": "Maltego GUI started.",
                "add entity: Domain": "[Graph] Added entity: example.com (Domain)",
                "run transform: To IP Address": "[Graph] example.com\n  |-- 93.184.216.34 (A record)"
            },
            description: 'Graph-based OSINT and link analysis.'
        },
        theharvester: {
            name: 'theHarvester',
            guide: `<h3>theHarvester</h3>
<p><b>What is it?</b><br>theHarvester is an OSINT tool for gathering emails, subdomains, hosts, employee names, and open ports from public sources such as search engines and PGP key servers.</p>
<p><b>How does it work?</b><br>theHarvester queries multiple public data sources (Google, Bing, LinkedIn, etc.) for information related to a target domain, then aggregates and displays the results for further analysis.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>theharvester -d example.com -b google</code> - Search Google for emails and subdomains</li>
  <li><code>theharvester -d example.com -b bing</code> - Search Bing for information</li>
</ul>
<p><b>Typical output:</b></p>
<pre>theHarvester v4.2.0
[*] Searching Google for emails, hosts, and subdomains...
[+] Emails found:
  admin@example.com
  support@example.com
[+] Hosts found:
  www.example.com
  mail.example.com
</pre>`,
            commands: {
                "theharvester -d example.com -b google": "theHarvester v4.2.0\n[*] Searching Google for emails, hosts, and subdomains...\n[+] Emails found:\n  admin@example.com\n  support@example.com\n[+] Hosts found:\n  www.example.com\n  mail.example.com",
                "theharvester -d example.com -b bing": "theHarvester v4.2.0\n[*] Searching Bing for emails, hosts, and subdomains...\n[+] Emails found:\n  info@example.com\n[+] Hosts found:\n  blog.example.com"
            },
            description: 'Email, subdomain, and host OSINT.'
        },
        shodan: {
            name: 'Shodan',
            guide: `<h3>Shodan</h3>
<p><b>What is it?</b><br>Shodan is a search engine for Internet-connected devices. It allows users to discover devices, servers, webcams, routers, and more, exposed to the public internet.</p>
<p><b>How does it work?</b><br>Shodan continuously scans the internet and indexes banners and metadata from devices and services. Users can search for devices by IP, port, service, or vulnerability, and analyze their exposure.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>shodan search apache</code> - Find devices running Apache HTTP Server</li>
  <li><code>shodan host 8.8.8.8</code> - Get details about a specific IP</li>
</ul>
<p><b>Typical output:</b></p>
<pre>Results for search: apache
[1] 203.0.113.10:80 - Apache httpd 2.4.29 (Ubuntu)
[2] 198.51.100.5:8080 - Apache Tomcat 9.0.31

Host details for 8.8.8.8:
  Organization: Google LLC
  Operating System: Linux
  Open Ports: 53/tcp, 443/tcp
</pre>`,
            commands: {
                "shodan search apache": "Results for search: apache\n[1] 203.0.113.10:80 - Apache httpd 2.4.29 (Ubuntu)\n[2] 198.51.100.5:8080 - Apache Tomcat 9.0.31",
                "shodan host 8.8.8.8": "Host details for 8.8.8.8:\n  Organization: Google LLC\n  Operating System: Linux\n  Open Ports: 53/tcp, 443/tcp"
            },
            description: 'Internet device search engine.'
        },
        spiderfoot: {
            name: 'SpiderFoot',
            guide: `<h3>SpiderFoot</h3>
<p><b>What is it?</b><br>SpiderFoot is an open-source automation tool for gathering intelligence on IPs, domains, emails, and more. It is used for threat intelligence, reconnaissance, and attack surface mapping.</p>
<p><b>How does it work?</b><br>SpiderFoot automates OSINT by querying dozens of public data sources and correlating the results. It can be run via a web UI or command line, and supports custom scan profiles.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>spiderfoot -s example.com</code> - Start a scan for a domain</li>
  <li><code>spiderfoot -s 8.8.8.8</code> - Scan an IP address</li>
</ul>
<p><b>Typical output:</b></p>
<pre>SpiderFoot v4.0
[*] Starting scan of example.com...
[+] Found 3 emails: admin@example.com, info@example.com, abuse@example.com
[+] Found 2 subdomains: mail.example.com, vpn.example.com
</pre>`,
            commands: {
                "spiderfoot -s example.com": "SpiderFoot v4.0\n[*] Starting scan of example.com...\n[+] Found 3 emails: admin@example.com, info@example.com, abuse@example.com\n[+] Found 2 subdomains: mail.example.com, vpn.example.com",
                "spiderfoot -s 8.8.8.8": "SpiderFoot v4.0\n[*] Starting scan of 8.8.8.8...\n[+] Found 1 ASN: AS15169 (Google LLC)"
            },
            description: 'Automated OSINT and threat intelligence.'
        },
        foca: {
            name: 'FOCA',
            guide: `<h3>FOCA</h3>
<p><b>What is it?</b><br>FOCA (Fingerprinting Organizations with Collected Archives) is a tool for discovering metadata and hidden information in documents. It is used for information gathering and reconnaissance, especially for extracting sensitive data from public files.</p>
<p><b>How does it work?</b><br>FOCA scans websites for downloadable documents (PDF, DOCX, XLSX, etc.), downloads them, and extracts metadata such as usernames, software versions, file paths, and more. This information can reveal internal network details and potential attack vectors.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>foca scan http://example.com/docs</code> - Scan a website for documents and extract metadata</li>
  <li><code>foca analyze report.pdf</code> - Analyze a specific document for metadata</li>
</ul>
<p><b>Typical output:</b></p>
<pre>Scanning http://example.com/docs...
[+] Found: annual_report.pdf
[+] Extracted metadata:
  Author: John Doe
  Company: Example Corp
  Software: Microsoft Word 2019
  File Path: C:\\Users\\jdoe\\Documents\\annual_report.pdf
</pre>`,
            commands: {
                "foca scan http://example.com/docs": "Scanning http://example.com/docs...\n[+] Found: annual_report.pdf\n[+] Extracted metadata:\n  Author: John Doe\n  Company: Example Corp\n  Software: Microsoft Word 2019\n  File Path: C:\\Users\\jdoe\\Documents\\annual_report.pdf",
                "foca analyze report.pdf": "Analyzing report.pdf...\n[+] Author: Jane Smith\n[+] Created: 2023-05-01\n[+] Last Modified: 2023-05-10"
            },
            description: 'Document metadata extraction and analysis.'
        },
        nessus: {
            name: 'Nessus',
            guide: `<h3>Nessus</h3>
<p><b>What is it?</b><br>Nessus is a widely used vulnerability scanner for identifying security issues, misconfigurations, and missing patches across a wide range of systems and applications.</p>
<p><b>How does it work?</b><br>Nessus scans target systems using a regularly updated plugin database to detect known vulnerabilities, weak configurations, and compliance issues. It provides detailed reports and remediation guidance.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>nessus scan 192.168.1.0/24</code> - Scan a subnet for vulnerabilities</li>
  <li><code>nessus report 192.168.1.10</code> - Generate a report for a specific host</li>
</ul>
<p><b>Typical output:</b></p>
<pre>Starting Nessus scan of 192.168.1.0/24...
[+] 192.168.1.10 - 3 vulnerabilities found
[+] 192.168.1.15 - 1 vulnerability found

Report for 192.168.1.10:
  - CVE-2022-1234: Critical
  - CVE-2021-5678: Medium
  - CVE-2020-9999: Low
</pre>`,
            commands: {
                "nessus scan 192.168.1.0/24": "Starting Nessus scan of 192.168.1.0/24...\n[+] 192.168.1.10 - 3 vulnerabilities found\n[+] 192.168.1.15 - 1 vulnerability found",
                "nessus report 192.168.1.10": "Report for 192.168.1.10:\n  - CVE-2022-1234: Critical\n  - CVE-2021-5678: Medium\n  - CVE-2020-9999: Low"
            },
            description: 'Comprehensive vulnerability scanning.'
        },
        openvas: {
            name: 'OpenVAS',
            guide: `<h3>OpenVAS</h3>
<p><b>What is it?</b><br>OpenVAS (Open Vulnerability Assessment System) is an open-source framework for scanning and managing vulnerabilities in networks and systems.</p>
<p><b>How does it work?</b><br>OpenVAS uses a regularly updated feed of Network Vulnerability Tests (NVTs) to scan targets for known vulnerabilities, weak configurations, and missing patches. It provides detailed scan results and risk ratings.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>openvas scan 10.0.0.0/24</code> - Scan a local network for vulnerabilities</li>
  <li><code>openvas report 10.0.0.5</code> - Generate a vulnerability report for a host</li>
</ul>
<p><b>Typical output:</b></p>
<pre>OpenVAS scan started for 10.0.0.0/24...
[+] 10.0.0.5 - 2 vulnerabilities found
[+] 10.0.0.8 - 0 vulnerabilities found

Report for 10.0.0.5:
  - SSH Weak Key Exchange: High
  - Outdated Apache: Medium
</pre>`,
            commands: {
                "openvas scan 10.0.0.0/24": "OpenVAS scan started for 10.0.0.0/24...\n[+] 10.0.0.5 - 2 vulnerabilities found\n[+] 10.0.0.8 - 0 vulnerabilities found",
                "openvas report 10.0.0.5": "Report for 10.0.0.5:\n  - SSH Weak Key Exchange: High\n  - Outdated Apache: Medium"
            },
            description: 'Open-source vulnerability assessment.'
        },
        metasploit: {
            name: 'Metasploit Framework',
            guide: `<h3>Metasploit Framework</h3>
<p><b>What is it?</b><br>The Metasploit Framework is a powerful open-source platform for developing, testing, and executing exploits. It is widely used for penetration testing and vulnerability research.</p>
<p><b>How does it work?</b><br>Metasploit provides a modular structure for exploits, payloads, and auxiliary modules. You can search for vulnerabilities, select exploits, set payloads, and launch attacks against targets. It also includes post-exploitation and reporting features.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>msfconsole</code> - Start the Metasploit console</li>
  <li><code>search exploit/windows/smb/ms17_010_eternalblue</code> - Search for a specific exploit</li>
  <li><code>use exploit/windows/smb/ms17_010_eternalblue</code> - Load the EternalBlue exploit module</li>
  <li><code>set RHOSTS 192.168.1.20</code> - Set the target host</li>
  <li><code>run</code> - Launch the exploit</li>
</ul>
<p><b>Typical output:</b></p>
<pre>msf5 > search exploit/windows/smb/ms17_010_eternalblue
[+] Found exploit/windows/smb/ms17_010_eternalblue
msf5 > use exploit/windows/smb/ms17_010_eternalblue
msf5 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 192.168.1.20
RHOSTS => 192.168.1.20
msf5 exploit(windows/smb/ms17_010_eternalblue) > run
[*] Exploit completed, session 1 opened
</pre>`,
            commands: {
                "msfconsole": "msf5 > ",
                "search exploit/windows/smb/ms17_010_eternalblue": "msf5 > search exploit/windows/smb/ms17_010_eternalblue\n[+] Found exploit/windows/smb/ms17_010_eternalblue",
                "use exploit/windows/smb/ms17_010_eternalblue": "msf5 exploit(windows/smb/ms17_010_eternalblue) > ",
                "set RHOSTS 192.168.1.20": "RHOSTS => 192.168.1.20",
                "run": "[*] Exploit completed, session 1 opened"
            },
            description: 'Exploit development and penetration testing.'
        },
        'cobalt-strike': {
            name: 'Cobalt Strike',
            guide: `<h3>Cobalt Strike</h3>
<p><b>What is it?</b><br>Cobalt Strike is a commercial threat emulation and post-exploitation tool used for red teaming and adversary simulations.</p>
<p><b>How does it work?</b><br>Cobalt Strike provides a team server and client interface for managing beacons (malware implants), simulating advanced attacks, and controlling compromised systems. It supports social engineering, lateral movement, and post-exploitation modules.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>cs connect teamserver 192.168.1.100</code> - Connect to a Cobalt Strike team server</li>
  <li><code>cs launch beacon 192.168.1.101</code> - Launch a beacon on a target</li>
</ul>
<p><b>Typical output:</b></p>
<pre>Connecting to teamserver at 192.168.1.100...
[+] Connected as operator
Launching beacon to 192.168.1.101...
[+] Beacon launched and active
</pre>`,
            commands: {
                "cs connect teamserver 192.168.1.100": "Connecting to teamserver at 192.168.1.100...\n[+] Connected as operator",
                "cs launch beacon 192.168.1.101": "Launching beacon to 192.168.1.101...\n[+] Beacon launched and active"
            },
            description: 'Threat emulation and post-exploitation.'
        },
        empire: {
            name: 'Empire',
            guide: `<h3>Empire</h3>
<p><b>What is it?</b><br>Empire is a post-exploitation and adversary emulation framework that uses PowerShell and Python agents. It is designed for red teaming, penetration testing, and simulating advanced persistent threats (APTs).</p>
<p><b>How does it work?</b><br>Empire allows operators to generate agents, establish command and control (C2) channels, and execute post-exploitation modules on compromised systems. It supports fileless attacks, credential harvesting, lateral movement, and more.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>empire</code> - Start the Empire console</li>
  <li><code>listeners</code> - List available listeners (C2 channels)</li>
  <li><code>agents</code> - List active agents</li>
  <li><code>interact AGENT1</code> - Interact with a specific agent</li>
  <li><code>usemodule credentials/mimikatz/logonpasswords</code> - Run Mimikatz on the target</li>
</ul>
<p><b>Typical output:</b></p>
<pre>(Empire) > listeners
[+] http listener started on 0.0.0.0:8080
(Empire) > agents
[+] AGENT1 - 192.168.1.50 - Windows 10
(Empire) > interact AGENT1
(Empire:AGENT1) > usemodule credentials/mimikatz/logonpasswords
[+] Dumped credentials:
  User: Administrator
  Password: Passw0rd!
</pre>`,
            commands: {
                "empire": "(Empire) > ",
                "listeners": "(Empire) > listeners\n[+] http listener started on 0.0.0.0:8080",
                "agents": "(Empire) > agents\n[+] AGENT1 - 192.168.1.50 - Windows 10",
                "interact AGENT1": "(Empire:AGENT1) > ",
                "usemodule credentials/mimikatz/logonpasswords": "[+] Dumped credentials:\n  User: Administrator\n  Password: Passw0rd!"
            },
            description: 'Post-exploitation and adversary emulation.'
        },
        sqlmap: {
            name: 'SQLmap',
            guide: `<h3>SQLmap</h3>
<p><b>What is it?</b><br>SQLmap is an open-source tool that automates the process of detecting and exploiting SQL injection vulnerabilities in web applications.</p>
<p><b>How does it work?</b><br>SQLmap tests web applications by sending crafted requests to parameters and analyzing responses for SQL injection flaws. It can enumerate databases, extract data, and even gain shell access if possible.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>sqlmap -u http://example.com/page.php?id=1 --dbs</code> - List databases on the target</li>
  <li><code>sqlmap -u http://example.com/page.php?id=1 -D testdb --tables</code> - List tables in a database</li>
  <li><code>sqlmap -u http://example.com/page.php?id=1 -D testdb -T users --dump</code> - Dump data from a table</li>
</ul>
<p><b>Typical output:</b></p>
<pre>[*] Testing connection to the target URL...
[+] The parameter 'id' appears to be injectable!
[+] Available databases:
  - information_schema
  - testdb
[+] Tables in testdb:
  - users
  - logins
[+] Dumping data from testdb.users:
| id | username | password |
|----|----------|----------|
| 1  | admin    | admin123 |
| 2  | alice    | alicepw  |
</pre>`,
            commands: {
                "sqlmap -u http://example.com/page.php?id=1 --dbs": "[*] Testing connection to the target URL...\n[+] The parameter 'id' appears to be injectable!\n[+] Available databases:\n  - information_schema\n  - testdb",
                "sqlmap -u http://example.com/page.php?id=1 -D testdb --tables": "[+] Tables in testdb:\n  - users\n  - logins",
                "sqlmap -u http://example.com/page.php?id=1 -D testdb -T users --dump": "[+] Dumping data from testdb.users:\n| id | username | password |\n|----|----------|----------|\n| 1  | admin    | admin123 |\n| 2  | alice    | alicepw  |"
            },
            description: 'Automated SQL injection exploitation.'
        },
        'burp-suite': {
            name: 'Burp Suite',
            guide: `<h3>Burp Suite</h3>
<p><b>What is it?</b><br>Burp Suite is a popular integrated platform for web application security testing. It is used for intercepting, modifying, and replaying HTTP/S traffic, as well as scanning for vulnerabilities.</p>
<p><b>How does it work?</b><br>Burp Suite acts as a proxy between your browser and the web server, allowing you to intercept and modify requests and responses. It includes tools for scanning, spidering, and attacking web applications.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>burp</code> - Launch the Burp Suite GUI</li>
  <li><code>burp scan http://example.com</code> - Scan a website for vulnerabilities</li>
  <li><code>burp repeater</code> - Open the Repeater tool for manual request manipulation</li>
</ul>
<p><b>Typical output:</b></p>
<pre>Burp Suite started.
[Scanner] Scanning http://example.com...
[+] Vulnerability found: Reflected XSS in /search
[Repeater] Ready for manual requests
</pre>`,
            commands: {
                "burp": "Burp Suite started.",
                "burp scan http://example.com": "[Scanner] Scanning http://example.com...\n[+] Vulnerability found: Reflected XSS in /search",
                "burp repeater": "[Repeater] Ready for manual requests"
            },
            description: 'Web application security testing platform.'
        },
        'owasp-zap': {
            name: 'OWASP ZAP',
            guide: `<h3>OWASP ZAP</h3>
<p><b>What is it?</b><br>OWASP ZAP (Zed Attack Proxy) is an open-source web application security scanner. It is designed for finding vulnerabilities in web applications during development and testing.</p>
<p><b>How does it work?</b><br>ZAP acts as a proxy and scanner for web applications, intercepting and modifying HTTP/S traffic. It can perform automated scans, spider sites, and provide detailed vulnerability reports.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>zap</code> - Launch the ZAP GUI</li>
  <li><code>zap scan http://example.com</code> - Scan a website for vulnerabilities</li>
  <li><code>zap spider http://example.com</code> - Spider a website to discover all links</li>
</ul>
<p><b>Typical output:</b></p>
<pre>OWASP ZAP started.
[Scanner] Scanning http://example.com...
[+] Vulnerability found: SQL Injection in /login
[Spider] Crawled 25 URLs
</pre>`,
            commands: {
                "zap": "OWASP ZAP started.",
                "zap scan http://example.com": "[Scanner] Scanning http://example.com...\n[+] Vulnerability found: SQL Injection in /login",
                "zap spider http://example.com": "[Spider] Crawled 25 URLs"
            },
            description: 'Open-source web application security scanner.'
        },
        'aircrack-ng': {
            name: 'Aircrack-ng',
            guide: `<h3>Aircrack-ng</h3>
<p><b>What is it?</b><br>Aircrack-ng is a suite of tools for auditing and cracking Wi-Fi networks. It is used for monitoring, attacking, testing, and cracking WEP and WPA-PSK keys.</p>
<p><b>How does it work?</b><br>Aircrack-ng captures wireless packets, analyzes them for weak encryption, and attempts to recover keys using dictionary or brute-force attacks. It includes tools for packet capture, deauthentication, and key cracking.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>airmon-ng start wlan0</code> - Enable monitor mode on a wireless interface</li>
  <li><code>airodump-ng wlan0mon</code> - Capture packets from nearby networks</li>
  <li><code>aircrack-ng -w wordlist.txt -b 00:11:22:33:44:55 capture.cap</code> - Crack a WPA handshake</li>
</ul>
<p><b>Typical output:</b></p>
<pre>Interface wlan0 set to monitor mode
[airodump-ng] Capturing packets on wlan0mon...
[aircrack-ng] Attempting to crack WPA handshake...
[+] Key found: supersecretkey
</pre>`,
            commands: {
                "airmon-ng start wlan0": "Interface wlan0 set to monitor mode",
                "airodump-ng wlan0mon": "[airodump-ng] Capturing packets on wlan0mon...",
                "aircrack-ng -w wordlist.txt -b 00:11:22:33:44:55 capture.cap": "[aircrack-ng] Attempting to crack WPA handshake...\n[+] Key found: supersecretkey"
            },
            description: 'Wi-Fi auditing and key cracking suite.'
        },
        wireshark: {
            name: 'Wireshark',
            guide: `<h3>Wireshark</h3>
<p><b>What is it?</b><br>Wireshark is a widely used open-source network protocol analyzer. It allows users to capture and interactively browse the traffic running on a computer network in real time.</p>
<p><b>How does it work?</b><br>Wireshark captures packets from network interfaces and decodes them, displaying protocol details and payloads. It supports hundreds of protocols and provides powerful filtering and search capabilities for network troubleshooting and security analysis.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>wireshark</code> - Launch the Wireshark GUI</li>
  <li><code>wireshark -r capture.pcap</code> - Open and analyze a saved packet capture file</li>
</ul>
<p><b>Typical output:</b></p>
<pre>Wireshark GUI started.
[Capture] 10,000 packets loaded from capture.pcap
[Analysis] Detected suspicious HTTP POST to 192.168.1.100
</pre>`,
            commands: {
                "wireshark": "Wireshark GUI started.",
                "wireshark -r capture.pcap": "[Capture] 10,000 packets loaded from capture.pcap\n[Analysis] Detected suspicious HTTP POST to 192.168.1.100"
            },
            description: 'Network protocol analysis and packet capture.'
        },
        ettercap: {
            name: 'Ettercap',
            guide: `<h3>Ettercap</h3>
<p><b>What is it?</b><br>Ettercap is a comprehensive suite for man-in-the-middle (MITM) attacks on local area networks. It supports active and passive dissection of many protocols and includes features for network and host analysis.</p>
<p><b>How does it work?</b><br>Ettercap can intercept, log, and manipulate network traffic in real time. It supports ARP poisoning, DNS spoofing, and credential harvesting, making it a powerful tool for penetration testers and attackers.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>ettercap -T -q -i eth0</code> - Run Ettercap in text mode, quietly, on interface eth0</li>
  <li><code>ettercap -G</code> - Launch the Ettercap GUI</li>
</ul>
<p><b>Typical output:</b></p>
<pre>Ettercap started in text mode on eth0
[+] ARP poisoning enabled
[+] Captured credentials: user:admin pass:password123
</pre>`,
            commands: {
                "ettercap -T -q -i eth0": "Ettercap started in text mode on eth0\n[+] ARP poisoning enabled\n[+] Captured credentials: user:admin pass:password123",
                "ettercap -G": "Ettercap GUI started."
            },
            description: 'Man-in-the-middle attacks and network sniffing.'
        },
        responder: {
            name: 'Responder',
            guide: `<h3>Responder</h3>
<p><b>What is it?</b><br>Responder is a tool for poisoning LLMNR, NBT-NS, and MDNS protocols to capture network credentials and hashes on local networks.</p>
<p><b>How does it work?</b><br>Responder listens for broadcast name resolution requests and responds with its own address, tricking clients into sending authentication data. It can capture NTLMv1/v2 hashes and relay attacks for further exploitation.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>responder -I eth0</code> - Start Responder on interface eth0</li>
  <li><code>responder -w -I eth0</code> - Enable WPAD rogue proxy server</li>
</ul>
<p><b>Typical output:</b></p>
<pre>Responder started on eth0
[+] Listening for LLMNR/NBT-NS/MDNS requests
[+] Captured NTLMv2 hash from 192.168.1.101: user:alice hash:112233445566...
</pre>`,
            commands: {
                "responder -I eth0": "Responder started on eth0\n[+] Listening for LLMNR/NBT-NS/MDNS requests",
                "responder -w -I eth0": "Responder started on eth0 with WPAD rogue proxy\n[+] Captured NTLMv2 hash from 192.168.1.101: user:alice hash:112233445566..."
            },
            description: 'Network poisoning and credential capture.'
        },
        hydra: {
            name: 'Hydra',
            guide: `<h3>Hydra</h3>
<p><b>What is it?</b><br>Hydra is a fast and flexible password-cracking tool that supports numerous protocols for online brute-force attacks.</p>
<p><b>How does it work?</b><br>Hydra attempts to log in to a service (SSH, FTP, HTTP, etc.) using a list of usernames and passwords, reporting successful logins. It supports parallelized attacks and custom modules.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>hydra -l admin -P passwords.txt ssh://192.168.1.10</code> - Brute-force SSH login</li>
  <li><code>hydra -L users.txt -P passwords.txt ftp://192.168.1.20</code> - Brute-force FTP login with user list</li>
</ul>
<p><b>Typical output:</b></p>
<pre>[22][ssh] host: 192.168.1.10   login: admin   password: letmein
[21][ftp] host: 192.168.1.20   login: alice   password: qwerty123
</pre>`,
            commands: {
                "hydra -l admin -P passwords.txt ssh://192.168.1.10": "[22][ssh] host: 192.168.1.10   login: admin   password: letmein",
                "hydra -L users.txt -P passwords.txt ftp://192.168.1.20": "[21][ftp] host: 192.168.1.20   login: alice   password: qwerty123"
            },
            description: 'Parallelized password brute-forcing.'
        },
        john: {
            name: 'John the Ripper',
            guide: `<h3>John the Ripper</h3>
<p><b>What is it?</b><br>John the Ripper is a popular password-cracking tool that supports a wide range of hash types and cracking modes.</p>
<p><b>How does it work?</b><br>John the Ripper takes password hashes and attempts to recover plaintext passwords using dictionary, brute-force, and rule-based attacks. It is highly configurable and efficient.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>john --wordlist=rockyou.txt hashes.txt</code> - Crack hashes using a wordlist</li>
  <li><code>john --show hashes.txt</code> - Show cracked passwords</li>
</ul>
<p><b>Typical output:</b></p>
<pre>Loaded 2 password hashes
admin:password123
alice:qwerty
</pre>`,
            commands: {
                "john --wordlist=rockyou.txt hashes.txt": "Loaded 2 password hashes\nadmin:password123\nalice:qwerty",
                "john --show hashes.txt": "admin:password123\nalice:qwerty"
            },
            description: 'Password hash cracking.'
        },
        hashcat: {
            name: 'Hashcat',
            guide: `<h3>Hashcat</h3>
<p><b>What is it?</b><br>Hashcat is an advanced password recovery tool that uses GPU acceleration to crack hashes quickly.</p>
<p><b>How does it work?</b><br>Hashcat supports a wide range of hash algorithms and attack modes, including dictionary, brute-force, combinator, and mask attacks. It leverages GPU power for high-speed cracking.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>hashcat -m 0 -a 0 hashes.txt rockyou.txt</code> - Crack MD5 hashes using a wordlist</li>
  <li><code>hashcat -m 1000 -a 3 ntlm.txt ?a?a?a?a?a?a</code> - Brute-force NTLM hashes with a mask</li>
</ul>
<p><b>Typical output:</b></p>
<pre>hashcat (v6.2.5) starting...
[+] hashes.txt:admin:21232f297a57a5a743894a0e4a801fc3 -> admin:admin
[+] hashes.txt:alice:25d55ad283aa400af464c76d713c07ad -> alice:12345678
</pre>`,
            commands: {
                "hashcat -m 0 -a 0 hashes.txt rockyou.txt": "hashcat (v6.2.5) starting...\n[+] hashes.txt:admin:21232f297a57a5a743894a0e4a801fc3 -> admin:admin\n[+] hashes.txt:alice:25d55ad283aa400af464c76d713c07ad -> alice:12345678",
                "hashcat -m 1000 -a 3 ntlm.txt ?a?a?a?a?a?a": "hashcat (v6.2.5) starting...\n[+] ntlm.txt:alice:32ed87bdb5fdc5e9cba88547376818d4 -> alice:secret1"
            },
            description: 'GPU-accelerated password cracking.'
        },
        xsstrike: {
            name: 'XSStrike',
            guide: `<h3>XSStrike</h3>
<p><b>What is it?</b><br>XSStrike is an advanced XSS (Cross-Site Scripting) detection suite. It is designed to identify and exploit XSS vulnerabilities in web applications.</p>
<p><b>How does it work?</b><br>XSStrike crawls web applications, analyzes parameters, and uses intelligent payloads to detect and exploit XSS vulnerabilities. It can generate proof-of-concept exploits and bypass common filters.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>xsstrike -u http://example.com/search?q=1</code> - Scan a URL for XSS vulnerabilities</li>
  <li><code>xsstrike -u http://example.com -l</code> - List all parameters and scan each for XSS</li>
</ul>
<p><b>Typical output:</b></p>
<pre>Scanning http://example.com/search?q=1...
[+] Reflected XSS found in parameter 'q'
[Payload] <script>alert(1)</script>
</pre>`,
            commands: {
                "xsstrike -u http://example.com/search?q=1": "Scanning http://example.com/search?q=1...\n[+] Reflected XSS found in parameter 'q'\n[Payload] <script>alert(1)</script>",
                "xsstrike -u http://example.com -l": "Listing parameters...\nScanning parameter 'id'...\nNo XSS found.\nScanning parameter 'q'...\n[+] Reflected XSS found!"
            },
            description: 'Advanced XSS detection and exploitation.'
        },
        commix: {
            name: 'Commix',
            guide: `<h3>Commix</h3>
<p><b>What is it?</b><br>Commix (Command Injection Exploiter) is an automated tool for detecting and exploiting command injection vulnerabilities in web applications.</p>
<p><b>How does it work?</b><br>Commix sends crafted payloads to web application parameters and analyzes responses to determine if arbitrary commands can be executed on the server. It supports various injection techniques and bypasses.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>commix --url="http://example.com/vuln.php?id=1"</code> - Test a URL for command injection</li>
  <li><code>commix --url="http://example.com" --os-cmd="id"</code> - Execute the 'id' command on the server</li>
</ul>
<p><b>Typical output:</b></p>
<pre>Testing http://example.com/vuln.php?id=1...
[+] Command injection vulnerability found!
[+] Result of 'id':
uid=33(www-data) gid=33(www-data) groups=33(www-data)
</pre>`,
            commands: {
                "commix --url=\"http://example.com/vuln.php?id=1\"": "Testing http://example.com/vuln.php?id=1...\n[+] Command injection vulnerability found!",
                "commix --url=\"http://example.com\" --os-cmd=\"id\"": "[+] Result of 'id':\nuid=33(www-data) gid=33(www-data) groups=33(www-data)"
            },
            description: 'Automated command injection exploitation.'
        },
        wpscan: {
            name: 'WPScan',
            guide: `<h3>WPScan</h3>
<p><b>What is it?</b><br>WPScan is a WordPress vulnerability scanner. It is used to find security issues, weak passwords, and outdated plugins/themes in WordPress sites.</p>
<p><b>How does it work?</b><br>WPScan enumerates users, plugins, and themes, checks for known vulnerabilities, and attempts brute-force attacks on login pages. It uses a regularly updated vulnerability database.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>wpscan --url http://example.com</code> - Scan a WordPress site for vulnerabilities</li>
  <li><code>wpscan --url http://example.com --enumerate u</code> - Enumerate users</li>
</ul>
<p><b>Typical output:</b></p>
<pre>Scanning http://example.com...
[+] WordPress version: 5.8.1
[+] Found 2 vulnerable plugins: contact-form-7, revslider
[+] Users found: admin, alice
</pre>`,
            commands: {
                "wpscan --url http://example.com": "Scanning http://example.com...\n[+] WordPress version: 5.8.1\n[+] Found 2 vulnerable plugins: contact-form-7, revslider",
                "wpscan --url http://example.com --enumerate u": "[+] Users found: admin, alice"
            },
            description: 'WordPress vulnerability scanning.'
        },
        dirbuster: {
            name: 'DirBuster/Dirsearch',
            guide: `<h3>DirBuster/Dirsearch</h3>
<p><b>What is it?</b><br>DirBuster and Dirsearch are tools for brute-forcing directories and files on web servers to discover hidden content.</p>
<p><b>How does it work?</b><br>These tools use wordlists to send requests for common directory and file names, analyzing responses to find accessible resources. They help uncover admin panels, backups, and sensitive files.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>dirbuster -u http://example.com</code> - Start a directory brute-force scan</li>
  <li><code>dirsearch -u http://example.com -e php,txt</code> - Scan for PHP and TXT files</li>
</ul>
<p><b>Typical output:</b></p>
<pre>Starting scan on http://example.com...
[+] Found: /admin/
[+] Found: /backup.zip
[+] Found: /index.php
</pre>`,
            commands: {
                "dirbuster -u http://example.com": "Starting scan on http://example.com...\n[+] Found: /admin/\n[+] Found: /backup.zip\n[+] Found: /index.php",
                "dirsearch -u http://example.com -e php,txt": "[+] Found: /config.php\n[+] Found: /readme.txt"
            },
            description: 'Directory and file brute-forcing.'
        },
        mimikatz: {
            name: 'Mimikatz',
            guide: `<h3>Mimikatz</h3>
<p><b>What is it?</b><br>Mimikatz is a tool for extracting plaintext passwords, hashes, PIN codes, and Kerberos tickets from memory on Windows systems.</p>
<p><b>How does it work?</b><br>Mimikatz interacts with Windows security subsystems to dump credentials from memory, perform pass-the-hash, and manipulate Kerberos tickets. It is widely used for post-exploitation and privilege escalation.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>mimikatz</code> - Start the Mimikatz interactive shell</li>
  <li><code>privilege::debug</code> - Enable debug privileges</li>
  <li><code>sekurlsa::logonpasswords</code> - Dump logon credentials</li>
</ul>
<p><b>Typical output:</b></p>
<pre>mimikatz 2.2.0 (x64)
Privilege '20' enabled
Authentication Id : 0 ; 123456 (00000000:0001e240)
User Name : Administrator
Domain   : EXAMPLE
Password : Passw0rd!
</pre>`,
            commands: {
                "mimikatz": "mimikatz 2.2.0 (x64)",
                "privilege::debug": "Privilege '20' enabled",
                "sekurlsa::logonpasswords": "Authentication Id : 0 ; 123456 (00000000:0001e240)\nUser Name : Administrator\nDomain   : EXAMPLE\nPassword : Passw0rd!"
            },
            description: 'Credential extraction and privilege escalation.'
        },
        bloodhound: {
            name: 'BloodHound',
            guide: `<h3>BloodHound</h3>
<p><b>What is it?</b><br>BloodHound is a tool for analyzing Active Directory (AD) trust relationships and privilege escalation paths.</p>
<p><b>How does it work?</b><br>BloodHound collects data from AD environments using ingestors, then visualizes relationships and attack paths in a graph database. It helps identify privilege escalation and lateral movement opportunities.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>bloodhound</code> - Launch the BloodHound GUI</li>
  <li><code>SharpHound.exe -c All</code> - Collect data from an AD environment</li>
</ul>
<p><b>Typical output:</b></p>
<pre>BloodHound GUI started.
[SharpHound] Collected 10,000 objects from AD
[Graph] Found shortest path from user1 to Domain Admins
</pre>`,
            commands: {
                "bloodhound": "BloodHound GUI started.",
                "SharpHound.exe -c All": "[SharpHound] Collected 10,000 objects from AD\n[Graph] Found shortest path from user1 to Domain Admins"
            },
            description: 'Active Directory attack path analysis.'
        },
        powersploit: {
            name: 'PowerSploit',
            guide: `<h3>PowerSploit</h3>
<p><b>What is it?</b><br>PowerSploit is a collection of Microsoft PowerShell modules for post-exploitation, offensive security, and red teaming.</p>
<p><b>How does it work?</b><br>PowerSploit provides scripts for code execution, credential harvesting, persistence, and more. It is used to automate post-exploitation tasks on Windows systems.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>powershell -ep bypass -File Invoke-Mimikatz.ps1</code> - Run Mimikatz via PowerSploit</li>
  <li><code>powershell -ep bypass -File Get-GPPPassword.ps1</code> - Extract Group Policy Preferences passwords</li>
</ul>
<p><b>Typical output:</b></p>
<pre>Running Invoke-Mimikatz.ps1...
[+] Credentials dumped: Administrator / Passw0rd!
Running Get-GPPPassword.ps1...
[+] Found password: GPPPassword123
</pre>`,
            commands: {
                "powershell -ep bypass -File Invoke-Mimikatz.ps1": "Running Invoke-Mimikatz.ps1...\n[+] Credentials dumped: Administrator / Passw0rd!",
                "powershell -ep bypass -File Get-GPPPassword.ps1": "Running Get-GPPPassword.ps1...\n[+] Found password: GPPPassword123"
            },
            description: 'PowerShell post-exploitation modules.'
        },
        set: {
            name: 'SET (Social Engineering Toolkit)',
            guide: `<h3>SET (Social Engineering Toolkit)</h3>
<p><b>What is it?</b><br>SET is an open-source penetration testing framework for social engineering attacks, including phishing, credential harvesting, and more.</p>
<p><b>How does it work?</b><br>SET provides a menu-driven interface to automate the creation and delivery of social engineering attacks. It supports spear phishing, website cloning, and payload generation.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>setoolkit</code> - Launch the SET interactive menu</li>
  <li><code>1</code> - Social-Engineering Attacks</li>
  <li><code>2</code> - Website Attack Vectors</li>
</ul>
<p><b>Typical output:</b></p>
<pre>SET v8.0.3
[Menu] 1) Social-Engineering Attacks
[Menu] 2) Website Attack Vectors
[Menu] 99) Exit
</pre>`,
            commands: {
                "setoolkit": "SET v8.0.3\n[Menu] 1) Social-Engineering Attacks\n[Menu] 2) Website Attack Vectors\n[Menu] 99) Exit",
                "1": "[Menu] 1) Social-Engineering Attacks",
                "2": "[Menu] 2) Website Attack Vectors"
            },
            description: 'Social engineering attack automation.'
        },
        beef: {
            name: 'BeEF',
            guide: `<h3>BeEF (Browser Exploitation Framework)</h3>
<p><b>What is it?</b><br>BeEF is a penetration testing tool that focuses on the web browser. It allows security professionals to assess the security posture of a target environment by using client-side attack vectors.</p>
<p><b>How does it work?</b><br>BeEF hooks browsers via a JavaScript payload. Once hooked, the browser can be controlled and used to launch further attacks, such as stealing credentials, exploiting vulnerabilities, or pivoting deeper into the network.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>beef</code> - Start the BeEF server and web UI</li>
  <li><code>hook.js</code> - Inject the BeEF hook into a target browser</li>
</ul>
<p><b>Typical output:</b></p>
<pre>BeEF server started at http://127.0.0.1:3000/ui/panel
[+] New browser hooked: 192.168.1.101 (Chrome)
</pre>`,
            commands: {
                "beef": "BeEF server started at http://127.0.0.1:3000/ui/panel",
                "hook.js": "[+] New browser hooked: 192.168.1.101 (Chrome)"
            },
            description: 'Browser exploitation and client-side attacks.'
        },
        gophish: {
            name: 'Gophish',
            guide: `<h3>Gophish</h3>
<p><b>What is it?</b><br>Gophish is an open-source phishing framework designed for businesses and penetration testers to conduct real-world phishing campaigns.</p>
<p><b>How does it work?</b><br>Gophish provides a web interface to create, launch, and track phishing campaigns. It automates email delivery, landing page hosting, and results tracking.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>gophish</code> - Start the Gophish server and web UI</li>
  <li><code>gophish campaign create</code> - Create a new phishing campaign</li>
</ul>
<p><b>Typical output:</b></p>
<pre>Gophish server started at http://127.0.0.1:3333
[+] Campaign created: "Q2 Security Awareness"
</pre>`,
            commands: {
                "gophish": "Gophish server started at http://127.0.0.1:3333",
                "gophish campaign create": "[+] Campaign created: \"Q2 Security Awareness\""
            },
            description: 'Phishing campaign automation and tracking.'
        },
        'king-phisher': {
            name: 'King Phisher',
            guide: `<h3>King Phisher</h3>
<p><b>What is it?</b><br>King Phisher is a tool for testing and promoting user awareness by simulating real-world phishing attacks.</p>
<p><b>How does it work?</b><br>King Phisher allows you to create and manage phishing campaigns, track email opens, credential submissions, and more, all from a user-friendly interface.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>king-phisher</code> - Start the King Phisher server and client</li>
  <li><code>king-phisher campaign create</code> - Create a new phishing campaign</li>
</ul>
<p><b>Typical output:</b></p>
<pre>King Phisher server started at http://127.0.0.1:8080
[+] Campaign created: "HR Policy Update"
</pre>`,
            commands: {
                "king-phisher": "King Phisher server started at http://127.0.0.1:8080",
                "king-phisher campaign create": "[+] Campaign created: \"HR Policy Update\""
            },
            description: 'Phishing simulation and user awareness.'
        },
        'thc-hydra': {
            name: 'THC-Hydra',
            guide: `<h3>THC-Hydra</h3>
<p><b>What is it?</b><br>THC-Hydra is a fast and flexible network login cracker that supports numerous protocols for online brute-force attacks.</p>
<p><b>How does it work?</b><br>THC-Hydra attempts to log in to a service (SSH, FTP, HTTP, etc.) using a list of usernames and passwords, reporting successful logins. It supports parallelized attacks and custom modules.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>hydra -L users.txt -P passwords.txt ssh://192.168.1.10</code> - Brute-force SSH login with user list</li>
  <li><code>hydra -l admin -P passwords.txt ftp://192.168.1.20</code> - Brute-force FTP login for a single user</li>
</ul>
<p><b>Typical output:</b></p>
<pre>[22][ssh] host: 192.168.1.10   login: alice   password: letmein
[21][ftp] host: 192.168.1.20   login: admin   password: qwerty123
</pre>`,
            commands: {
                "hydra -L users.txt -P passwords.txt ssh://192.168.1.10": "[22][ssh] host: 192.168.1.10   login: alice   password: letmein",
                "hydra -l admin -P passwords.txt ftp://192.168.1.20": "[21][ftp] host: 192.168.1.20   login: admin   password: qwerty123"
            },
            description: 'Parallelized network login brute-forcing.'
        },
        rainbowcrack: {
            name: 'RainbowCrack',
            guide: `<h3>RainbowCrack</h3>
<p><b>What is it?</b><br>RainbowCrack is a tool for password cracking using rainbow tables, which are precomputed tables for reversing cryptographic hash functions.</p>
<p><b>How does it work?</b><br>RainbowCrack uses rainbow tables to look up hash values and recover plaintext passwords much faster than brute-force or dictionary attacks, provided the hash is in the table.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>rainbowcrack hash.txt table.rt</code> - Crack hashes in hash.txt using a rainbow table</li>
</ul>
<p><b>Typical output:</b></p>
<pre>Loaded 1000 hashes from hash.txt
[+] Cracked: 21232f297a57a5a743894a0e4a801fc3 -> admin
[+] Cracked: 25d55ad283aa400af464c76d713c07ad -> alice
</pre>`,
            commands: {
                "rainbowcrack hash.txt table.rt": "Loaded 1000 hashes from hash.txt\n[+] Cracked: 21232f297a57a5a743894a0e4a801fc3 -> admin\n[+] Cracked: 25d55ad283aa400af464c76d713c07ad -> alice"
            },
            description: 'Rainbow table password cracking.'
        },
        mobsf: {
            name: 'MobSF (Mobile Security Framework)',
            guide: `<h3>MobSF (Mobile Security Framework)</h3>
<p><b>What is it?</b><br>MobSF is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis, and security assessment framework.</p>
<p><b>How does it work?</b><br>MobSF can perform static and dynamic analysis of mobile apps, including code review, API analysis, and runtime behavior monitoring. It provides detailed security reports and recommendations.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>mobsf</code> - Start the MobSF server and web UI</li>
  <li><code>mobsf scan app.apk</code> - Scan an Android APK for vulnerabilities</li>
</ul>
<p><b>Typical output:</b></p>
<pre>MobSF server started at http://127.0.0.1:8000
[+] Scan complete: app.apk
[+] Issues found: 3 (Insecure API, Hardcoded Key, Debuggable)
</pre>`,
            commands: {
                "mobsf": "MobSF server started at http://127.0.0.1:8000",
                "mobsf scan app.apk": "[+] Scan complete: app.apk\n[+] Issues found: 3 (Insecure API, Hardcoded Key, Debuggable)"
            },
            description: 'Automated mobile app security testing.'
        },
        frida: {
            name: 'Frida',
            guide: `<h3>Frida</h3>
<p><b>What is it?</b><br>Frida is a dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers to inject scripts into running processes.</p>
<p><b>How does it work?</b><br>Frida allows you to hook into native apps, trace function calls, and modify behavior at runtime. It supports Windows, macOS, Linux, iOS, and Android.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>frida -U -f com.example.app -l script.js --no-pause</code> - Inject a script into an Android app</li>
  <li><code>frida-trace -i open com.example.app</code> - Trace the 'open' function in an app</li>
</ul>
<p><b>Typical output:</b></p>
<pre>Instrumenting com.example.app...
[+] Script injected successfully
[Trace] open("/data/data/com.example.app/file.txt")
</pre>`,
            commands: {
                "frida -U -f com.example.app -l script.js --no-pause": "Instrumenting com.example.app...\n[+] Script injected successfully",
                "frida-trace -i open com.example.app": "[Trace] open(\"/data/data/com.example.app/file.txt\")"
            },
            description: 'Dynamic instrumentation and runtime analysis.'
        },
        apktool: {
            name: 'Apktool',
            guide: `<h3>Apktool</h3>
<p><b>What is it?</b><br>Apktool is a tool for reverse engineering Android APK files, allowing you to decode resources to nearly original form and rebuild them after making modifications.</p>
<p><b>How does it work?</b><br>Apktool disassembles APKs, extracts resources, and allows for modification and reassembly. It is useful for malware analysis, app customization, and security research.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>apktool d app.apk</code> - Disassemble an APK</li>
  <li><code>apktool b app/</code> - Rebuild an APK from modified sources</li>
</ul>
<p><b>Typical output:</b></p>
<pre>Disassembling app.apk...
[+] Resources extracted to app/
Rebuilding app/...
[+] APK rebuilt successfully
</pre>`,
            commands: {
                "apktool d app.apk": "Disassembling app.apk...\n[+] Resources extracted to app/",
                "apktool b app/": "Rebuilding app/...\n[+] APK rebuilt successfully"
            },
            description: 'Android APK reverse engineering and rebuilding.'
        },
        jadx: {
            name: 'Jadx',
            guide: `<h3>Jadx</h3>
<p><b>What is it?</b><br>Jadx is a Dex to Java decompiler that converts Android .dex and .apk files to Java source code for analysis and review.</p>
<p><b>How does it work?</b><br>Jadx decompiles Dalvik bytecode to Java source, making it easier to understand app logic, find vulnerabilities, and audit code.</p>
<p><b>Example usage:</b></p>
<ul>
  <li><code>jadx app.apk</code> - Decompile an APK to Java source</li>
  <li><code>jadx-gui app.apk</code> - Launch the Jadx GUI for interactive analysis</li>
</ul>
<p><b>Typical output:</b></p>
<pre>Decompiling app.apk...
[+] Java source code written to ./app/sources/
Launching Jadx GUI...
[+] GUI ready for analysis
</pre>`,
            commands: {
                "jadx app.apk": "Decompiling app.apk...\n[+] Java source code written to ./app/sources/",
                "jadx-gui app.apk": "Launching Jadx GUI...\n[+] GUI ready for analysis"
            },
            description: 'Android Dex to Java decompilation.'
        }
    };
    // --- END FLAT TOOL LIST ---

    // Organize tools by category based on updated red.txt
    const redCategories = [
        {
            name: 'Reconnaissance & Enumeration',
            tools: {
                nmap: allTools.nmap,
                'recon-ng': allTools['recon-ng'],
                maltego: allTools.maltego,
                theharvester: allTools.theharvester,
                shodan: allTools.shodan,
                spiderfoot: allTools.spiderfoot,
                foca: allTools.foca
            }
        },
        {
            name: 'Vulnerability Scanning & Exploitation',
            tools: {
                nessus: allTools.nessus,
                openvas: allTools.openvas,
                metasploit: allTools.metasploit,
                'cobalt-strike': allTools['cobalt-strike'],
                empire: allTools.empire,
                sqlmap: allTools.sqlmap,
                'burp-suite': allTools['burp-suite'],
                'owasp-zap': allTools['owasp-zap']
            }
        },
        {
            name: 'Network & Wireless Attacks',
            tools: {
                'aircrack-ng': allTools['aircrack-ng'],
                wireshark: allTools.wireshark,
                ettercap: allTools.ettercap,
                responder: allTools.responder,
                hydra: allTools.hydra,
                john: allTools.john,
                hashcat: allTools.hashcat
            }
        },
        {
            name: 'Web Application Attacks',
            tools: {
                'burp-suite': allTools['burp-suite'],
                sqlmap: allTools.sqlmap,
                xsstrike: allTools.xsstrike,
                commix: allTools.commix,
                wpscan: allTools.wpscan,
                dirbuster: allTools.dirbuster
            }
        },
        {
            name: 'Post-Exploitation & Privilege Escalation',
            tools: {
                mimikatz: allTools.mimikatz,
                bloodhound: allTools.bloodhound,
                powersploit: allTools.powersploit,
                empire: allTools.empire
            }
        },
        {
            name: 'Social Engineering & Phishing',
            tools: {
                set: allTools.set,
                beef: allTools.beef,
                gophish: allTools.gophish,
                'king-phisher': allTools['king-phisher']
            }
        },
        {
            name: 'Password Attacks',
            tools: {
                john: allTools.john,
                hashcat: allTools.hashcat,
                'thc-hydra': allTools['thc-hydra'],
                rainbowcrack: allTools.rainbowcrack
            }
        },
        {
            name: 'Mobile & IoT Hacking',
            tools: {
                mobsf: allTools.mobsf,
                frida: allTools.frida,
                apktool: allTools.apktool,
                jadx: allTools.jadx
            }
        }
    ];

    // UI rendering
    const toolList = document.getElementById('tool-list');
    const toolSearch = document.getElementById('tool-search');
    const toolGuide = document.getElementById('main-tool-guide');
    const terminal = document.getElementById('main-terminal');
    const hiddenInput = document.getElementById('main-hidden-input');
    let currentToolKey = null;
    let currentCategory = null;
    let commandHistory = [];
    let historyIndex = 0;

    function renderToolList(filter = "") {
        toolList.innerHTML = "";
        redCategories.forEach(cat => {
            // Filter tools in this category
            const filtered = Object.entries(cat.tools).filter(([key, tool]) => {
                return (
                    tool.name.toLowerCase().includes(filter) ||
                    (tool.description && tool.description.toLowerCase().includes(filter))
                );
            });
            if (filtered.length > 0) {
                // Category header
                const header = document.createElement('li');
                header.textContent = cat.name;
                header.className = 'tool-category-header';
                header.style.cssText = 'font-weight:bold;margin-top:18px;margin-bottom:6px;color:#ff1744;font-size:1.08em;background:none;cursor:default;';
                toolList.appendChild(header);
                // Tools
                filtered.forEach(([key, tool]) => {
                    const li = document.createElement('li');
                    li.textContent = tool.name;
                    li.dataset.tool = key;
                    if (key === currentToolKey) li.classList.add('selected');
                    li.onclick = () => selectTool(key, cat);
                    toolList.appendChild(li);
                });
            }
        });
    }

    function selectTool(toolKey, catOverride) {
        currentToolKey = toolKey;
        // Find the category for this tool
        let foundCat = catOverride;
        if (!foundCat) {
            for (const cat of redCategories) {
                if (Object.keys(cat.tools).includes(toolKey)) {
                    foundCat = cat;
                    break;
                }
            }
        }
        currentCategory = foundCat;
        renderToolList(toolSearch.value.toLowerCase());
        // Show the activity above the guide
        toolGuide.innerHTML = (currentCategory && currentCategory.activity ? `<div class='category-activity'>${currentCategory.activity}</div>` : "") + allTools[toolKey].guide;
        terminal.innerHTML = "";
        commandHistory = [];
        historyIndex = 0;
        createNewInputLine();
        hiddenInput.value = '';
        hiddenInput.focus();
    }

    function createNewInputLine() {
        const line = document.createElement('div');
        line.className = 'input-line';
        line.innerHTML = `<span class=\"prompt\">${currentToolKey}&gt;</span><span class=\"input-text\"></span><span class=\"cursor\"></span>`;
        terminal.appendChild(line);
        terminal.scrollTop = terminal.scrollHeight;
    }

    function runCommand(cmd) {
        const toolData = allTools[currentToolKey];
        const currentLine = terminal.querySelector('.input-line');
        if(currentLine) {
            currentLine.querySelector('.cursor').remove();
            const oldInput = currentLine.querySelector('.input-text').innerText;
            currentLine.innerHTML = `<span class=\"prompt\">${currentToolKey}&gt;</span>${oldInput}`;
            currentLine.classList.remove('input-line');
        }
        if (cmd) {
            const outputText = (toolData.commands && toolData.commands[cmd]) || `command not found: ${cmd}`;
            const outputLine = document.createElement('div');
            outputLine.className = 'output';
            outputLine.innerText = outputText;
            terminal.appendChild(outputLine);
            if (cmd && !commandHistory.includes(cmd)) {
                commandHistory.push(cmd);
            }
        }
        historyIndex = commandHistory.length;
        createNewInputLine();
        hiddenInput.value = '';
    }

    terminal.addEventListener('click', () => {
        hiddenInput.focus();
    });
    hiddenInput.addEventListener('focus', () => terminal.classList.add('focused'));
    hiddenInput.addEventListener('blur', () => terminal.classList.remove('focused'));
    hiddenInput.addEventListener('input', () => {
        const inputText = terminal.querySelector('.input-line .input-text');
        if(inputText) {
            inputText.textContent = hiddenInput.value;
        }
    });
    hiddenInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            runCommand(hiddenInput.value.trim());
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            if (historyIndex > 0) {
                historyIndex--;
                hiddenInput.value = commandHistory[historyIndex];
                hiddenInput.dispatchEvent(new Event('input'));
            }
        } else if (e.key === 'ArrowDown') {
            e.preventDefault();
            if (historyIndex < commandHistory.length - 1) {
                historyIndex++;
                hiddenInput.value = commandHistory[historyIndex];
                hiddenInput.dispatchEvent(new Event('input'));
            } else {
                historyIndex = commandHistory.length;
                hiddenInput.value = '';
                hiddenInput.dispatchEvent(new Event('input'));
            }
        }
    });

    toolSearch.addEventListener('input', function() {
        renderToolList(this.value.toLowerCase());
        // If no tool is selected or filtered out, select the first visible tool
        const first = toolList.querySelector('li:not(.tool-category-header)');
        if (first && !first.classList.contains('selected')) {
            selectTool(first.dataset.tool);
        }
    });

    // Initial render
    renderToolList();
    // Select the first tool in the first category by default
    const firstCat = redCategories[0];
    selectTool(Object.keys(firstCat.tools)[0], firstCat);
}); 

// Red Team Tools JavaScript with Sound Effects
document.addEventListener('DOMContentLoaded', function() {
    // Initialize sound button state
    const soundBtn = document.getElementById('sound-toggle');
    if (soundBtn) {
        soundBtn.textContent = window.soundManager.enabled ? '🔊' : '🔇';
        soundBtn.style.background = window.soundManager.enabled ? '#00eaff' : '#ff1744';
    }
    
    // Add sound effects to tool cards
    const toolCards = document.querySelectorAll('.tool-card');
    toolCards.forEach(card => {
        card.addEventListener('click', function() {
            window.soundManager.playClick();
            // Add visual feedback
            this.classList.add('success-feedback');
            setTimeout(() => {
                this.classList.remove('success-feedback');
            }, 500);
        });
        
        card.addEventListener('mouseenter', function() {
            window.soundManager.playHover();
        });
    });
    
    // Add sound effects to navigation links
    const navLinks = document.querySelectorAll('nav a');
    navLinks.forEach(link => {
        link.addEventListener('click', function() {
            window.soundManager.playClick();
        });
        
        link.addEventListener('mouseenter', function() {
            window.soundManager.playHover();
        });
    });
    
    // Add sound effects to return button
    const returnBtn = document.querySelector('.return-btn');
    if (returnBtn) {
        returnBtn.addEventListener('click', function() {
            window.soundManager.playClick();
        });
        
        returnBtn.addEventListener('mouseenter', function() {
            window.soundManager.playHover();
        });
    }
    
    // Add sound effects to terminal interactions
    const terminal = document.querySelector('.terminal');
    if (terminal) {
        terminal.addEventListener('click', function() {
            window.soundManager.playTerminal();
        });
    }
    
    // Add sound effects to any buttons in the content
    const buttons = document.querySelectorAll('button');
    buttons.forEach(button => {
        button.addEventListener('click', function() {
            window.soundManager.playClick();
        });
        
        button.addEventListener('mouseenter', function() {
            window.soundManager.playHover();
        });
    });
    
    // Add sound effects to logo
    const logo = document.querySelector('.page-logo');
    if (logo) {
        logo.addEventListener('click', function() {
            window.soundManager.playSuccess();
            // Add visual feedback
            this.style.animation = 'logoGlow 0.5s ease-in-out';
            setTimeout(() => {
                this.style.animation = '';
            }, 500);
        });
        
        logo.addEventListener('mouseenter', function() {
            window.soundManager.playHover();
        });
    }
});

function toggleSound() {
    window.soundManager.toggle();
    const soundBtn = document.getElementById('sound-toggle');
    soundBtn.textContent = window.soundManager.enabled ? '🔊' : '🔇';
    soundBtn.style.background = window.soundManager.enabled ? '#00eaff' : '#ff1744';
    
    // Add visual feedback
    soundBtn.classList.add('success-feedback');
    setTimeout(() => {
        soundBtn.classList.remove('success-feedback');
    }, 500);
}

// Red Team Tools JavaScript
document.addEventListener('DOMContentLoaded', function() {
    // Add hover effects to tool cards
    const toolCards = document.querySelectorAll('.tool-card');
    toolCards.forEach(card => {
        card.addEventListener('click', function() {
            // Add visual feedback
            this.classList.add('success-feedback');
            setTimeout(() => {
                this.classList.remove('success-feedback');
            }, 500);
        });
    });
    
    // Add hover effects to navigation links
    const navLinks = document.querySelectorAll('nav a');
    navLinks.forEach(link => {
        link.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-2px)';
        });
        
        link.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0)';
        });
    });
    
    // Add hover effects to return button
    const returnBtn = document.querySelector('.return-btn');
    if (returnBtn) {
        returnBtn.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-2px)';
        });
        
        returnBtn.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0)';
        });
    }
    
    // Add hover effects to any buttons in the content
    const buttons = document.querySelectorAll('button');
    buttons.forEach(button => {
        button.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-2px)';
        });
        
        button.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0)';
        });
    });
});