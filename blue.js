document.addEventListener('DOMContentLoaded', () => {
    // Enhanced Blue Team Tools with detailed descriptions and interactive commands
    const blueCategories = [
        {
            name: 'SIEM & Log Analysis',
            activity: '🔍 Monitoring and analyzing security events, logs, and alerts in real-time',
            tools: {
                splunk: {
                    name: 'Splunk',
                    guide: `<h3>🔍 Splunk Enterprise Security</h3>
<p><b>What is it?</b><br>Splunk is a powerful platform for searching, monitoring, and analyzing machine-generated big data via a web-style interface. It's the industry standard for SIEM (Security Information and Event Management) and log analysis.</p>

<p><b>Key Features:</b></p>
<ul>
<li>Real-time log indexing and correlation</li>
<li>Advanced search and analytics</li>
<li>Custom dashboards and visualizations</li>
<li>Machine learning for anomaly detection</li>
<li>Threat intelligence integration</li>
<li>Compliance reporting</li>
</ul>

<p><b>SPL (Search Processing Language) Examples:</b></p>
<ul>
<li><code>index=main error</code> - Search for errors in main index</li>
<li><code>index=main source="firewall" action=DENY | stats count by src_ip</code> - Count denied connections by source IP</li>
<li><code>index=main | timechart count by sourcetype</code> - Time-based chart of events</li>
<li><code>index=main | search user="admin" | table _time, source, message</code> - Search for admin user activity</li>
</ul>

<p><b>Available Commands:</b></p>
<ul>
<li><code>help</code> - Show available commands</li>
<li><code>search [SPL query]</code> - Search logs with SPL syntax</li>
<li><code>indexes</code> - List available indexes</li>
<li><code>sources</code> - List data sources</li>
<li><code>sourcetypes</code> - List sourcetypes</li>
<li><code>stats</code> - Show system statistics</li>
<li><code>users</code> - List active users</li>
<li><code>alerts</code> - Show recent alerts</li>
</ul>`,
                    commands: {
                        "help": `Splunk Enterprise Security - Available Commands:

SEARCH COMMANDS:
• search [SPL query] - Search logs with SPL syntax
• indexes - List available data indexes
• sources - List data sources
• sourcetypes - List sourcetypes

SYSTEM COMMANDS:
• stats - Show system statistics
• users - List active users
• alerts - Show recent alerts

SPL EXAMPLES:
• search index=main error
• search index=main source="firewall" action=DENY | stats count by src_ip
• search index=main | timechart count by sourcetype
• search index=main | search user="admin" | table _time, source, message

Type 'search' followed by your SPL query to search logs.`,
                        "search index=main error": `Searching index=main for "error"...
Results: 1,247 events found in the last 24 hours

_time                source              sourcetype         message
2024-01-15 14:23:12 web-server-01      apache:access      ERROR: Authentication failed for user admin from 10.0.0.15
2024-01-15 14:22:45 firewall-01        cisco:asa          ERROR: Connection timeout to 192.168.1.100:443
2024-01-15 14:21:33 database-01        mysql:error        ERROR: Failed login attempt from 10.0.0.15 (Access denied)
2024-01-15 14:20:18 web-server-02      nginx:access       ERROR: SSL certificate expired for domain example.com
2024-01-15 14:19:05 app-server-01      custom:app         ERROR: Database connection failed - timeout after 30s

Showing 5 of 1,247 results`,
                        "search index=main source=\"firewall\" action=DENY | stats count by src_ip": `Searching index=main source="firewall" action=DENY | stats count by src_ip...
Results: 156 events found in the last 24 hours

src_ip          count
10.0.0.15       45
10.0.0.16       32
10.0.0.17       28
10.0.0.18       23
10.0.0.19       18
10.0.0.20       10

Total: 156 denied connections`,
                        "search index=main | timechart count by sourcetype": `Searching index=main | timechart count by sourcetype...
Results: Time-based chart of events by sourcetype

_time                apache:access    cisco:asa    mysql:error    nginx:access    custom:app
2024-01-15 14:00    1,234           567          89             234             123
2024-01-15 14:15    1,456           634          92             267             145
2024-01-15 14:30    1,678           712          95             289             167

Chart shows event counts per 15-minute interval`,
                        "search index=main | search user=\"admin\" | table _time, source, message": `Searching index=main | search user="admin" | table _time, source, message...
Results: 23 events found in the last 24 hours

_time                source              message
2024-01-15 14:23:12 web-server-01      User admin login successful from 10.0.0.15
2024-01-15 14:22:45 database-01        User admin executed query: SELECT * FROM users
2024-01-15 14:21:33 app-server-01      User admin accessed sensitive file: /etc/passwd
2024-01-15 14:20:18 web-server-01      User admin logout from 10.0.0.15
2024-01-15 14:19:05 database-01        User admin created new user: john.doe

Showing 5 of 23 results`,
                        "indexes": `Available Indexes:

Index Name        Event Count    Size        Status
main              2,847,392      847 GB      Active
_internal         45,234         12 GB       Active
_audit            23,456         8 GB        Active
security          12,345         4 GB        Active
network           34,567         15 GB       Active
application       67,890         25 GB       Active
system            89,123         35 GB       Active

Total Events: 3,120,007
Total Size: 946 GB`,
                        "sources": `Data Sources:

Source Type        Count    Examples
Firewall           5        cisco:asa, pfSense, iptables
Web Server         8        apache:access, nginx:access, iis
Database           4        mysql:error, postgresql, oracle
System             12       syslog, windows:eventlog, osx:system
Network            6        netflow, sflow, packet_capture
Application        15       custom:app, java:log, python:log
Security           7        ids:alert, edr:event, antivirus

Total Sources: 57`,
                        "sourcetypes": `Sourcetypes:

Category           Sourcetype
Web                apache:access, nginx:access, iis:access
Network            cisco:asa, netflow, sflow
Database           mysql:error, postgresql, oracle:error
System             syslog, windows:eventlog, osx:system
Security           ids:alert, edr:event, antivirus:scan
Application        custom:app, java:log, python:log
Firewall           pfSense, iptables, cisco:asa

Total Sourcetypes: 45`,
                        "stats": `Splunk System Statistics:

PERFORMANCE:
• Total events indexed: 3,120,007
• Events per second: 1,247
• Search performance: 95% queries < 5s
• Indexing rate: 1.2 GB/hour

RESOURCES:
• Storage used: 946 GB / 2 TB (47%)
• Memory usage: 8.5 GB / 16 GB (53%)
• CPU usage: 45%
• Disk I/O: 234 MB/s

LICENSE:
• Daily quota: 78% used
• License type: Enterprise
• Expiration: 2024-12-31`,
                        "users": `Active Users:

Username           Role              Last Activity    Status
admin              Administrator     2 minutes ago    Online
analyst1           Security Analyst  5 minutes ago    Online
analyst2           Security Analyst  12 minutes ago   Online
manager1           Security Manager  1 hour ago       Online
responder1         Incident Responder 3 minutes ago   Online
viewer1            Viewer            45 minutes ago   Online
auditor1           Auditor           2 hours ago      Offline

Total Users: 7
Online Users: 6`,
                        "alerts": `Recent Security Alerts (Last 24 hours):

HIGH PRIORITY:
• [14:23:12] Multiple failed login attempts from 10.0.0.15 (45 attempts)
• [13:45:33] Unusual network traffic to suspicious IP 185.220.101.45
• [12:18:47] Malware signature detected in file upload: trojan.exe

MEDIUM PRIORITY:
• [11:32:15] Privilege escalation attempt detected on web-server-01
• [10:55:22] Data exfiltration attempt blocked from database-01
• [09:28:14] Unusual PowerShell activity on workstation-05

LOW PRIORITY:
• [08:15:33] SSL certificate expired for domain old.example.com
• [07:42:18] High CPU usage detected on app-server-02

Total Alerts: 8 (3 high, 3 medium, 2 low priority)`
                    },
                    description: 'Enterprise SIEM platform for security monitoring and log analysis'
                },
                elk: {
                    name: 'ELK Stack (Elasticsearch, Logstash, Kibana)',
                    guide: `<h3>🔍 ELK Stack</h3>
<p><b>What is it?</b><br>The ELK Stack is a collection of three open-source products: Elasticsearch (search engine), Logstash (data processing), and Kibana (visualization). Together, they provide a powerful platform for log analysis and security monitoring.</p>

<p><b>Components:</b></p>
<ul>
<li><b>Elasticsearch:</b> Distributed search and analytics engine</li>
<li><b>Logstash:</b> Data processing pipeline for logs</li>
<li><b>Kibana:</b> Web interface for data visualization</li>
</ul>

<p><b>Key Features:</b></p>
<ul>
<li>Real-time log ingestion and processing</li>
<li>Full-text search and analytics</li>
<li>Custom dashboards and visualizations</li>
<li>Machine learning capabilities</li>
<li>Alerting and monitoring</li>
<li>Scalable architecture</li>
</ul>

<p><b>Available Commands:</b></p>
<ul>
<li><code>help</code> - Show available commands</li>
<li><code>search [query]</code> - Search Elasticsearch</li>
<li><code>indices</code> - List Elasticsearch indices</li>
<li><code>pipelines</code> - Show Logstash pipelines</li>
<li><code>dashboards</code> - List Kibana dashboards</li>
<li><code>status</code> - Check ELK stack health</li>
</ul>`,
                    commands: {
                        "help": `ELK Stack - Available Commands:
• search [query] - Search Elasticsearch indices
• indices - List available Elasticsearch indices
• pipelines - Show Logstash processing pipelines
• dashboards - List Kibana dashboards
• status - Check health of all components
• nodes - Show cluster node information
• templates - List index templates

Example searches:
• search error
• search source:firewall AND action:deny
• search @timestamp:[now-1h TO now]`,
                        "search error": `Searching for "error" across all indices...
Found 892 documents in 0.045 seconds

Results:
• web-logs-2024.01.15: 234 errors
• system-logs-2024.01.15: 156 errors
• application-logs-2024.01.15: 502 errors

Top error types:
• Connection timeout: 45%
• Authentication failed: 32%
• Permission denied: 23%`,
                        "indices": `Elasticsearch Indices:
• web-logs-2024.01.15 (1.2GB, 45,234 docs)
• system-logs-2024.01.15 (856MB, 23,456 docs)
• application-logs-2024.01.15 (2.1GB, 67,890 docs)
• security-logs-2024.01.15 (445MB, 12,345 docs)
• network-logs-2024.01.15 (678MB, 34,567 docs)

Total indices: 15
Total storage: 5.3GB`,
                        "pipelines": `Logstash Processing Pipelines:
• web-logs-pipeline - Processes web server logs
• system-logs-pipeline - Processes system logs
• security-logs-pipeline - Processes security events
• network-logs-pipeline - Processes network traffic
• application-logs-pipeline - Processes application logs

Pipeline Status: All running
Total events processed: 183,492 in last hour`,
                        "dashboards": `Kibana Dashboards:
• Security Overview - Real-time security monitoring
• Network Traffic Analysis - Network flow visualization
• System Health - Infrastructure monitoring
• Application Performance - APM metrics
• User Activity - User behavior analytics
• Compliance Reporting - Regulatory dashboards

Access via: http://localhost:5601`,
                        "status": `ELK Stack Health Status:
• Elasticsearch: 🟢 Healthy (3 nodes, green status)
• Logstash: 🟢 Running (5 pipelines active)
• Kibana: 🟢 Available (http://localhost:5601)

Cluster Health: Green
Active Shards: 45/45
Indexing Rate: 1,234 docs/sec
Search Rate: 567 queries/sec`,
                        "nodes": `Elasticsearch Cluster Nodes:
• node-1 (Master): 192.168.1.10 - CPU: 45%, RAM: 67%
• node-2 (Data): 192.168.1.11 - CPU: 38%, RAM: 72%
• node-3 (Data): 192.168.1.12 - CPU: 42%, RAM: 69%

Cluster Status: Green
Total Nodes: 3
Active Shards: 45`,
                        "templates": `Index Templates:
• logstash-* - Default template for Logstash indices
• security-* - Template for security event indices
• web-* - Template for web server logs
• system-* - Template for system logs
• application-* - Template for application logs

Template Management: Use Kibana Index Management or API`
                    },
                    description: 'Open-source log analysis and visualization platform'
                },
                graylog: {
                    name: 'Graylog',
                    guide: `<h3>🔍 Graylog</h3>
<p><b>What is it?</b><br>Graylog is an open-source log management platform that can collect, index, and analyze both structured and unstructured data from almost any source. It's particularly popular for security monitoring and compliance.</p>

<p><b>Key Features:</b></p>
<ul>
<li>Centralized log collection and processing</li>
<li>Powerful search and analytics</li>
<li>Real-time alerting and notifications</li>
<li>Role-based access control</li>
<li>REST API for integration</li>
<li>Extensible plugin architecture</li>
</ul>

<p><b>Available Commands:</b></p>
<ul>
<li><code>help</code> - Show available commands</li>
<li><code>search [query]</code> - Search logs</li>
<li><code>streams</code> - List message streams</li>
<li><code>inputs</code> - Show data inputs</li>
<li><code>alerts</code> - Show active alerts</li>
<li><code>users</code> - List users</li>
</ul>`,
                    commands: {
                        "help": `Graylog - Available Commands:
• search [query] - Search logs with Graylog query syntax
• streams - List message streams
• inputs - Show configured data inputs
• alerts - Show active alerts and notifications
• users - List users and their roles
• stats - Show system statistics
• nodes - Show cluster node information

Example searches:
• source:firewall AND action:deny
• level:ERROR OR level:CRITICAL
• message:"authentication failed"`,
                        "search source:firewall AND action:deny": `Searching for firewall deny actions...
Found 156 messages in the last 24 hours

Results:
• 2024-01-15 14:23:12 - DENY 10.0.0.15 -> 192.168.1.100 (Port 22)
• 2024-01-15 14:22:45 - DENY 10.0.0.16 -> 192.168.1.101 (Port 80)
• 2024-01-15 14:21:33 - DENY 10.0.0.17 -> 192.168.1.102 (Port 443)

Top denied IPs:
• 10.0.0.15: 45 denials
• 10.0.0.16: 32 denials
• 10.0.0.17: 28 denials`,
                        "streams": `Message Streams:
• Security Events - High-priority security alerts
• Network Traffic - Network flow and firewall logs
• System Logs - Operating system and service logs
• Application Logs - Application-specific events
• Compliance - Regulatory compliance events
• Performance - System performance metrics

Total Streams: 6
Total Messages: 2,847,392`,
                        "inputs": `Data Inputs:
• GELF UDP - Graylog Extended Log Format (UDP)
• GELF TCP - Graylog Extended Log Format (TCP)
• Syslog UDP - System logs via UDP
• Syslog TCP - System logs via TCP
• Beats - Filebeat, Packetbeat, etc.
• REST API - HTTP/REST input

Input Status: All active
Total Inputs: 12`,
                        "alerts": `Active Alerts:
• High CPU Usage - Triggered 5 minutes ago
• Multiple Failed Logins - Triggered 12 minutes ago
• Unusual Network Traffic - Triggered 23 minutes ago
• Disk Space Low - Triggered 1 hour ago

Alert History (Last 24h):
• Total Alerts: 15
• High Priority: 3
• Medium Priority: 8
• Low Priority: 4`,
                        "users": `Graylog Users:
• admin (Administrator) - Full access
• analyst1 (Security Analyst) - Read/Write access
• analyst2 (Security Analyst) - Read/Write access
• viewer1 (Viewer) - Read-only access
• manager1 (Manager) - Read/Write + Admin access

Total Users: 5
Active Sessions: 3`,
                        "stats": `Graylog System Statistics:
• Total Messages: 2,847,392
• Messages per second: 1,234
• Index Size: 847 GB
• Active Streams: 6
• Active Inputs: 12
• Cluster Health: Green
• Uptime: 15 days, 7 hours`
                    },
                    description: 'Open-source log management and analysis platform'
                }
            }
        },
        {
            name: 'Intrusion Detection & Prevention (IDS/IPS)',
            activity: '🛡️ Detecting and preventing network intrusions and malicious activities',
            tools: {
                snort: {
                    name: 'Snort',
                    guide: `<h3>🛡️ Snort IDS/IPS</h3>
<p><b>What is it?</b><br>Snort is an open-source network intrusion detection and prevention system (IDS/IPS) capable of real-time traffic analysis and packet logging. It's one of the most widely used IDS/IPS solutions in the world.</p>

<p><b>Key Features:</b></p>
<ul>
<li>Real-time packet analysis and inspection</li>
<li>Rule-based detection engine</li>
<li>Protocol analysis and anomaly detection</li>
<li>Preprocessor plugins for advanced analysis</li>
<li>Flexible output formats</li>
<li>Community and commercial rule sets</li>
</ul>

<p><b>Operating Modes:</b></p>
<ul>
<li><b>Sniffer Mode:</b> Read and display packets</li>
<li><b>Packet Logger Mode:</b> Log packets to disk</li>
<li><b>Network IDS Mode:</b> Monitor network for intrusions</li>
<li><b>Inline Mode:</b> Act as IPS with packet dropping</li>
</ul>

<p><b>Rule Syntax Examples:</b></p>
<ul>
<li><code>alert tcp any any -> any 80 (msg:"Web Attack"; content:"GET /admin"; sid:1001;)</code></li>
<li><code>alert tcp any any -> any 22 (msg:"SSH Brute Force"; threshold:type threshold, track by_src, count 5, seconds 60; sid:1002;)</code></li>
<li><code>alert ip any any -> any any (msg:"Suspicious IP"; ipvar:SUSPICIOUS_IPS; sid:1003;)</code></li>
</ul>

<p><b>Available Commands:</b></p>
<ul>
<li><code>help</code> - Show available commands</li>
<li><code>start</code> - Start Snort in IDS mode</li>
<li><code>stop</code> - Stop Snort</li>
<li><code>status</code> - Show Snort status</li>
<li><code>rules</code> - List loaded rules</li>
<li><code>alerts</code> - Show recent alerts</li>
<li><code>stats</code> - Show statistics</li>
<li><code>config</code> - Show configuration</li>
<li><code>test-rule [rule]</code> - Test rule syntax</li>
</ul>`,
                    commands: {
                        "help": `Snort IDS/IPS - Available Commands:

CONTROL COMMANDS:
• start - Start Snort in IDS mode
• stop - Stop Snort service
• status - Show current status

RULE MANAGEMENT:
• rules - List loaded rules and categories
• test-rule [rule] - Test rule syntax
• config - Show current configuration

MONITORING:
• alerts - Show recent security alerts
• stats - Show packet and alert statistics

EXAMPLES:
• start - Start monitoring network traffic
• alerts - View recent intrusion attempts
• test-rule "alert tcp any any -> any 80 (msg:\"Test\"; sid:9999;)"`,
                        "start": `Starting Snort IDS...
Loading configuration from /etc/snort/snort.conf
Loading rules from /etc/snort/rules/

Rule Loading Summary:
• Community rules: 3,247 rules loaded
• Emerging threats: 1,856 rules loaded
• Custom rules: 23 rules loaded
• Total rules: 5,126

Initializing preprocessors:
• frag3: Fragment reassembly
• stream5: TCP stream reassembly
• http_inspect: HTTP inspection
• ftp_telnet: FTP/Telnet inspection
• smtp: SMTP inspection
• dns: DNS inspection
• ssl: SSL/TLS inspection
• dcerpc2: DCERPC inspection

Starting packet capture on eth0...
Snort IDS is now running and monitoring network traffic

Output files:
• Alert file: /var/log/snort/alert
• Log directory: /var/log/snort/
• Unified2 output: /var/log/snort/snort.u2`,
                        "stop": `Stopping Snort IDS...
Sending SIGTERM to Snort process (PID: 1234)
Waiting for graceful shutdown...
Snort IDS stopped successfully

Final Statistics:
• Packets processed: 1,234,567
• Alerts generated: 45
• Rules matched: 67
• TCP sessions: 12,345
• UDP sessions: 5,678`,
                        "status": `Snort IDS Status:

SERVICE STATUS:
• Service: Running (PID: 1234)
• Mode: Network IDS
• Interface: eth0
• Configuration: /etc/snort/snort.conf

RULES STATUS:
• Rules loaded: 5,126
• Active rules: 5,089
• Disabled rules: 37
• Preprocessors: 8 active

PERFORMANCE:
• Packets per second: 1,234
• Memory usage: 256 MB
• CPU usage: 12%
• Uptime: 2 days, 15 hours, 32 minutes`,
                        "rules": `Loaded Snort Rules:

COMMUNITY RULES (3,247):
DOS Attacks:
• 234 rules - SYN flood, ICMP flood, UDP flood
• 123 rules - Application layer DDoS

Web Attacks:
• 567 rules - SQL injection, XSS, directory traversal
• 234 rules - Web shell, file inclusion
• 156 rules - Authentication bypass

Malware:
• 445 rules - Botnet C&C communication
• 234 rules - Malware download attempts
• 189 rules - Ransomware indicators

Exploits:
• 789 rules - Buffer overflow attempts
• 456 rules - Remote code execution
• 234 rules - Privilege escalation

EMERGING THREATS (1,856):
• Botnet C&C: 234 rules
• Malware traffic: 567 rules
• Exploit kits: 345 rules
• APT indicators: 710 rules

CUSTOM RULES (23):
• Company-specific: 15 rules
• Compliance: 8 rules

Total Rules: 5,126
Active Rules: 5,089
Disabled Rules: 37`,
                        "alerts": `Recent Snort Alerts (Last 24 hours):

HIGH PRIORITY:
• [14:23:12] [1:2345:1] "Suspicious HTTP request to malicious domain" 
  TCP 10.0.0.15:54321 -> 185.220.101.45:80
  Rule: alert tcp any any -> any 80 (msg:"Malicious Domain Access"; content:"malware.com"; sid:2345;)

• [14:22:45] [1:3456:2] "Port scan detected from 10.0.0.15"
  TCP 10.0.0.15:12345 -> 192.168.1.100:22
  Rule: alert tcp any any -> any 22 (msg:"Port Scan"; threshold:type threshold, track by_src, count 10, seconds 60; sid:3456;)

• [14:21:33] [1:4567:3] "SQL injection attempt detected"
  TCP 10.0.0.15:54321 -> 192.168.1.101:80
  Rule: alert tcp any any -> any 80 (msg:"SQL Injection"; content:"' OR 1=1--"; sid:4567;)

MEDIUM PRIORITY:
• [14:20:18] [1:5678:4] "Malware download attempt blocked"
• [14:19:05] [1:6789:5] "Brute force attack detected"
• [14:18:33] [1:7890:6] "Suspicious PowerShell activity"

Alert Summary:
• High Priority: 3 alerts
• Medium Priority: 8 alerts
• Low Priority: 12 alerts
• Total: 23 alerts`,
                        "stats": `Snort Statistics:

PACKET STATISTICS:
• Packets Processed: 1,234,567
• Packets Dropped: 0
• Packets Ignored: 12,345
• Fragments Reassembled: 8,234
• Streams Reassembled: 15,678

ALERT STATISTICS:
• Alerts Generated: 23
• Rules Matched: 45
• TCP Sessions: 12,345
• UDP Sessions: 5,678
• ICMP Packets: 2,345

PERFORMANCE METRICS:
• Packets per second: 1,234
• Memory usage: 256 MB
• CPU usage: 12%
• Disk I/O: 45 MB/s
• Active TCP sessions: 234`,
                        "config": `Snort Configuration:

CONFIGURATION FILES:
• Main config: /etc/snort/snort.conf
• Rules directory: /etc/snort/rules/
• Log directory: /var/log/snort/
• Alert file: /var/log/snort/alert
• Interface: eth0
• Mode: Network IDS

PREPROCESSORS:
• frag3: Fragment reassembly
• stream5: TCP stream reassembly
• http_inspect: HTTP inspection
• ftp_telnet: FTP/Telnet inspection
• smtp: SMTP inspection
• dns: DNS inspection
• ssl: SSL/TLS inspection
• dcerpc2: DCERPC inspection

OUTPUT PLUGINS:
• alert_fast: Fast alerting
• log_tcpdump: Packet logging
• unified2: Unified2 output format`,
                        "test-rule alert tcp any any -> any 80 (msg:\"Test Rule\"; sid:9999;)": `Testing rule syntax...
Rule: alert tcp any any -> any 80 (msg:"Test Rule"; sid:9999;)

Syntax check: PASSED
Rule components:
• Action: alert
• Protocol: tcp
• Source: any:any
• Destination: any:80
• Options: msg:"Test Rule", sid:9999

Rule is valid and ready to use.`
                    },
                    description: 'Open-source network intrusion detection and prevention system'
                },
                suricata: {
                    name: 'Suricata',
                    guide: `<h3>🛡️ Suricata IDS/IPS</h3>
<p><b>What is it?</b><br>Suricata is a high-performance Network IDS, IPS, and Network Security Monitoring (NSM) engine. It's designed to be fast, robust, and feature-rich, supporting multi-threading and modern network architectures.</p>

<p><b>Key Features:</b></p>
<ul>
<li>Multi-threaded architecture for high performance</li>
<li>Advanced rule language with Lua scripting</li>
<li>Protocol analysis and anomaly detection</li>
<li>File extraction and analysis</li>
<li>HTTP/HTTPS inspection</li>
<li>SSL/TLS traffic analysis</li>
<li>Integration with external tools</li>
</ul>

<p><b>Available Commands:</b></p>
<ul>
<li><code>help</code> - Show available commands</li>
<li><code>start</code> - Start Suricata</li>
<li><code>stop</code> - Stop Suricata</li>
<li><code>status</code> - Show status</li>
<li><code>rules</code> - List rules</li>
<li><code>alerts</code> - Show alerts</li>
<li><code>files</code> - Show extracted files</li>
</ul>`,
                    commands: {
                        "help": `Suricata IDS/IPS - Available Commands:
• start - Start Suricata IDS/IPS
• stop - Stop Suricata service
• status - Show current status and performance
• rules - List loaded rules and categories
• alerts - Show recent security alerts
• files - Show extracted files and analysis
• stats - Show detailed statistics
• config - Show configuration details

Example usage:
• start - Begin network monitoring
• alerts - View intrusion attempts
• files - Check extracted malware samples`,
                        "start": `Starting Suricata IDS/IPS...
Loading configuration from /etc/suricata/suricata.yaml
Initializing multi-threaded engine...
• Threads: 8 worker threads
• Memory: 2 GB allocated
• CPU affinity: Enabled

Loading rules:
• Emerging Threats: 2,456 rules
• Snort Community: 3,247 rules
• Custom rules: 45 rules
• Total: 5,748 rules loaded

Starting packet capture on eth0...
Suricata is now running in IDS mode
Alert file: /var/log/suricata/fast.log
EVE log: /var/log/suricata/eve.json`,
                        "stop": `Stopping Suricata IDS/IPS...
Sending shutdown signal to Suricata (PID: 2345)
Waiting for graceful shutdown...
Suricata stopped successfully

Final Statistics:
• Packets processed: 2,345,678
• Alerts generated: 67
• Files extracted: 23
• Rules matched: 89`,
                        "status": `Suricata IDS/IPS Status:
• Service: Running (PID: 2345)
• Mode: Network IDS
• Interface: eth0
• Threads: 8 worker threads
• Rules loaded: 5,748
• Memory usage: 2.1 GB
• CPU usage: 18%

Performance:
• Packets per second: 2,345
• Alerts per second: 0.5
• Files extracted: 23
• Uptime: 3 days, 7 hours`,
                        "rules": `Loaded Suricata Rules:
• Emerging Threats (2,456):
  - Malware: 567 rules
  - Exploits: 789 rules
  - Botnet: 234 rules
  - APT: 456 rules
  - Web attacks: 410 rules

• Snort Community (3,247):
  - DOS attacks: 234 rules
  - Web attacks: 567 rules
  - Malware: 445 rules
  - Exploits: 789 rules
  - Policy violations: 212 rules

• Custom Rules (45):
  - Company-specific: 30 rules
  - Compliance: 15 rules

Total Rules: 5,748
Active Rules: 5,689
Disabled Rules: 59`,
                        "alerts": `Recent Suricata Alerts (Last 24 hours):
• 14:23:12 - [1:2345:1] Suspicious HTTP request to malicious domain
• 14:22:45 - [1:3456:2] Port scan detected from 10.0.0.15
• 14:21:33 - [1:4567:3] SQL injection attempt detected
• 14:20:18 - [1:5678:4] Malware download attempt blocked
• 14:19:05 - [1:6789:5] Brute force attack detected

Alert Summary:
• High Priority: 5 alerts
• Medium Priority: 12 alerts
• Low Priority: 18 alerts
• Total: 35 alerts`,
                        "files": `Extracted Files (Last 24 hours):
• suspicious_document.pdf (2.3 MB) - Extracted from HTTP traffic
• malware_sample.exe (1.7 MB) - Extracted from HTTP traffic
• phishing_email.eml (45 KB) - Extracted from SMTP traffic
• malicious_script.js (12 KB) - Extracted from HTTP traffic

File Analysis:
• PDF files: 3 (2 suspicious)
• Executables: 5 (4 malicious)
• Scripts: 8 (6 malicious)
• Documents: 12 (3 suspicious)

Total files: 28
Malicious files: 15 (53.6%)`,
                        "stats": `Suricata Statistics:
• Packets Processed: 2,345,678
• Packets Dropped: 0
• Packets Ignored: 23,456
• Alerts Generated: 35
• Rules Matched: 67
• Files Extracted: 28
• TCP Sessions: 23,456
• UDP Sessions: 12,345
• HTTP Requests: 45,678

Performance Metrics:
• Packets per second: 2,345
• Memory usage: 2.1 GB
• CPU usage: 18%
• Disk I/O: 67 MB/s`
                    },
                    description: 'High-performance network IDS/IPS and NSM engine'
                }
            }
        },
        {
            name: 'Endpoint Protection & Monitoring',
            activity: '🖥️ Monitoring and protecting endpoints from threats and suspicious activity',
            tools: {
                osquery: {
                    name: 'Osquery',
                    guide: `<h3>🖥️ Osquery</h3>
<p><b>What is it?</b><br>Osquery is an operating system instrumentation framework for Windows, macOS, Linux, and FreeBSD. It exposes the OS as a high-performance relational database, allowing you to write SQL-based queries to explore system data.</p>
<p><b>Key Features:</b></p>
<ul>
<li>SQL-based queries for system data</li>
<li>Cross-platform support</li>
<li>Real-time monitoring with event-based tables</li>
<li>Extensible with custom tables and plugins</li>
</ul>
<p><b>Available Commands:</b></p>
<ul>
<li><code>help</code> - Show available commands</li>
<li><code>query [SQL]</code> - Run an osquery SQL query</li>
<li><code>tables</code> - List available tables</li>
<li><code>examples</code> - Show example queries</li>
</ul>`,
                    commands: {
                        "help": `Osquery - Available Commands:\n• query [SQL] - Run an osquery SQL query\n• tables - List available tables\n• examples - Show example queries\n\nExample: query SELECT * FROM processes WHERE name='ssh';`,
                        "query SELECT * FROM processes WHERE name='ssh';": `pid: 1234, name: ssh, user: root, state: running`,
                        "tables": `Available Tables:\n• processes\n• users\n• listening_ports\n• logged_in_users\n• file\n• system_info\n• kernel_info\n• crontab\n• etc_hosts\n• ...`,
                        "examples": `Example Queries:\n• query SELECT * FROM users;\n• query SELECT * FROM listening_ports WHERE port=22;\n• query SELECT * FROM processes WHERE name='explorer.exe';\n• query SELECT * FROM system_info;`
                    },
                    description: 'SQL-powered endpoint visibility and monitoring framework'
                },
                sysmon: {
                    name: 'Sysmon',
                    guide: `<h3>🖥️ Sysmon</h3>
<p><b>What is it?</b><br>Sysmon is a Windows system service and device driver that logs system activity to the Windows event log. It provides detailed information about process creations, network connections, and changes to file creation time.</p>
<p><b>Key Features:</b></p>
<ul>
<li>Detailed process creation logs</li>
<li>Network connection monitoring</li>
<li>File creation and modification tracking</li>
<li>Hashes of process images</li>
<li>Integration with SIEMs</li>
</ul>
<p><b>Available Commands:</b></p>
<ul>
<li><code>help</code> - Show available commands</li>
<li><code>status</code> - Show Sysmon status</li>
<li><code>config</code> - Show current configuration</li>
<li><code>logs</code> - Show recent Sysmon logs</li>
</ul>`,
                    commands: {
                        "help": `Sysmon - Available Commands:\n• status - Show Sysmon status\n• config - Show current configuration\n• logs - Show recent Sysmon logs\n\nExample: status`,
                        "status": `Sysmon is running. Version: 14.0.0.0\nMonitored events: Process Create, Network Connect, File Create, Registry, DNS Query`,
                        "config": `Sysmon Configuration:\n• Log process creation: enabled\n• Log network connections: enabled\n• Log file creation: enabled\n• Hash algorithms: SHA256, MD5\n• Log DNS queries: enabled`,
                        "logs": `Recent Sysmon Logs:\n• [14:23:12] Process Create: powershell.exe (PID 4321)\n• [14:22:45] Network Connect: 192.168.1.100:443\n• [14:21:33] File Create: C:\\temp\\malware.exe\n• [14:20:18] DNS Query: suspicious-domain.com`
                    },
                    description: 'Windows system activity monitoring and logging tool'
                },
                crowdstrike: {
                    name: 'CrowdStrike Falcon',
                    guide: `<h3>🖥️ CrowdStrike Falcon</h3>
<p><b>What is it?</b><br>CrowdStrike Falcon is a cloud-delivered endpoint protection platform that combines antivirus, EDR, and threat intelligence. It uses lightweight agents and cloud analytics to detect and respond to threats in real time.</p>
<p><b>Key Features:</b></p>
<ul>
<li>Cloud-based EDR and antivirus</li>
<li>Threat intelligence integration</li>
<li>Real-time detection and response</li>
<li>Lightweight agent</li>
<li>Incident investigation and remediation</li>
</ul>
<p><b>Available Commands:</b></p>
<ul>
<li><code>help</code> - Show available commands</li>
<li><code>status</code> - Show agent status</li>
<li><code>alerts</code> - Show recent alerts</li>
<li><code>scan</code> - Simulate a malware scan</li>
</ul>`,
                    commands: {
                        "help": `CrowdStrike Falcon - Available Commands:\n• status - Show agent status\n• alerts - Show recent alerts\n• scan - Simulate a malware scan\n\nExample: status`,
                        "status": `CrowdStrike Falcon agent is running and healthy. Last cloud sync: 2 minutes ago.`,
                        "alerts": `Recent Alerts:\n• [14:23:12] Malware detected and quarantined: ransomware.exe\n• [13:45:33] Suspicious PowerShell activity\n• [12:18:47] Lateral movement attempt blocked`,
                        "scan": `Simulating malware scan...\nNo threats detected. System is clean.`
                    },
                    description: 'Cloud-delivered EDR and endpoint protection platform'
                },
                carbonblack: {
                    name: 'Carbon Black',
                    guide: `<h3>🖥️ Carbon Black</h3>
<p><b>What is it?</b><br>Carbon Black is an endpoint security platform for threat detection, incident response, and forensics. It continuously records and stores endpoint activity data, enabling security teams to detect, respond to, and remediate threats.</p>
<p><b>Key Features:</b></p>
<ul>
<li>Continuous endpoint activity recording</li>
<li>Threat detection and response</li>
<li>Incident investigation and forensics</li>
<li>Behavioral analytics</li>
<li>Integration with SIEMs and SOAR</li>
</ul>
<p><b>Available Commands:</b></p>
<ul>
<li><code>help</code> - Show available commands</li>
<li><code>status</code> - Show agent status</li>
<li><code>alerts</code> - Show recent alerts</li>
<li><code>investigate</code> - Simulate an incident investigation</li>
</ul>`,
                    commands: {
                        "help": `Carbon Black - Available Commands:\n• status - Show agent status\n• alerts - Show recent alerts\n• investigate - Simulate an incident investigation\n\nExample: status`,
                        "status": `Carbon Black agent is running and healthy. Last event upload: 5 minutes ago.`,
                        "alerts": `Recent Alerts:\n• [14:23:12] Ransomware blocked: cryptolocker.exe\n• [13:45:33] Unusual process injection detected\n• [12:18:47] Suspicious network connection blocked`,
                        "investigate": `Simulating incident investigation...\nNo active threats found. All endpoints are secure.`
                    },
                    description: 'Endpoint security platform for detection, response, and forensics'
                }
            }
        }
    ];

    // Flatten tools for search and selection
    const allTools = {};
    blueCategories.forEach(cat => {
        Object.entries(cat.tools).forEach(([key, tool]) => {
            allTools[key] = tool;
        });
    });

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
        blueCategories.forEach(cat => {
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
                header.style.cssText = 'font-weight:bold;margin-top:18px;margin-bottom:6px;color:#00eaff;font-size:1.08em;background:none;cursor:default;';
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
            for (const cat of blueCategories) {
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
            const outputText = (toolData.commands && toolData.commands[cmd]) || `Command not found: ${cmd}\nType 'help' for available commands.`;
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
    const firstCat = blueCategories[0];
    selectTool(Object.keys(firstCat.tools)[0], firstCat);

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
