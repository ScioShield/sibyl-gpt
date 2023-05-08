# Sibyl-GPT Alert Parsing Script

This script connects to the ElasticSearch Detection Engine API, retrieves alerts, allows users to choose one for investigation, and sends the chosen alert to OpenAI to get suggested investigation and remediation.  

## Acknowledgments

The main inspiration for this work is from Mika's excellent [article](https://www.elastic.co/security-labs/exploring-applications-of-chatgpt-to-improve-detection-response-and-understanding) 

## Requirements

An OpenAI API key  

Python 3.6 or higher  
- requests  
- openai  
- dotenv  
- rich  

Install the required libraries using:  

```
python3 -m pip install -r requirements.txt --user
```
[Why "python3 -m pip"?](https://stackoverflow.com/questions/25749621/whats-the-difference-between-pip-install-and-python-m-pip-install)

An Elastic instance with **open** alerts. I have a provisioning [script](https://github.com/ScioShield/AtomicFireFly) if you want to bring one up locally.  

## Features
- Fetch open alerts from the ElasticSearch Detection Engine API. Sorted from most to least critical.  
- Display unique alert list and allow users to choose one for investigation. Sorted from newest to oldest.  
- Retrieve detailed alert data based on the user's choice  
- Send the selected alert to OpenAI for recommended investigation and remediation  
- Display the suggested investigation path and Kibana searches  
- Estimate the cost of OpenAI API calls  
- Save OpenAI input and output to a file (optional)  

## Caveats

**This script is an experiment!**  

**I am not a programmer!** :) The code probably has bugs/issues, please raise an issue if you have any problems running it.  

Review the data that will be sent to OpenAI with the `--debug` flag first. You will be sending internal hostnames and IP addresses to an external third party. Without pseudonymization this will almost certainly contravene your companies security policy!  

I would strongly advise to spin up a test cluster first! Wouldn't want to `rm -rf /` prod, unless you really want to wake up on a Monday morning!  

Sending large amounts of data to OpenAI can be quite costly especially for the GPT-4 model, hence the save to file feature.  

## Usage

1. Add your Elasticsearch credentials and OpenAI API key to a `.env` file in the script directory:  
Or rename the `.env.example` file to `.env` and change the required felids. Replace the item after "=" with the value, no quotes!

```
E_URL=Elastic_URL # Example: https://192.168.56.10:5601 or https://atomicfirefly:5601
E_USER=Elastic_Username # Example: elastic
E_PASS=Elastic_Password # Example: o2PAhmXC9eYVNUKpoieBYKbXqJ83vNo0
E_CA_PATH=Path_to_CA_certificates # Example: /tmp/certs/ca.crt
OPENAI_API_KEY=Your_OpenAI_API_Key # Example: sk-SSdkIHByZXRlbmQgSSB3YXMgb25lIG9mIHRob3NlIGRlYWYtbXV0ZXMgb3Igc2hvdWxkIEk/Cg==
```
Remove the `CA_CERTS_PATH` var from the script and `.env` if you are using an unsecured cluster or the Elastic Cloud

2. Run the script using:

```
python3 sibyl-gpt.py
```

3. Optional flags:

- `-h, --help`: Print the help message

- `--debug`: Enable debug mode (doesn't send any API calls to OpenAI).

- `--g4`: Use GPT-4 model, default is gpt-3.5-turbo.

- `--risk`: Specify the minimum risk score (0-100), defaults to 70.

- `--size`: Specify the number of returned results (the unique_alerts search is separate), defaults to 100.

- `--save`: Save the OpenAI output to a file (doesn't work for hints).

## Improvements and future work

- The rich rendering markdown isn't perfect  
- Think about a time window (as in look at alerts in the past day, week, month, etc not just all time)  
- Update the cost estimate function to also catch hint calls to be added to the total  
- Think about adding a "session" feature so it makes the costing (I'm still not happy about where the costing is displayed) and saving functions much better.  
- Get a way for it to work with an Elastic API key (So remove user/pass)  
- Think about a way to open a case in Elastic with all the details filled in  
- Think about a pseudonymization function to send OpenAI fake IP and hostnames, then reverse the process locally before being displayed to the user (the description in the hint makes this a bit more complex)  
- Unit tests  
- Snyk monitoring  
- Debug mode should also show what endpoints the script is connecting to e.g. `Connecting to: https://atomicfirefly:5601`  
- Think about LangChain and how to integrate this system with a "long term memory" vector database like Pinecone or Elastic's vector store (so the whole returned alert can be stored not just the small subsection we send to OpenAI), this way if an alert has been raised before can use that result as an example (more broadly not all items *need* to be sent to the OpenAI's API so a smart way of filtering it will save a lot of $$$)  
- Maybe have a way to chose what type of data to send to OpenAI (So can be only alert related, alert and host related, alert and exact process related, etc.)  
- Generalizing the script to work with other SIEMs like Splunk  

## Demo

1. No arguments (so will default to a risk score of minimum 70, a size window of 100, however always will search for 1000 alerts, using gpt-3.5-turbo, doesn't save to a file, always outputs API call cost estimates)
```
$ python3 sibyl-gpt.py
[1] Malware Detection Alert, Severity: critical
[2] Parent Process PID Spoofing, Severity: high
[3] Potential Invoke-Mimikatz PowerShell Script, Severity: high
[4] Suspicious PrintSpooler Service Executable File Creation, Severity: high

> Enter the number of the alert you'd like to investigate (1-4), 'H' for hint (sends the alert selection to OpenAI) or 'Q' to quit: 1  

[1] Malware Detection Alert, Severity: critical, Description: malware, intrusion_detection, file event with process powershell.exe, parent process powershell.exe, file PotentiallyUnwanted.exe, by vagrant on atomicfirefly-windows created critical alert Malware Detection Alert.
[2] Malware Detection Alert, Severity: critical, Description: malware, intrusion_detection, process event with process PotentiallyUnwanted.exe, parent process powershell.exe, file PotentiallyUnwanted.exe, by vagrant on atomicfirefly-windows created critical alert Malware Detection Alert.
[3] Malware Detection Alert, Severity: critical, Description: malware, intrusion_detection, process event with process PotentiallyUnwanted.exe, parent process powershell.exe, file PotentiallyUnwanted.exe, by vagrant on atomicfirefly-windows created critical alert Malware Detection Alert.
[4] Malware Detection Alert, Severity: critical, Description: malware, intrusion_detection, file event with process powershell.exe, parent process powershell.exe, file PotentiallyUnwanted.exe, by vagrant on atomicfirefly-windows created critical alert Malware Detection Alert.
[5] Malware Detection Alert, Severity: critical, Description: malware, intrusion_detection, file event with process svchost.exe, parent process services.exe, file BIT9AEB.tmp, by SYSTEM on atomicfirefly-windows created critical alert Malware Detection Alert.
[6] Malware Detection Alert, Severity: critical, Description: malware, intrusion_detection, file event with process svchost.exe, parent process services.exe, file Backstab64.exe, by SYSTEM on atomicfirefly-windows created critical alert Malware Detection Alert.
[7] Malware Detection Alert, Severity: critical, Description: malware, intrusion_detection, process event with process Backstab64.exe, parent process powershell.exe, file Backstab64.exe, by vagrant on atomicfirefly-windows created critical alert Malware Detection Alert.

> Enter the number of the alert you'd like to investigate (1-7), 'H' for hint (sends the alert selection to OpenAI) or 'Q' to quit: 5

Suggested investigation and remediation for the alert:
Investigation:
1. Check if the identified malware is known and if there are any associated risk factors.
2. Check if there are any other systems in the network that have been affected by the same malware.
3. Identify the source of the malware and how it entered the system.
4. Check if any data has been exfiltrated from the system.
5. Check if any other malicious activity has been detected on the system.

Remediation:
1. Quarantine the affected system and disconnect it from the network.
2. Disable any services or processes that are associated with the malware.
3. Use anti-malware software to remove the malware from the system.
4. Update the system and all the software to the latest version to prevent future attacks.
5. Change all the login credentials for the system and related accounts.
6. Conduct a comprehensive security audit to identify any vulnerabilities and take necessary actions to fix them.

Thinking step by step create and justify Kibana searches to investigate:
Step 1: Investigate svchost.exe process

To investigate the svchost.exe process, we can use the "process.args" field and search for logs that match the following query:

process.args: "C:\\Windows\\System32\\svchost.exe"

This will return all logs where the process.args contain the string "C:\Windows\System32\svchost.exe". We can further filter the results by using time range and hostname if needed.

Step 2: Investigate the parent process of svchost.exe

To investigate the parent process of svchost.exe, we can use the "process.parent.name" field and search for logs that match the following query:

process.parent.name: "services.exe"

This will return all logs where the process.parent.name contains the string "services.exe". We can further filter the results by using time range and hostname if needed.

Step 3: Investigate the file created by the svchost.exe process

To investigate the file created by the svchost.exe process, we can use the "file.path" field and search for logs that match the following query:

file.path: "BIT9AEB.tmp"

This will return all logs where the file.path contains the string "BIT9AEB.tmp". We can further filter the results by using time range and hostname if needed.

Step 4: Investigate the severity of the alert

To investigate the severity of the alert, we can use the "kibana.alert.severity" field and search for logs that match the following query:

kibana.alert.severity: "critical"

This will return all logs where the kibana.alert.severity contains the string "critical". We can further filter the results by using time range and hostname if needed.

Step 5: Investigate the risk score of the alert

To investigate the risk score of the alert, we can use the "kibana.alert.risk_score" field and search for logs that match the following query:

kibana.alert.risk_score: 99

This will return all logs where the kibana.alert.risk_score is equal to 99. We can further filter the results by using time range and hostname if needed.

Step 6: Investigate the rule ID of the alert

To investigate the rule ID of the alert, we can use the "kibana.alert.rule.rule_id" field and search for logs that match the following query:

kibana.alert.rule.rule_id: "9a1a2dae-0b5f-4c3d-8305-a268d404c306"

This will return all logs where the kibana.alert.rule.rule_id is equal to "9a1a2dae-0b5f-4c3d-8305-a268d404c306". We can further filter the results by using time range and hostname if needed.

Total estimated cost for all API calls: $0.0007
```
2. With debug flag
```
$ python3 sibyl-gpt.py --debug                   
Status code: 200
[1] Malware Detection Alert, Severity: critical
[2] Parent Process PID Spoofing, Severity: high
[3] Potential Invoke-Mimikatz PowerShell Script, Severity: high
[4] Suspicious PrintSpooler Service Executable File Creation, Severity: high

> Enter the number of the alert you'd like to investigate (1-4), 'H' for hint (sends the alert selection to OpenAI) or 'Q' to quit: 4

[1] Suspicious PrintSpooler Service Executable File Creation, Severity: high, Description: file event with process spoolsv.exe, file tsprint.dll, by SYSTEM on atomicfirefly-windows created high alert Suspicious PrintSpooler Service Executable File Creation.

> Enter the number of the alert you'd like to investigate (1-1), 'H' for hint (sends the alert selection to OpenAI) or 'Q' to quit: 1

OpenAI API request:
Model: gpt-3.5-turbo
Messages: Suggested investigation and remediation for the alert:
{'kibana.alert.start': '2023-05-06T21:40:01.031Z', 'kibana.alert.rule.name': 'Suspicious PrintSpooler Service Executable File Creation', 'host': {'hostname': 'atomicfirefly-windows', 'os': {'Ext': {'variant': 'Windows 10 Enterprise Evaluation'}, 'kernel': '21H2 (10.0.19044.2846)', 'name': 'Windows', 'family': 'windows', 'type': 'windows', 'version': '21H2 (10.0.19044.2846)', 'platform': 'windows', 'full': 'Windows 10 Enterprise Evaluation 21H2 (10.0.19044.2846)'}, 'ip': ['10.0.2.15', 'fe80::f44e:5074:2e05:6e0b', '192.168.56.30', 'fe80::a929:789f:8f07:6356', '127.0.0.1', '::1'], 'name': 'atomicfirefly-windows', 'id': '72734f24-37d9-436d-8a41-6b286ecc6fbf', 'architecture': 'x86_64'}, 'kibana.alert.reason': 'file event with process spoolsv.exe, file tsprint.dll, by SYSTEM on atomicfirefly-windows created high alert Suspicious PrintSpooler Service Executable File Creation.', 'kibana.alert.severity': 'high', 'kibana.alert.risk_score': 73, 'kibana.alert.rule.description': "Detects attempts to exploit privilege escalation vulnerabilities related to the Print Spooler service. For more information refer to the following CVE's - CVE-2020-1048, CVE-2020-1337 and CVE-2020-1300 and verify that the impacted system is patched.", 'kibana.alert.rule.rule_id': '5bb4a95d-5a08-48eb-80db-4c3a63ec78a8', 'kibana.alert.rule.threat': [{'framework': 'MITRE ATT&CK', 'tactic': {'reference': 'https://attack.mitre.org/tactics/TA0004/', 'name': 'Privilege Escalation', 'id': 'TA0004'}, 'technique': [{'reference': 'https://attack.mitre.org/techniques/T1068/', 'name': 'Exploitation for Privilege Escalation', 'id': 'T1068'}]}]}

Suggested investigation and remediation for the alert:

Debug mode: Skipping API call

OpenAI API request:
Model: gpt-3.5-turbo
Messages: Thinking step by step create and justify Kibana searches to investigate:
{'kibana.alert.start': '2023-05-06T21:40:01.031Z', 'kibana.alert.rule.name': 'Suspicious PrintSpooler Service Executable File Creation', 'host': {'hostname': 'atomicfirefly-windows', 'os': {'Ext': {'variant': 'Windows 10 Enterprise Evaluation'}, 'kernel': '21H2 (10.0.19044.2846)', 'name': 'Windows', 'family': 'windows', 'type': 'windows', 'version': '21H2 (10.0.19044.2846)', 'platform': 'windows', 'full': 'Windows 10 Enterprise Evaluation 21H2 (10.0.19044.2846)'}, 'ip': ['10.0.2.15', 'fe80::f44e:5074:2e05:6e0b', '192.168.56.30', 'fe80::a929:789f:8f07:6356', '127.0.0.1', '::1'], 'name': 'atomicfirefly-windows', 'id': '72734f24-37d9-436d-8a41-6b286ecc6fbf', 'architecture': 'x86_64'}, 'kibana.alert.reason': 'file event with process spoolsv.exe, file tsprint.dll, by SYSTEM on atomicfirefly-windows created high alert Suspicious PrintSpooler Service Executable File Creation.', 'kibana.alert.severity': 'high', 'kibana.alert.risk_score': 73, 'kibana.alert.rule.description': "Detects attempts to exploit privilege escalation vulnerabilities related to the Print Spooler service. For more information refer to the following CVE's - CVE-2020-1048, CVE-2020-1337 and CVE-2020-1300 and verify that the impacted system is patched.", 'kibana.alert.rule.rule_id': '5bb4a95d-5a08-48eb-80db-4c3a63ec78a8', 'kibana.alert.rule.threat': [{'framework': 'MITRE ATT&CK', 'tactic': {'reference': 'https://attack.mitre.org/tactics/TA0004/', 'name': 'Privilege Escalation', 'id': 'TA0004'}, 'technique': [{'reference': 'https://attack.mitre.org/techniques/T1068/', 'name': 'Exploitation for Privilege Escalation', 'id': 'T1068'}]}]}

Thinking step by step create and justify Kibana searches to investigate:

Debug mode: Skipping API call 

Total estimated cost for all API calls: $0.0008
```
3. With a hint, using GPT-4, and saving the output to a file
```
$ python3 sibyl-gpt.py --g4 --save
[1] Malware Detection Alert, Severity: critical
[2] Parent Process PID Spoofing, Severity: high
[3] Potential Invoke-Mimikatz PowerShell Script, Severity: high
[4] Suspicious PrintSpooler Service Executable File Creation, Severity: high

> Enter the number of the alert you'd like to investigate (1-4), 'H' for hint (sends the alert selection to OpenAI) or 'Q' to quit: 1

[1] Malware Detection Alert, Severity: critical, Description: malware, intrusion_detection, file event with process powershell.exe, parent process powershell.exe, file PotentiallyUnwanted.exe, by vagrant on atomicfirefly-windows created critical alert Malware Detection Alert.
[2] Malware Detection Alert, Severity: critical, Description: malware, intrusion_detection, process event with process PotentiallyUnwanted.exe, parent process powershell.exe, file PotentiallyUnwanted.exe, by vagrant on atomicfirefly-windows created critical alert Malware Detection Alert.
[3] Malware Detection Alert, Severity: critical, Description: malware, intrusion_detection, process event with process PotentiallyUnwanted.exe, parent process powershell.exe, file PotentiallyUnwanted.exe, by vagrant on atomicfirefly-windows created critical alert Malware Detection Alert.
[4] Malware Detection Alert, Severity: critical, Description: malware, intrusion_detection, file event with process powershell.exe, parent process powershell.exe, file PotentiallyUnwanted.exe, by vagrant on atomicfirefly-windows created critical alert Malware Detection Alert.
[5] Malware Detection Alert, Severity: critical, Description: malware, intrusion_detection, file event with process svchost.exe, parent process services.exe, file BIT9AEB.tmp, by SYSTEM on atomicfirefly-windows created critical alert Malware Detection Alert.
[6] Malware Detection Alert, Severity: critical, Description: malware, intrusion_detection, file event with process svchost.exe, parent process services.exe, file Backstab64.exe, by SYSTEM on atomicfirefly-windows created critical alert Malware Detection Alert.
[7] Malware Detection Alert, Severity: critical, Description: malware, intrusion_detection, process event with process Backstab64.exe, parent process powershell.exe, file Backstab64.exe, by vagrant on atomicfirefly-windows created critical alert Malware Detection Alert.

> Enter the number of the alert you'd like to investigate (1-7), 'H' for hint (sends the alert selection to OpenAI) or 'Q' to quit: h

Hint: Option 6: Malware Detection Alert, Severity: critical, Description: malware, intrusion_detection, file event with process svchost.exe, parent process services.exe, file Backstab64.exe, by SYSTEM on atomicfirefly-windows created critical alert Malware Detection Alert.

This option should be investigated first because it involves a known malicious file (Backstab64.exe) which is being executed by a critical system process (svchost.exe) under the SYSTEM account, indicating a higher likelihood of a serious system compromise.

Total estimated cost for hint API call: $0.0171

> Enter the number of the alert you'd like to investigate (1-7), 'H' for hint (sends the alert selection to OpenAI) or 'Q' to quit: 6

Suggested investigation and remediation for the alert:

Based on the provided alert, it appears that there is a potential malware infection on the host 'atomicfirefly-windows'. The suspicious process detected is 'svchost.exe' with arguments related to 'BITS', and the  
file 'Backstab64.exe' has also been flagged. The alert has a critical severity with a risk score of 99.

Here are some suggested steps for investigation and remediation:

  1 Isolate the affected system from the network to prevent potential lateral movement or data exfiltration.
  2 Perform a full antimalware scan on the affected system using an updated antivirus solution.
  3 Search for and remove any instances of 'Backstab64.exe' and other suspicious files.
  4 Analyze the 'svchost.exe' process to check for injected or disguised malicious code. Ensure that it is running from the correct location (C:\Windows\System32) and confirm its legitimacy.
  5 Review event logs and process monitoring tools for any suspicious activity or connections, keeping an eye out for recently executed commands, newly created accounts, or unauthorized remote access attempts.
  6 If any accounts were found compromised during the investigation, reset their credentials and enforce strong authentication mechanisms, such as multi-factor authentication.
  7 Implement and update security policies for systems and network devices, ensuring user permissions are properly configured and least privilege principles are followed.
  8 Patch and update all software, operating systems, and security tools installed on the affected system to protect against future attacks.
  9 Educate end-users about potential risks and best practices to maintain a secure environment, including recognizing and avoiding phishing emails and malicious attachments.
 10 Regularly monitor systems and network devices for signs of suspicious activity. Consider deploying an intrusion detection system (IDS) or security information and event management (SIEM) software for a more   
    proactive security approach.

After carrying out these steps, continue to monitor the system and network to ensure that the malware has been successfully removed and no further suspicious activity is detected.

Thinking step by step create and justify Kibana searches to investigate:

Step 1: Investigate the Malware Detection Alert Firstly, we want to focus on the malware detection alert and examine the details of the generated warning. To do this, we can create a search in Kibana that looks
for alerts with the specific rule name "Malware Detection Alert".

Search: kibana.alert.rule.name: "Malware Detection Alert"

Step 2: Narrow down to the specific alert time We want to investigate the specific alert that started at '2023-05-06T21:48:21.035Z'. To filter the search results to this exact alert, add a timestamp filter to the 
search.

Search: kibana.alert.rule.name: "Malware Detection Alert" AND kibana.alert.start: "2023-05-06T21:48:21.035Z"

Step 3: Investigate the process arguments involved To understand the cause of the malware alert, we need to investigate the process arguments involved in triggering the alert. Add the 'process.args' field to the  
search query.

Search: kibana.alert.rule.name: "Malware Detection Alert" AND kibana.alert.start: "2023-05-06T21:48:21.035Z" AND process.args: "*"

Step 4: Identify the host where the alert was triggered To further investigate the malware alert, we need to identify the host where the alert was generated. Add the 'host.name' field to the search query.         

Search: kibana.alert.rule.name: "Malware Detection Alert" AND kibana.alert.start: "2023-05-06T21:48:21.035Z" AND process.args: "*" AND host.name: "atomicfirefly-windows"                                            

Step 5: Investigate the severity and risk score of the alert Next, we want to understand the severity of the alert and its risk score. Add the 'kibana.alert.severity' and 'kibana.alert.risk_score' fields to the   
search query.

Search: kibana.alert.rule.name: "Malware Detection Alert" AND kibana.alert.start: "2023-05-06T21:48:21.035Z" AND process.args: "*" AND host.name: "atomicfirefly-windows" AND kibana.alert.severity: "critical" AND  
kibana.alert.risk_score: 99

Step 6: Investigate the alert's rule description Lastly, to better understand the context of the alert, we want to investigate its rule description. Add the 'kibana.alert.rule.description' field to the search     
query.

Search: kibana.alert.rule.name: "Malware Detection Alert" AND kibana.alert.start: "2023-05-06T21:48:21.035Z" AND process.args: "*" AND host.name: "atomicfirefly-windows" AND kibana.alert.severity: "critical" AND  
kibana.alert.risk_score: 99 AND kibana.alert.rule.description: "*"

This Kibana search will provide information on the specific malware detection alert, including details about the process arguments, the host where the alert was generated, its severity and risk score, and the rule
description. By analyzing the search results, we can better understand the circumstances that led to the alert and develop appropriate remediation strategies.

Total estimated cost for all API calls: $0.0202

The OpenAI output and inputs have been saved to openai_output_gpt-4_20230508-103004.txt
```
4. With a min risk of 0 (will show all alerts)
```
$ python3 sibyl-gpt.py --risk 0
[1] Malware Detection Alert, Severity: critical
[2] Parent Process PID Spoofing, Severity: high
[3] Potential Invoke-Mimikatz PowerShell Script, Severity: high
[4] Suspicious PrintSpooler Service Executable File Creation, Severity: high
[5] Account Configured with Never-Expiring Password, Severity: medium
[6] Enumeration of Privileged Local Groups Membership, Severity: medium
[7] First Time Seen Driver Loaded, Severity: medium
[8] LSASS Process Access via Windows API, Severity: medium
[9] Potential PowerShell HackTool Script by Function Names, Severity: medium
[10] Potential Process Injection via PowerShell, Severity: medium
[11] PowerShell PSReflect Script, Severity: medium
[12] PowerShell Script with Token Impersonation Capabilities, Severity: medium
[13] Remote File Download via PowerShell, Severity: medium
[14] Suspicious Portable Executable Encoded in Powershell Script, Severity: medium
[15] System Shells via Services, Severity: medium
[16] Unusual Parent-Child Relationship, Severity: medium
[17] User Added to Privileged Group, Severity: medium
[18] Connection to Commonly Abused Web Services, Severity: low
[19] Ingress Transfer via Windows BITS, Severity: low
[20] Local Scheduled Task Creation, Severity: low
[21] My First Rule, Severity: low
[22] Service Control Spawned via Script Interpreter, Severity: low
[23] Startup or Run Key Registry Modification, Severity: low
[24] Unusual Persistence via Services Registry, Severity: low
[25] User Account Creation, Severity: low
[26] Whoami Process Activity, Severity: low

> Enter the number of the alert you'd like to investigate (1-26), 'H' for hint (sends the alert selection to OpenAI) or 'Q' to quit: q

Quitting the script. Bye!
```

## References

- [Auto-GPT](https://github.com/Significant-Gravitas/Auto-GPT)  
- [Mika's article](https://www.elastic.co/security-labs/exploring-applications-of-chatgpt-to-improve-detection-response-and-understanding)  
- [Mika's code](https://gist.github.com/Mikaayenson/9efff700e5d799c672c6b17338d2de6a)