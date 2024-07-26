# KQL Alerts for Microsoft Sentinel

![Untitled](https://github.com/jsom98/Pictures/blob/main/Screenshot%202024-02-07%20190105.png)

**Test Brute Force Attempt – Windows:**

KQL:
```
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(60m)
| summarize FailureCount = count() by AttackerIP = IpAddress, EventID, Activity, DestinationHostName = Computer
| where FailureCount >= 10
```
Description:

The provided KQL query is designed to identify potential brute force attacks on Windows hosts. It filters the security events based on the event ID (4625), which represents a failed login attempt. The query then groups the data by the attacker's IP address, event ID, activity, and destination host name. It also counts the number of failures for each group. Finally, the query filters the grouped data to only include groups with a failure count of 10 or more, indicating potential brute force attacks.

Response Actions:

- Block the IP address at the firewall: If the IP address is external to your network, you may consider blocking it at the firewall to prevent further failed login attempts.
- Monitor the IP address: Keep an eye on the IP address to see if there are any further failed or successful login attempts.
- Investigate the source of the IP address: Use threat intelligence tools such as [https://www.abuseipdb.com/](https://www.abuseipdb.com/) and [https://viz.greynoise.io/](https://viz.greynoise.io/) to determine if the IP address is known to be malicious or associated with any known threats.
- Notify the user: If the IP address is internal to your network, notify the user associated with the IP address and ask them to change their password, as it may have been compromised.
- Implement multi-factor authentication: If you haven't already, consider implementing multi-factor authentication to prevent unauthorized access.

**Personalized: Possible Lateral Movement (Excessive Password Resets):**

KQL:
```
AuditLogs
| where OperationName startswith "Change" or OperationName startswith "Reset"
| order by TimeGenerated
| summarize count() by tostring(InitiatedBy)
| project Count = count_, InitiatorId = parse_json(InitiatedBy).user.id, InitiatorUpn = parse_json(InitiatedBy).user.userPrincipalName, InitiatorIpAddress = parse_json(InitiatedBy).user.ipAddress
| where Count >= 10
```
Description:

The provided KQL query is designed to identify users who have initiated multiple "Change" or "Reset" operations in Azure Active Directory (AAD). It filters the audit logs based on the OperationName property, which starts with either "Change" or "Reset". The query then orders the data by the TimeGenerated property in ascending order. It then groups the data by the user ID of the user who initiated the operation and counts the number of occurrences.The query then uses the parse_json() function to extract the user ID, user principal name, and IP address from the InitiatedBy property. These values are then projected into separate columns.Finally, the query filters the grouped data to only include users who have initiated 10 or more operations. This indicates potential suspicious activity, such as a user attempting to modify multiple accounts or resources.

Response Actions:

- Investigate the user: Check if the user who initiated the changes or resets is a legitimate user or a potential attacker. You can do this by checking the user's IP address, user principal name (UPN), and other relevant information.
- Review the changes made: Analyze the changes made by the user to determine if they were malicious or legitimate. You can do this by reviewing the logs and identifying any suspicious activities.
- Implement additional security measures: Based on the analysis of the logs, implement additional security measures to prevent future attacks. This may include blocking suspicious IP addresses, implementing multi-factor authentication (MFA), or limiting user access to specific resources.
- Monitor user activity: Continuously monitor the user's activity to detect any suspicious behavior. This can be done by setting up alerts in Azure Sentinel or Azure Monitor that trigger when specific activities are detected.
- Educate users: Educate users about the importance of security and the potential consequences of performing unauthorized activities. This can help reduce the risk of users inadvertently causing security incidents.

**Personalized: Brute Force ATTEMPT - Linux Syslog:**

KQL:
```
// Brute Force Success Linux
let IpAddress_REGEX_PATTERN = @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b";
Syslog
| where Facility == "auth" and SyslogMessage startswith "Failed password for"
| where TimeGenerated > ago(1h)
| project TimeGenerated, AttackerIP = extract(IpAddress_REGEX_PATTERN, 0, SyslogMessage), DestinationHostName = HostName, DestinationIP = HostIP, Facility, SyslogMessage, ProcessName, SeverityLevel, Type
| summarize FailureCount = count() by AttackerIP, DestinationHostName, DestinationIP
| where FailureCount >= 10
```
Description:

The provided KQL query is designed to identify potential brute force attacks on Linux hosts that have successfully logged in. It defines a regular expression pattern for IP addresses and extracts the attacker's IP address from the SyslogMessage property using the extract() function. The query filters the Syslog data based on the Facility property, which should be "auth", and the message should start with "Failed password for". The query then filters the data to only include events that occurred within the last hour. The query then groups the data by the attacker's IP address, destination host name, and destination IP address. It counts the number of failures for each group. Finally, the query filters the grouped data to only include groups with a failure count of 10 or more. This indicates potential brute force attacks that have successfully logged in.

Response Actions:

- Block IP Addresses: Block the IP addresses of the attackers in your firewall. This will prevent them from attempting further login attempts.
- Update Security Measures: Update your security measures to prevent brute force attacks. This may include implementing stronger password policies, limiting login attempts, or using multi-factor authentication.
- Inform the Users: Inform the affected users about the attack and recommend them to change their passwords. This will help prevent further damage to the system.
- Implement a Response Plan: Develop a response plan to handle brute force attacks. This plan should include steps to detect, respond to, and recover from such attacks.
- Perform a Post-Attack Analysis: After the attack has been mitigated, perform a post-attack analysis to identify the root cause of the attack and implement measures to prevent similar attacks in the future.

**Personalized: Brute Force ATTEMPT - Azure Active Directory:**

KQL:
```
SigninLogs
| where ResultDescription == "Invalid username or password or Invalid on-premise username or password."
| project TimeGenerated, ResultDescription, UserPrincipalName, UserId, AppDisplayName, IPAddress, IPAddressFromResourceProvider, City = LocationDetails.city, State = LocationDetails.state, Country = LocationDetails.country, Latitude = LocationDetails.geoCoordinates.latitude, Longitude = LocationDetails.geoCoordinates.longitude
```
Description:

The provided KQL query is designed to investigate failed sign-in attempts in Azure Active Directory (AAD). It filters the sign-in logs based on the ResultDescription property, which should be "Invalid username or password or Invalid on-premise username or password.". The query then projects the following properties into the output: TimeGenerated, ResultDescription, UserPrincipalName, UserId, AppDisplayName, IPAddress, IPAddressFromResourceProvider, City, State, Country, Latitude, and Longitude. The City, State, Country, Latitude, and Longitude properties are extracted from the LocationDetails property using the dot notation.

Response Actions:

- Monitor User Activity: Monitor the activity of the affected users. This will help you identify any suspicious activity or patterns in the user behavior.
- Enforce Strong Password Policies: Enforce strong password policies to ensure that users have strong and unique passwords. This will help prevent unauthorized access.
- Implement Multi-Factor Authentication: Implement multi-factor authentication to ensure that only authorized users can access the system. This will help prevent unauthorized access.
- Limit Login Attempts: Limit the number of login attempts for each user. This will help prevent brute force attacks.
- Educate Users on Security: Educate your users on the importance of security and the steps they can take to protect the system. This will help prevent attacks, including attacks targeting user accounts.

**Personalized: Brute Force ATTEMPT – Windows:**

KQL:
```
// Failed logon
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(60m)
| summarize FailureCount = count() by AttackerIP = IpAddress, EventID, Activity, DestinationHostName = Computer
| where FailureCount >= 10
```
Description:

The provided KQL query is designed to identify potential brute force attacks on Windows hosts. It filters the security events based on the EventID property, which should be 4625, which indicates a failed logon attempt. The query then filters the data to only include events that occurred within the last 60 minutes. The query then groups the data by the attacker's IP address, event ID, activity, and destination host name, and counts the number of failures for each group. Finally, the query filters the grouped data to only include groups with a failure count of 10 or more. This indicates potential brute force attacks.

Response Actions:

- Block IP Addresses: Block the IP addresses of the attackers in your firewall. This will prevent them from attempting further login attempts.
- Monitor and Analyze: Continuously monitor the logs for any suspicious activity. This will help you identify any new attackers or patterns in the attacks.
- Update Security Measures: Update your security measures to prevent failed logon attempts. This may include implementing stronger password policies, limiting login attempts, or using multi-factor authentication.
- Contact the System Administrator: Notify the system administrator of the attack and the affected hosts. This will help them take appropriate actions to secure the system.
- Implement a Response Plan: Develop a response plan to handle failed logon attempts. This plan should include steps to detect, respond to, and recover from such attacks.

**Personalized: Brute Force ATTEMPT - MS SQL Server:**

KQL:
```
// Brute Force Attempt MS SQL Server
let IpAddress_REGEX_PATTERN = @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b";
Event
| where EventLog == "Application"
| where EventID == 18456
| where TimeGenerated > ago(1hr)
| project TimeGenerated, AttackerIP = extract(IpAddress_REGEX_PATTERN, 0, RenderedDescription), DestinationHostName = Computer, RenderedDescription
| summarize FailureCount = count() by AttackerIP, DestinationHostName
| where FailureCount >= 3
```
Description:

The provided KQL query is designed to identify potential brute force attacks on Microsoft SQL Server. It defines a regular expression pattern for IP addresses and extracts the attacker's IP address from the RenderedDescription property using the extract() function. The query filters the event data based on the EventLog property, which should be "Application", and the EventID property, which should be 18456, which indicates a failed logon attempt. The query then filters the data to only include events that occurred within the last hour. The query then groups the data by the attacker's IP address, destination host name, and counts the number of failures for each group. Finally, the query filters the grouped data to only include groups with a failure count of 3 or more. This indicates potential brute force attacks.

Response Actions:

- Block IP Addresses: Block the IP addresses of the attackers in your firewall. This will prevent them from attempting further login attempts.
- Monitor and Analyze: Continuously monitor the logs for any suspicious activity. This will help you identify any new attackers or patterns in the attacks.
- Update Security Measures: Update your security measures to prevent brute force attacks. This may include implementing stronger password policies, limiting login attempts, or using multi-factor authentication.
- Contact the System Administrator: Notify the system administrator of the attack and the affected hosts. This will help them take appropriate actions to secure the system.
- Implement a Response Plan: Develop a response plan to handle brute force attacks. This plan should include steps to detect, respond to, and recover from such attacks.

**Personalized: Brute Force ATTEMPT - Azure Key Vault:**

KQL:
```
// Failed access attempts
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where ResultSignature == "Forbidden"
```
Description:

The provided KQL query is designed to identify failed access attempts in Azure Key Vault. It filters the AzureDiagnostics table based on the ResourceProvider property, which should be "MICROSOFT.KEYVAULT", and the ResultSignature property, which should be "Forbidden". This indicates that the access attempt was denied due to insufficient permissions.

Response Actions:

- Investigate and Identify: Investigate and identify the cause of the failed access attempts. This could include reviewing logs, monitoring user activity, and conducting an analysis of the system.
- Update Security Measures: Update your security measures to prevent failed access attempts. This may include implementing stronger access policies, limiting access attempts, or using multi-factor authentication.
- Contact the System Administrator: Notify the system administrator of the failed access attempts and the affected resources. This will help them take appropriate actions to secure the system.
- Implement a Response Plan: Develop a response plan to handle failed access attempts. This plan should include steps to detect, respond to, and recover from such incidents.
- Educate Users on Security: Educate your users on the importance of security and the steps they can take to protect the system. This will help prevent attacks, including attacks targeting the system's resources.

**Personalized: Windows Host Firewall Tampering**

KQL:
```
Event
| where EventLog == "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
| where EventID == 2003
```
Description:

The provided KQL query is designed to identify blocked incoming connections in the Windows Firewall. It filters the Event table based on the EventLog property, which should be "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", and the EventID property, which should be 2003. This indicates that the incoming connection was blocked by the Windows Firewall.

Response Actions:

- Investigate and Identify: Investigate and identify the cause of the blocked traffic. This could include reviewing logs, monitoring network activity, and conducting an analysis of the system.
- Update Security Measures: Update your security measures to prevent blocked traffic. This may include implementing stronger access policies, limiting access attempts, or using multi-factor authentication.
- Contact the System Administrator: Notify the system administrator of the blocked traffic and the affected hosts. This will help them take appropriate actions to secure the system.
- Implement a Response Plan: Develop a response plan to handle blocked traffic. This plan should include steps to detect, respond to, and recover from such incidents.
- Educate Users on Security: Educate your users on the importance of security and the steps they can take to protect the system. This will help prevent attacks, including attacks targeting the system's resources.

**Personalized: Brute Force SUCCESS - Linux Syslog:**

KQL:
```
// Brute Force Success Linux
let FailedLogons = Syslog
| where Facility == "auth" and SyslogMessage startswith "Failed password for"
| where TimeGenerated > ago(1h)
| project TimeGenerated, SourceIP = extract(@"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", 0, SyslogMessage), DestinationHostName = HostName, DestinationIP = HostIP, Facility, SyslogMessage, ProcessName, SeverityLevel, Type
| summarize FailureCount = count() by AttackerIP = SourceIP, DestinationHostName
| where FailureCount >= 5;
let SuccessfulLogons = Syslog
| where Facility == "auth" and SyslogMessage startswith "Accepted password for"
| where TimeGenerated > ago(1h)
| project TimeGenerated, SourceIP = extract(@"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", 0, SyslogMessage), DestinationHostName = HostName, DestinationIP = HostIP, Facility, SyslogMessage, ProcessName, SeverityLevel, Type
| summarize SuccessfulCount = count() by SuccessTime = TimeGenerated, AttackerIP = SourceIP, DestinationHostName
| where SuccessfulCount >= 1
| project DestinationHostName, SuccessfulCount, AttackerIP, SuccessTime;
let BruteForceSuccesses = SuccessfulLogons
| join kind = inner FailedLogons on AttackerIP, DestinationHostName;
BruteForceSuccesses
```
Description:

The provided KQL query is designed to identify brute force attacks on Linux systems that have successfully logged in. It defines two variables, FailedLogons and SuccessfulLogons, and then combines them to identify brute force attacks. The FailedLogons variable filters the Syslog table based on the Facility property, which should be "auth", and the SyslogMessage property, which should start with "Failed password for". It then filters the data to only include events that occurred within the last hour. The variable then groups the data by the source IP address, destination host name, and counts the number of failures for each group. The SuccessfulLogons variable filters the Syslog table based on the Facility property, which should be "auth", and the SyslogMessage property, which should start with "Accepted password for". It then filters the data to only include events that occurred within the last hour. The variable then groups the data by the time generated, source IP address, destination host name, and counts the number of successful logons for each group. The BruteForceSuccesses variable combines the FailedLogons and SuccessfulLogons variables to identify brute force attacks. It performs an inner join on the AttackerIP and DestinationHostName properties of the two variables.

Response Actions:

- Investigate and Identify: Investigate and identify the cause of the brute force success event. This could include reviewing logs, monitoring user activity, and conducting an analysis of the system.
- Update Security Measures: Update your security measures to prevent brute force attacks. This may include implementing stronger password policies, limiting login attempts, or using multi-factor authentication.
- Contact the System Administrator: Notify the system administrator of the brute force success event and the affected hosts. This will help them take appropriate actions to secure the system.
- Implement a Response Plan: Develop a response plan to handle brute force success events. This plan should include steps to detect, respond to, and recover from such incidents.
- Perform a Post-Attack Analysis: Perform a post-attack analysis to identify the root cause of the attack and implement measures to prevent similar attacks in the future.

**Personalized: Possible Privilege Escalation (Azure Key Vault Critical Credential Retrieval or Update):**

KQL:
```
// Updating a specific existing password Success
let CRITICAL_PASSWORD_NAME = "Tenant-Global-Admin-Password";
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName == "SecretGet" or OperationName == "SecretSet"
| where id_s contains CRITICAL_PASSWORD_NAME
```
Description:

The provided KQL query is designed to identify successful updates to a specific existing password in Azure Key Vault. It defines a variable, CRITICAL_PASSWORD_NAME, which is set to the name of the sensitive password. The query then filters the AzureDiagnostics table based on the ResourceProvider property, which should be "MICROSOFT.KEYVAULT", and the OperationName property, which should be either "SecretGet" or "SecretSet". It then filters the data to only include events where the id_s property contains the name of the sensitive password.

Possible Response Actions:

- Review the Event: Review the event to determine the purpose of the password update. This could include reviewing logs, monitoring user activity, and conducting an analysis of the system.
- Verify User Identity: Verify the identity of the user who performed the password update. This will help ensure that the password update was performed by an authorized user.
- Monitor System Activity: Monitor the system activity for any suspicious activity. This will help you detect and respond to any potential attacks or unauthorized access attempts.
- Update Security Measures: Update your security measures to prevent unauthorized password updates. This may include implementing stronger access policies, limiting access attempts, or using multi-factor authentication.
- Implement a Response Plan: Develop a response plan to handle password updates. This plan should include steps to detect, respond to, and recover from such incidents.

**Personalized: Brute Force SUCCESS – Windows:**

KQL:
```
// Brute Force Success Windows
let FailedLogons = SecurityEvent
| where EventID == 4625 and LogonType == 3
| where TimeGenerated > ago(1h)
| summarize FailureCount = count() by AttackerIP = IpAddress, EventID, Activity, LogonType, DestinationHostName = Computer
| where FailureCount >= 5;
let SuccessfulLogons = SecurityEvent
| where EventID == 4624 and LogonType == 3
| where TimeGenerated > ago(1h)
| summarize SuccessfulCount = count() by AttackerIP = IpAddress, LogonType, DestinationHostName = Computer, AuthenticationSuccessTime = TimeGenerated;
SuccessfulLogons
| join kind = inner FailedLogons on DestinationHostName, AttackerIP, LogonType
| project AuthenticationSuccessTime, AttackerIP, DestinationHostName, FailureCount, SuccessfulCount
```
Description:

The provided KQL query is designed to identify successful logons following a series of failed logon attempts on Windows systems, which may indicate a brute force attack. It defines two variables, FailedLogons and SuccessfulLogons, and then combines them to identify successful logons following a series of failed logons. The FailedLogons variable filters the SecurityEvent table based on the EventID property, which should be 4625, and the LogonType property, which should be 3. It then filters the data to only include events that occurred within the last hour. The variable then groups the data by the attacker's IP address, event ID, activity, logon type, and destination host name, and counts the number of failures for each group. The SuccessfulLogons variable filters the SecurityEvent table based on the EventID property, which should be 4624, and the LogonType property, which should be 3. It then filters the data to only include events that occurred within the last hour. The variable then groups the data by the attacker's IP address, logon type, destination host name, and successful logon time. The final line of the query combines the FailedLogons and SuccessfulLogons variables to identify successful logons following a series of failed logons. It performs an inner join on the DestinationHostName, AttackerIP, and LogonType properties of the two variables.

Possible Response Actions:

- Investigate and Identify: Investigate and identify the cause of the brute force success event. This could include reviewing logs, monitoring user activity, and conducting an analysis of the system.
- Update Security Measures: Update your security measures to prevent brute force attacks. This may include implementing stronger password policies, limiting login attempts, or using multi-factor authentication.
- Contact the System Administrator: Notify the system administrator of the brute force success event and the affected hosts. This will help them take appropriate actions to secure the system.
- Implement a Response Plan: Develop a response plan to handle brute force success events. This plan should include steps to detect, respond to, and recover from such incidents.
- Perform a Post-Attack Analysis: Perform a post-attack analysis to identify the root cause of the attack and implement measures to prevent similar attacks in the future.

**Personalized: Malware Detected:**

KQL:
```
Event
| where EventLog == "Microsoft-Windows-Windows Defender/Operational"
| where EventID == "1116" or EventID == "1117"
```
Description:

This KQL query filters events from the Windows Defender operational log with either EventID 1116 or 1117. Event ID 1116 is generated when Windows Defender starts a full scan or a scan triggered by a scheduled task or command-line request. Event ID 1117 is generated when Windows Defender completes a full scan or a scan triggered by a scheduled task or command-line request.

Possible Response Actions:

- Investigate and Identify: Investigate and identify the cause of the Windows Defender event. This could include reviewing logs, monitoring system activity, and conducting an analysis of the system.
- Update Security Measures: Update your security measures to prevent malware and other threats. This may include implementing stronger access policies, limiting access attempts, or using multi-factor authentication.
- Contact the System Administrator: Notify the system administrator of the Windows Defender event and the affected hosts. This will help them take appropriate actions to secure the system.
- Implement a Response Plan: Develop a response plan to handle Windows Defender events. This plan should include steps to detect, respond to, and recover from such incidents.
- Perform a Post-Attack Analysis: Perform a post-attack analysis to identify the root cause of the threat and implement measures to prevent similar threats in the future.

**Personalized: Brute Force SUCCESS - Azure Active Directory:**

KQL:
```
// Failed AAD logon
let FailedLogons = SigninLogs
| where Status.failureReason == "Invalid username or password or Invalid on-premise username or password."
| where TimeGenerated > ago(1h)
| project TimeGenerated, Status = Status.failureReason, UserPrincipalName, UserId, UserDisplayName, AppDisplayName, AttackerIP = IPAddress, IPAddressFromResourceProvider, City = LocationDetails.city, State = LocationDetails.state, Country = LocationDetails.country, Latitude = LocationDetails.geoCoordinates.latitude, Longitude = LocationDetails.geoCoordinates.longitude
| summarize FailureCount = count() by AttackerIP, UserPrincipalName;
let SuccessfulLogons = SigninLogs
| where Status.errorCode == 0
| where TimeGenerated > ago(1h)
| project TimeGenerated, Status = Status.errorCode, UserPrincipalName, UserId, UserDisplayName, AppDisplayName, AttackerIP = IPAddress, IPAddressFromResourceProvider, City = LocationDetails.city, State = LocationDetails.state, Country = LocationDetails.country, Latitude = LocationDetails.geoCoordinates.latitude, Longitude = LocationDetails.geoCoordinates.longitude
| summarize SuccessCount = count() by AuthenticationSuccessTime = TimeGenerated, AttackerIP, UserPrincipalName, UserId, UserDisplayName;
let BruteForceSuccesses = SuccessfulLogons
| join kind = inner FailedLogons on AttackerIP, UserPrincipalName;
BruteForceSuccesses
| project AttackerIP, TargetAccount = UserPrincipalName, UserId, FailureCount, SuccessCount, AuthenticationSuccessTime
```
Description:

This KQL query is designed to identify brute force attacks on Azure Active Directory (AAD) accounts based on failed and successful sign-in attempts. It defines two variables, FailedLogons and SuccessfulLogons, and then combines them to identify successful logons following a series of failed logons. The FailedLogons variable filters the SigninLogs table based on the failureReason property, which should be "Invalid username or password or Invalid on-premise username or password.". It then filters the data to only include events that occurred within the last hour. The variable then groups the data by the attacker's IP address, user principal name, and counts the number of failures for each group. The SuccessfulLogons variable filters the SigninLogs table based on the errorCode property, which should be 0, indicating a successful sign-in attempt. It then filters the data to only include events that occurred within the last hour. The variable then groups the data by the successful sign-in time, attacker's IP address, user principal name, user ID, user display name, and counts the number of successful logons for each group. The final line of the query combines the FailedLogons and SuccessfulLogons variables to identify successful logons following a series of failed logons. It performs an inner join on the AttackerIP and UserPrincipalName properties of the two variables.

Possible Response Actions:

- Investigate and Identify: Investigate and identify the cause of the failed AAD logon event. This could include reviewing logs, monitoring user activity, and conducting an analysis of the system.
- Update Security Measures: Update your security measures to prevent failed logons. This may include implementing stronger password policies, limiting login attempts, or using multi-factor authentication.
- Contact the System Administrator: Notify the system administrator of the failed AAD logon event and the affected users. This will help them take appropriate actions to secure the system.
- Implement a Response Plan: Develop a response plan to handle failed logon events. This plan should include steps to detect, respond to, and recover from such incidents.
- Perform a Post-Attack Analysis: Perform a post-attack analysis to identify the root cause of the failed logons and implement measures to prevent similar failures in the future.

**Personalized: Possible Privilege Escalation (Global Administrator Role Assignment):**

KQL:
```
AuditLogs
| where OperationName == "Add member to role" and Result == "success"
| where TargetResources[0].modifiedProperties[1].newValue == '"Global Administrator"' or TargetResources[0].modifiedProperties[1].newValue == '"Company Administrator"' and TargetResources[0].type == "User"
| where TimeGenerated > ago(60m)
| project
TimeGenerated,
OperationName,
AssignedRole = TargetResources[0].modifiedProperties[1].newValue,
Status = Result,
TargetResources,
InitiatorID = InitiatedBy["user"]["id"],
TargetID = TargetResources[0]["id"]
```
Description:

This KQL query filters Azure Active Directory (AAD) audit logs for successful "Add member to role" operations where the assigned role is either "Global Administrator" or "Company Administrator" for a user. It then filters the data to only include events that occurred within the last 60 minutes.

Possible Response Actions:

- Revoke the Global Administrator role from the affected user account immediately if unintended, otherwise skip to the documentation phase.
- Check for any other unauthorized role assignments made by the attacker and revoke them if necessary.
- Identify the root cause of the incident and take corrective actions to prevent similar incidents from occurring in the future.
- Restore any data or system configurations that may have been affected by the incident. This may involve resetting the Global Administrator password for the affected account and updating the secret in Key Vault

**Theory:**

You should always use more than one intelligence source, if you can do so, in order to obtain the most-complete presentation of the facts. They have enhanced the quality of my work on a daily basis.

Ipabused database is crowd sourced so its faster and its also harder to so people can comment on the ip addresses.

GreyNoise Intelligence has a contract with the Department of Defense (DOD) to help reduce alert fatigue from the internet noise that creates false positives within the government's SOCs

