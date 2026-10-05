# Cloud Incident Response: Investigating a Compromised AWS Access Key

**Author:** David Tuala
**Date of incident (simulated):** October 4, 2026
**Status:** Contained and remediated
**Environment:** AWS (Free Plan) · CloudTrail · IAM · S3 · CloudShell

> **Note:** This is a hands-on lab. I built the environment, played the attacker against my own AWS account, and then investigated the activity as a security analyst. All "sensitive" files contained fake data, and the compromised key has been deleted.

---

## 1. Summary

An access key belonging to the IAM user `intern-dev` was used by an "attacker" to explore the AWS account. Using the stolen key, the attacker confirmed whose identity they had, listed the account's S3 buckets, browsed a bucket containing (fake) sensitive data, and downloaded a customer list. The attacker then tried twice to gain more control by creating a new user and listing all users. Both attempts were blocked because the key only had read-only access to S3.

I investigated the activity in AWS CloudTrail across two regions, built a timeline, deactivated the key, verified the attacker was locked out, and deleted the key.

| Item | Detail |
|---|---|
| Incident type | Compromised long-term access key |
| Affected identity | IAM user `intern-dev` |
| Access key | `...QFJO` (now deleted) |
| Permissions on key | `AmazonS3ReadOnlyAccess` |
| Data accessed | `Customer_list.txt` (fake data) |
| Privilege escalation | Attempted, **blocked** |
| Detection method | Manual review of CloudTrail logs |
| Time to containment | About 1 hour 15 minutes after the last malicious action |

---

## 2. Lab Setup

1. **Secured the account** with multi-factor authentication (MFA) before building anything.
2. **Turned on logging** with a multi-region CloudTrail trail (`management-events`) saving logs to a dedicated S3 bucket, with log file validation enabled so the logs can be proven untampered.
3. **Created a target**: an S3 bucket (`david-ir-sensitive-data-2026`) with two fake files, a customer list and a payroll file. Public access was blocked.
4. **Created a victim**: an IAM user `intern-dev` with read-only S3 access and a long-term access key.
5. **Simulated the attack** from AWS CloudShell using the stolen key.

I planned to use Amazon GuardDuty for automated threat detection, but it is not available on the AWS Free Plan, so all detection in this project was done manually from CloudTrail.

---

## 3. Timeline

All times are Central Daylight Time (UTC-5) on October 4, 2026.

| Time | Event | Region | Source IP | Identity | Result |
|---|---|---|---|---|---|
| 1:12:30 AM | `GetCallerIdentity` | us-east-2 | 18.222.138.57 | intern-dev (`...QFJO`) | Succeeded |
| 2:55:02 PM | `GetCallerIdentity` | us-east-2 | 18.118.114.129 | intern-dev (`...QFJO`) | Succeeded |
| 2:55:20 PM | `ListBuckets` | us-east-2 | 18.118.114.129 | intern-dev (`...QFJO`) | Succeeded |
| 3:03:12 PM | `CreateUser` (backdoor-admin) | us-east-1 | 18.118.114.129 | intern-dev (`...QFJO`) | **AccessDenied** |
| 3:04:15 PM | `ListUsers` | us-east-1 | 18.118.114.129 | intern-dev (`...QFJO`) | **AccessDenied** |
| 3:07:17 PM | `ListUsers` | us-east-1 | 18.118.114.129 | intern-dev (`...QFJO`) | **AccessDenied** |
| 4:22:35 PM | `UpdateAccessKey` (deactivate) | us-east-1 | — | Admin (me) | Key disabled |
| 4:48:27 PM | `DeleteAccessKey` | us-east-1 | — | Admin (me) | Key deleted |

**Not visible in CloudTrail:** the attacker also listed the files inside the target bucket and downloaded `Customer_list.txt`. These actions did not appear in the logs (see Section 6, Logging Gap). I know they happened because I performed them during the simulation.

---

## 4. What the Attacker Did

Read in order, the timeline tells a clear story:

1. **Checked the stolen key** (`GetCallerIdentity`): the attacker's first move was to find out whose credentials they had.
2. **Looked for data** (`ListBuckets`): 18 seconds later, they listed every S3 bucket in the account.
3. **Took data**: they browsed the target bucket and downloaded the customer list.
4. **Tried to gain more power** (`CreateUser`): they tried to create a new user called `backdoor-admin`, which would have given them a way back in even after the original key was removed.
5. **Kept trying** (`ListUsers` twice): after being blocked, they tried to list every user in the account, likely looking for a more powerful account to target.

### MITRE ATT&CK mapping

| Technique | ID | Evidence |
|---|---|---|
| Valid Accounts: Cloud Accounts | T1078.004 | Stolen `intern-dev` access key used to sign in |
| Cloud Storage Object Discovery | T1619 | Listed buckets and bucket contents |
| Data from Cloud Storage | T1530 | Downloaded `Customer_list.txt` |
| Create Account: Cloud Account | T1136.003 | `CreateUser` attempt (blocked) |
| Account Discovery: Cloud Account | T1087.004 | `ListUsers` attempts (blocked) |

---

## 5. Indicators of Compromise

- **Access key `...QFJO`** used for discovery and escalation attempts
- **Same key used from two different IP addresses** (18.222.138.57 and 18.118.114.129), about 14 hours apart. Both addresses belong to AWS because the attack ran from CloudShell, but in a real investigation one key appearing from multiple IPs is a strong sign it was stolen.
- **`AccessDenied` errors** on `iam:CreateUser` and `iam:ListUsers` from a user that only needs S3 access
- **Repeated attempts** after being denied, which suggests deliberate behavior rather than a mistake
- **Rapid sequence** of identity check followed by bucket discovery within seconds

---

## 6. Key Findings

### Least privilege limited the damage
Because `intern-dev` only had read-only S3 access, the attacker could read data but could not create users or explore IAM. Without that restriction, the `CreateUser` attempt could have given them a permanent backdoor.

### The attack was split across two regions
The S3 and identity events were logged in **us-east-2 (Ohio)**, where the attack ran. The IAM events were logged in **us-east-1 (N. Virginia)**, because IAM is a global service. If I had only searched Ohio, I would have missed the privilege escalation attempts entirely. Analysts need to check every relevant region.

### Logging gap: file access was invisible
My trail only recorded **management events**. Looking inside a bucket (`ListObjectsV2`) and downloading a file (`GetObject`) are **S3 data events**, which are not recorded by default. As a result, the actual data theft left no trace in the logs. For buckets holding sensitive data, data event logging should be turned on.

### A real credential exposure happened during the lab
While setting up the attack, the secret access key appeared in screenshots I took of my screen. This is exactly how keys leak in the real world. Because the key was deactivated and deleted as part of the response, the exposure caused no further harm, but it reinforced why credentials should never be shown, shared, or stored in plain files.

---

## 7. Containment and Remediation

| Step | Action | Time |
|---|---|---|
| Contain | Deactivated access key `...QFJO` | 4:22:35 PM |
| Verify | Re-ran `aws sts get-caller-identity` with the stolen key, which returned `InvalidClientTokenId`, confirming the attacker was locked out | After deactivation |
| Eradicate | Deleted the access key | 4:48:27 PM |
| Clean up | Deleted the downloaded key file and screenshots that showed the key | After deletion |

**Time to containment:** the last malicious action was at 3:07:17 PM, and the key was disabled at 4:22:35 PM, a gap of **1 hour 15 minutes**. With automated alerting, this could be reduced to minutes.

---

## 8. Recommendations

1. **Avoid long-term access keys.** Use temporary credentials (IAM roles or IAM Identity Center) so a stolen key expires on its own.
2. **Keep least privilege.** It was the control that stopped the escalation attempts in this incident.
3. **Turn on S3 data event logging** for buckets that hold sensitive data, so file access is recorded.
4. **Automate detection.** Use a service like GuardDuty, or CloudWatch alarms on events such as `CreateUser` and repeated `AccessDenied` errors, to cut response time.
5. **Search all regions during investigations,** especially us-east-1 for IAM activity.
6. **Require MFA** on every human login.
7. **Never expose credentials** in screenshots, documents, chats, or code repositories.

---

## 9. What I Learned

- How to read CloudTrail events and pull out the details that matter: time, event name, source IP, access key, and error code
- How to turn raw log entries into a timeline that explains what an attacker did and in what order
- Why global services like IAM log to us-east-1, and why that can hide activity from an analyst
- That logs only show what you configured them to capture, so understanding your logging setup is part of the investigation
- How the incident response cycle works in practice: prepare, detect, investigate, contain, eradicate, and learn

---

## 10. Tools Used

- **AWS CloudTrail**: activity logging and event history
- **AWS IAM**: users, access keys, permissions, and MFA
- **Amazon S3**: target data storage and log storage
- **AWS CloudShell** and **AWS CLI**: simulating the attacker
- **MITRE ATT&CK**: mapping attacker behavior to known techniques
