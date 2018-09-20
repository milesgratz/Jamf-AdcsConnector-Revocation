# Jamf-AdcsConnector-Revocation

Certificate revocation is a security requirement to prevent unauthorized devices from accessing a network. Currently, the ability to perform certificate revocation is not possible with existing Jamf external CA integration, however, this can be accomplished using the following approach:

1. Create a non-compliance group in Jamf Pro (*certificates to revoke*)
2. Create a service account in Jamf with read-only API access
3. Create a scheduled task on Jamf AD CS Connector

# Prerequisites

- Jamf Pro, configured and working
- Jamf AD CS Connector, configured and working
- Microsoft CA (ADCS), configured and working

# Install

## 1. Creating non-compliance group in Jamf

Login to your Jamf console and create a new group. This can be a Smart Group with specific compliance criteria like OS version, or a Static Group that will be manually managed. After creating your group, check the Jamf URL to determine the group unique ID. In the example below, the group ID is 830. 

	https://yourJamf.example.com/staticComputerGroups.html?id=830&o=r
  
## 2. Creating read-only API service account in Jamf

The simplest approach is to grant **Access Level: Full Access** and **Privileged Set: Auditor**. Ideally, you would restrict this to your specific environment (e.g. Computers, Mobile Devices, Smart Computer Groups, Smart Mobile Device Groups, Static Computer Groups, Static Mobile Device Groups)

## 3. Creating scheduled task on Jamf AD CS Connector

### Granting permissions on Microsoft CA

To perform certificate revocation, you need to grant "Issue and Manage Certificates" permissions to either (1) the Jamf AD CS Connector computer object or (2) a dedicated service account. In the next step, we will configure the Scheduled Task on the Jamf AD CS Connector server accordingly.  

1. Login to your **Microsoft CA** server
2. Launch **Certification Authority** (certsrv.msc)
3. Right-click the CA, select **Properties**, select the **Security** tab 
4. Grant **Issue and Manage Certificates** to the appropriate computer or user object

![Microsoft CA Permissions](/Images/certsrv.png)

### Installing PowerShell PKI module on Jamf AD CS Connector

Windows Server 2016 has native support for installing from PowerShell Gallery. Otherwise, you can follow instructions [here](https://github.com/Crypt32/PSPKI) to install manually.  

	Install-Module -Name PSPKI

### Creating Scheduled Task on Jamf AD CS Connector

You can create the scheduled task manually, otherwise this is an easy way of import it. 

1. Login to your **Jamf AD CS Connector** server
2. Create a folder for storing the script and logs (*by default, D:\Jamf-AdcsConnector-Revocation*)
3. Copy [**Jamf-AdcsConnector-Revocation.ps1**](/Jamf-AdcsConnector-Revocation.ps1) and [**Jamf-AdcsConnector-Revocation.xml**](/Jamf-AdcsConnector-Revocation.xml) to the folder
4. Open **Task Scheduler**, right-click **Task Scheduler Library**, choose **Import**
5. Import the **Jamf-AdcsConnector-Revocation.xml** Scheduled Task XML
6. Update the Scheduled Task **User or Group** (*by default, it is using the Jamf AD CS Connector computer objecy "SYSTEM" account*) 
7. Update the Scheduled Task **Triggers** (*by default, it runs hourly, starting on 2020-01-01*)
8. Update the Scheduled Task **Actions** (*by default, script is D:\Jamf-AdcsConnector-Revocation\Jamf-AdcsConnector-Revocation.ps1*)
 
![Jamf AD CS Connector General tab](/Images/schtasks1.png)
![Jamf AD CS Connector Actions tab](/Images/schtasks2.png)

# Logging

The scheduled task will log in two places:

- Event Viewer: **Application\Jamf-AdcsConnector-Revocation**
- Log file: **Jamf-AdcsConnector-Revocation.log** (*by default, current path of Jamf-AdcsConnector-Revocation.ps1 script*)

## Event Viewer 

![Jamf AD CS Connector EventLog](/Images/eventvwr.png)

### Success Events

- 8000: Success - importing PSPKI module
- 8001: Success - querying Jamf group
- 8002: Success - querying Jamf computer
- 8003: Success - revoking certificate (*or verifying it is already revoked*)

### Error Events

- 9000: Failure - importing PSPKI module
- 9001: Failure - querying Jamf group
- 9002: Failure - querying Jamf computer
- 9003: Failure - revoking certificate

## Log file

![Jamf AD CS Connector EventLog](/Images/log.png)

