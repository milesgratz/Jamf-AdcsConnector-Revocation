#######################################################################
#                                                                     #
#            Jamf AD CS Connector - certificate revocation            #
#                                                                     #
#######################################################################
#                                                                     #
#   Certificate revocation is a security requirement to prevent       #
#    unauthorized devices from accessing a network. Currently, the    #
#    ability to perform certificate revocation is not possible with   #
#    existing Jamf external CA integration. This can be accomplished  #
#    using the following approach:                                    #
#                                                                     #
#   1.  Create non-compliance group in Jamf Pro (static or smart)     #
#   2.  Create service account in Jamf Pro with API "read" access     #
#   3.  Create scheduled task on Microsoft CA or Jamf ADCS Proxy      #
#        +requires PowerShell PKI module                              #
#        +requires "Issue and Manage Certificates" on Microsoft CA    #
#                                                                     #
#######################################################################
#                                                                     #
#      Log Name:         Application                                  #
#      Source:           Jamf-AdcsProxy-Revocation                    #
#                                                                     #
#      EventId 8000:     Success - importing PSPKI module             #
#      EventId 8001:     Success - querying group                     #
#      EventId 8002:     Success - querying computer                  #
#      EventId 8003:     Success - revoking certificate               #
#                                                                     #
#      EventId 9000:     Failure - importing PSPKI module             #
#      EventId 9001:     Failure - querying group                     #
#      EventId 9002:     Failure - querying computer                  #
#      EventId 9003:     Failure - revoking certificate               #
#                                                                     #
#######################################################################
#                                                                     #
#      links:   https://docs.jamf.com/ad-cs-connector                 #
#      links:   https://developer.jamf.com/apis/classic-api           #
#      links:   https://github.com/Crypt32/pspki                      #
#                                                                     #
#######################################################################
#                                                                     #
#      author:  github.com/milesgratz                                 #
#      date:    2018-09-19                                            #
#      note:    made with love <3                                     #
#                                                                     #
#######################################################################

#======================================================================
# Variables to customize for your environment
#======================================================================
$issuingCA = 'yourMicrosoftCA.domain.com'
$apiUrl = 'https://yourJamf.domain.com/JSSResource'
$apiUser = 'yourApiUser'
$apiPass = 'yourApiPwd'                                     
$apiGroupId = '000'                                            # Jamf group ID to revoke certs
$apiTls12 = $true                                              # Jamf HTTPS, enable TLS 1.2 
$apiSelfSigned = $false                                        # Jamf HTTPS, allow self-signed 
$logFile = "$PSScriptRoot\Jamf-AdcsConnector-Revocation.log"   # Logging, optional to hardcode path

#======================================================================
# Define logging function
#======================================================================
Function Write-Log {
    param(
        $Message,
        $LogPath,
        $Color = "Yellow"
    )

    Write-Host "$Message" -ForegroundColor $Color
    if ($LogPath -ne $null)
    {
        $logTime = Get-Date -format "yyyy-MM-dd HH:mm:ss zzz"
        Write-Output "[$logTime] $Message" | Out-File -Append $LogPath
    }
}

#======================================================================
# Creating new Event source on server
#======================================================================
try 
{
    $eventSource = 'Jamf-AdcsConnector-Revocation'
    if (!([System.Diagnostics.EventLog]::SourceExists($eventSource)))
    {
        New-EventLog -LogName Application -Source $eventSource -ErrorAction Stop
    }
}
catch
{
    $errorMsg = $_.Exception.Message
    Write-Log "Failed to create new event log: $errorMsg" -LogPath $logFile
    Exit
}

#======================================================================
# Import PowerShell PKI module
#======================================================================
Import-Module PSPKI -ErrorAction SilentlyContinue

try 
{
    # Verify PSPKI module is installed
    if (!(Get-Module PSPKI -ErrorAction Stop))
    { 
        Install-Module PSPKI -ErrorAction Stop -Force
        Import-Module PSPKI -ErrorAction Stop
    }
    else
    {
        # Do nothing - module already imported 
    }

    # Logging
    $outcome = "Successfully imported PowerShell PKI module"
    Write-Log $outcome -LogPath $logFile
    Write-EventLog -Message $outcome -LogName Application -Source $eventSource -EntryType Information -EventId 8000
}
catch
{
    # Logging
    $errorMsg = $_.Exception.Message
    $outcome = "Failed to import PowerShell PKI module. Exception: $errorMsg"
    Write-Log $outcome -LogPath $logFile
    Write-EventLog -Message $outcome -LogName Application -Source $eventSource -EntryType Error -EventId 9000
    Exit
}

#======================================================================
# Connecting to Jamf Classic API
#======================================================================
$user = $apiUser
$pass = ConvertTo-SecureString -String $apiPass -AsPlainText -Force
$creds = New-Object –TypeName System.Management.Automation.PSCredential –ArgumentList $user, $pass

# Configure TLS 1.2 as default
if ($apiTls12)
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

if ($apiSelfSigned)
{
    # Add class to ignore self-signed certs
    add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem) {
                return true;
            }
        }
"@

    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}

#======================================================================
# Querying computers in desired Jamf group
#======================================================================
try
{
    $url = "$apiUrl/computergroups/id/$apiGroupId"
    $group = Invoke-RestMethod -Uri $url -Credential $creds -ErrorAction Stop
    $groupCount = ($group.computer_group.computers | Measure-Object).Count
    
    # Logging
    $outcome = "Successfully queried Jamf certificate revocation group Id: $apiGroupId. Computer count: $groupCount"
    Write-Log $outcome -LogPath $logFile
    Write-EventLog -Message $outcome -LogName Application -Source $eventSource -EntryType Information -EventId 8001
}
catch
{
    # Logging
    $errorMsg = $_.Exception.Message
    $outcome = "Failed to query Jamf certificate revocation group Id: $apiGroupId. Exception: $errorMsg"
    Write-Log $outcome -LogPath $logFile
    Write-EventLog -Message $outcome -LogName Application -Source $eventSource -EntryType Error -EventId 9001
    Exit
}

#======================================================================
# Loop through group and revoke certificates
#======================================================================
foreach ($machine in $group.computer_group.computers)
{
    #------------------------------------------------------------------
    # Getting certificates associated with computer in Jamf
    #------------------------------------------------------------------ 
    try
    {
        # Define variables to get computer details
        $computerId = $machine.Id
        $computerName = $machine.Name
        $url = "$apiUrl/computers/id/$computerId"

        # Query API for computer details
        $data = Invoke-RestMethod -Uri $url -Credential $creds -ErrorAction Stop
     
        # Find identity certificates
        $identity = $data.computer.certificates | Where-Object { ($_.identity -eq $True) -and ($_.common_name -eq "$computerName") }     
        $certCount = ($identity | Measure-Object).Count

        # Logging
        $outcome = "Successfully queried computer: $computerName. Certificate count: $certCount"
        Write-Log $outcome -LogPath $logFile
        Write-EventLog -Message $outcome -LogName Application -Source $eventSource -EntryType Information -EventId 8002       
    }
    catch
    {
        # Logging
        $errorMsg = $_.Exception.Message
        $outcome = "Failed to query computer: $computerName. Exception: $errorMsg"
        Write-Log $outcome -LogPath $logFile
        Write-EventLog -Message $outcome -LogName Application -Source $eventSource -EntryType Error -EventId 9002
    }

    #------------------------------------------------------------------
    # Finding and revoking certificate on CA
    #------------------------------------------------------------------ 
    if ($certCount -gt 0)
    {
        try
        {
            # Check if cert is currently valid, or already revoked 
            $certExpiration = (Get-Date $identity.expires_utc).ToUniversalTime()
            $issuedCert = Get-IssuedRequest -CertificationAuthority $issuingCA -Filter "NotAfter -eq $certExpiration","CommonName -eq $computerName" -ErrorAction Stop
            $revokedCert = Get-RevokedRequest -CertificationAuthority $issuingCA -Filter "NotAfter -eq $certExpiration","CommonName -eq $computerName" -ErrorAction Stop
            
            if ($issuedCert)
            {
                #Revoke cert
                $issuedCert | Revoke-Certificate -Reason CeaseOfOperation -ErrorAction Stop

                # Logging
                $outcome = "Successfully revoked certificate from CA: $issuingCA. Computer name: $computerName. Serialnumber: $($issuedCert.SerialNumber)"
                Write-Log $outcome -LogPath $logFile
                Write-EventLog -Message $outcome -LogName Application -Source $eventSource -EntryType Information -EventId 8003
            }
            elseif ($revokedCert)
            {
                $revokedDate = Get-Date $revokedCert.'Request.RevokedWhen' -Format o
                
                # Logging
                $outcome = "Successfully verified certificate was already revoked on $revokedDate from CA: $issuingCA. Computer name: $computerName. Serialnumber: $($revokedCert.SerialNumber)"
                Write-Log $outcome -LogPath $logFile
                Write-EventLog -Message $outcome -LogName Application -Source $eventSource -EntryType Information -EventId 8003
            }
            else
            {
                throw "Certificate not found on CA"
            }
        }
        catch
        {
            # Logging
            $errorMsg = $_.Exception.Message
            $outcome = "Failed to revoke certificate from CA: $issuingCA. Computer name: $computerName. Exception: $errorMsg"
            Write-Log $outcome -LogPath $logFile
            Write-EventLog -Message $outcome -LogName Application -Source $eventSource -EntryType Error -EventId 9003
        }
    }
    else
    {
        # Do nothing - there are no certificates associated with computer
    }
 
    #------------------------------------------------------------------
    # Cleaning up variables
    #------------------------------------------------------------------   
    Clear-Variable computerId,computerName,url,data,identity,certCount,outcome,errorMsg,certExpiration,issuedCert,revokedCert,revokedDate -ErrorAction SilentlyContinue
}
