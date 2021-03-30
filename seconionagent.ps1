
# Purpose: Install additional packages from Chocolatey.

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Installing additional Choco packages..."

If (-not (Test-Path "C:\ProgramData\chocolatey")) {
  Write-Host "Installing Chocolatey"
  iex ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))
} else {
  Write-Host "Chocolatey is already installed."
}

Write-Host "Installing Chocolatey extras..."
choco install -y --limit-output --no-progress wireshark winpcap

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Choco addons complete!"

####################################################################################################################################################################################################################
# Purpose: Installs a handful of SysInternals tools on the host into c:\Tools\Sysinternals

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Installing SysInternals Tooling..."
$sysinternalsDir = "C:\Tools\Sysinternals"
$sysmonDir = "C:\ProgramData\Sysmon"
If(!(test-path $sysinternalsDir)) {
  New-Item -ItemType Directory -Force -Path $sysinternalsDir
} Else {
  Write-Host "Tools directory exists. Exiting."
  exit
}

If(!(test-path $sysmonDir)) {
  New-Item -ItemType Directory -Force -Path $sysmonDir
} Else {
  Write-Host "Sysmon directory exists. Exiting."
  exit
}

$autorunsPath = "C:\Tools\Sysinternals\Autoruns64.exe"
$procmonPath = "C:\Tools\Sysinternals\Procmon.exe"
$psexecPath = "C:\Tools\Sysinternals\PsExec64.exe"
$procexpPath = "C:\Tools\Sysinternals\procexp64.exe"
$sysmonPath = "C:\Tools\Sysinternals\Sysmon64.exe"
$tcpviewPath = "C:\Tools\Sysinternals\Tcpview.exe"
$sysmonConfigPath = "$sysmonDir\sysmonConfig.xml"


# Microsoft likes TLSv1.2 as well
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Downloading Autoruns64.exe..."
(New-Object System.Net.WebClient).DownloadFile('https://live.sysinternals.com/Autoruns64.exe', $autorunsPath)
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Downloading Procmon.exe..."
(New-Object System.Net.WebClient).DownloadFile('https://live.sysinternals.com/Procmon.exe', $procmonPath)
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Downloading PsExec64.exe..."
(New-Object System.Net.WebClient).DownloadFile('https://live.sysinternals.com/PsExec64.exe', $psexecPath)
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Downloading procexp64.exe..."
(New-Object System.Net.WebClient).DownloadFile('https://live.sysinternals.com/procexp64.exe', $procexpPath)
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Downloading Sysmon64.exe..."
(New-Object System.Net.WebClient).DownloadFile('https://live.sysinternals.com/Sysmon64.exe', $sysmonPath)
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Downloading Tcpview.exe..."
(New-Object System.Net.WebClient).DownloadFile('https://live.sysinternals.com/Tcpview.exe', $tcpviewPath)
Copy-Item $sysmonPath $sysmonDir

# Download Olaf Hartongs Sysmon config
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Downloading Olaf Hartong's Sysmon config..."
(New-Object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml', "$sysmonConfigPath")
# Alternative: Download SwiftOnSecurity's Sysmon config
# Write-Host "Downloading SwiftOnSecurity's Sysmon config..."
# (New-Object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml', "$sysmonConfigPath")

# Start Sysmon
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Starting Sysmon..."
Start-Process -FilePath "$sysmonDir\Sysmon64.exe" -ArgumentList "-accepteula -i $sysmonConfigPath"
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Verifying that the Sysmon service is running..."
Start-Sleep 5 # Give the service time to start
If ((Get-Service -name Sysmon64).Status -ne "Running")
{
  throw "The Sysmon service did not start successfully"
}

# Make the event log channel readable. For some reason this doesn't work in the GPO and only works when run manually.
wevtutil sl Microsoft-Windows-Sysmon/Operational "/ca:O:BAG:SYD:(A;;0x5;;;BA)(A;;0x1;;;S-1-5-20)(A;;0x1;;;S-1-5-32-573)"

####################################################################################################################################################################################################################
# Purpose: Installs osquery on the host
# Note: by default, osquery will be configured to connect to the Fleet server on the "logger" host via TLS.

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Installing osquery..."
$flagfile = "c:\Program Files\osquery\osquery.flags"
choco install -y --limit-output --no-progress osquery | Out-String  # Apparently Out-String makes the process wait
$service = Get-WmiObject -Class Win32_Service -Filter "Name='osqueryd'"
If (-not ($service)) {
  Write-Host "Setting osquery to run as a service"
  New-Service -Name "osqueryd" -BinaryPathName "C:\Program Files\osquery\osqueryd\osqueryd.exe --flagfile=`"C:\Program Files\osquery\osquery.flags`""

  # Download the flags file from the Palantir osquery-configuration Github
  # GitHub requires TLS 1.2 as of 2/1/2018
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Invoke-WebRequest -Uri "https://raw.githubusercontent.com/palantir/osquery-configuration/master/Classic/Endpoints/Windows/osquery.flags" -OutFile $flagfile

  ## Use the TLS config
  ## Add entry to hosts file for Kolide for SSL validation
  Add-Content "c:\windows\system32\drivers\etc\hosts" "        10.0.0.252    kolide"
  ## Add kolide secret and avoid BOM
  $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
  [System.IO.File]::WriteAllLines("c:\Program Files\osquery\kolide_secret.txt", "enrollmentsecret", $Utf8NoBomEncoding)
  ## Change TLS server hostname in the flags file
  (Get-Content $flagfile) -replace 'tls.endpoint.server.com', 'kolide:8412' | Set-Content $flagfile
  ## Change path to secrets in the flags file
  (Get-Content $flagfile) -replace 'path\\to\\file\\containing\\secret.txt', 'Program Files\osquery\kolide_secret.txt' | Set-Content $flagfile
  ## Change path to certfile in the flags file
  (Get-Content $flagfile) -replace 'c:\\ProgramData\\osquery\\certfile.crt', 'c:\Program Files\osquery\certfile.crt' | Set-Content $flagfile
  ## Remove the verbose flag and replace it with the logger_min_status=1 option (See https://github.com/osquery/osquery/issues/5212)
  (Get-Content $flagfile) -replace '--verbose=true', '--logger_min_status=1' | Set-Content $flagfile
  ## Add certfile.crt
  Copy-Item "c:\vagrant\resources\fleet\server.crt" "c:\Program Files\osquery\certfile.crt"
  ## Start the service
  Start-Service osqueryd
}
else {
  Write-Host "osquery is already installed. Moving On."
}
If ((Get-Service -name osqueryd).Status -ne "Running")
{
  throw "osqueryd service was not running"
}
####################################################################################################################################################################################################################

# Purpose: Configure winlogbeat

$service = Get-WmiObject -Class Win32_Service -Filter "Name='winlogbeat'"
If (-not ($service)) {
  choco install winlogbeat -y

  $confFile = @"
processors:
  - script:
      when.equals.winlog.channel: Security
      lang: javascript
      id: security
      file: `${path.home}/module/security/config/winlogbeat-security.js
winlogbeat.event_logs:
  - name: ForwardedEvents
    ignore_older: 15m
  
  - name: WEC-Authentication
  - name: WEC-Code-Integrity
  - name: WEC-EMET
  - name: WEC-Powershell
  - name: WEC-Process-Execution
  - name: WEC-Services
  - name: WEC-WMI
  - name: WEC16-Test
  - name: WEC2-Application-Crashes
  - name: WEC2-Applocker
  - name: WEC2-Group-Policy-Errors
  - name: WEC2-Object-Manipulation
  - name: WEC2-Registry
  - name: WEC2-Task-Scheduler
  - name: WEC2-Windows-Defender
  - name: WEC3-Account-Management
  - name: WEC3-Drivers
  - name: WEC3-External-Devices
  - name: WEC3-Firewall
  - name: WEC3-Print
  - name: WEC3-Smart-Card
  - name: WEC3-Windows-Diagnostics
  - name: WEC4-Bits-Client
  - name: WEC4-DNS
  - name: WEC4-Hotpatching-Errors
  - name: WEC4-Shares
  - name: WEC4-System-Time-Change
  - name: WEC4-Windows-Updates
  - name: WEC4-Wireless
  - name: WEC5-Autoruns
  - name: WEC5-Certificate-Authority
  - name: WEC5-Crypto-API
  - name: WEC5-Log-Deletion-Security
  - name: WEC5-Log-Deletion-System
  - name: WEC5-MSI-Packages
  - name: WEC5-Operating-System
  - name: WEC6-ADFS
  - name: WEC6-Device-Guard
  - name: WEC6-Duo-Security
  - name: WEC6-Exploit-Guard
  - name: WEC6-Microsoft-Office
  - name: WEC6-Software-Restriction-Policies
  - name: WEC6-Sysmon
    processors:
    - script:
        lang: javascript
        id: sysmon
        file: `${path.home}/module/sysmon/config/winlogbeat-sysmon.js
  - name: WEC7-Active-Directory
  - name: WEC7-Privilege-Use
  - name: WEC7-Terminal-Services
setup.kibana:

  # Kibana Host
  # Scheme and port can be left out and will be set to the default (http and 5601)
  # In case you specify and additional path, the scheme is required: http://localhost:5601/path
  # IPv6 addresses should always be defined as: https://[2001:db8::1]:5601
  #host: "localhost:5601"


#output.logstash:
  # The Logstash hosts
  #hosts: ["10.0.0.252:5044"]
"@
  $confFile | Out-File -FilePath C:\ProgramData\chocolatey\lib\winlogbeat\tools\winlogbeat.yml -Encoding ascii

  winlogbeat --path.config C:\ProgramData\chocolatey\lib\winlogbeat\tools setup

  sc.exe failure winlogbeat reset= 30 actions= restart/5000
  Start-Service winlogbeat
}
else {
  Write-Host "winlogbeat is already configured. Moving On."
}
If ((Get-Service -name winlogbeat).Status -ne "Running") {
  throw "winlogbeat service was not running"
}
