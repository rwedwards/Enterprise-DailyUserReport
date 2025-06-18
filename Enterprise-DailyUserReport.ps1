#==================================================================================
# Author: Richard Edwards for CompanyName
# Reviewer: 
# Last Updated: 2025-06-18
# Self-contained logon script for VDI/Thick Client/Trusted Thin Client environments
#==================================================================================

$DaysToKeep = 7
$Username   = $env:USERNAME
$Today      = Get-Date -Format "yyyy-MM-dd"
# Where to save the report
$Username = $env:USERNAME
#change this to the actual share name
$BasePath = "\\Domain\Path_to_share\$Username"
# Ensure the directory exists
if (-not (Test-Path $BasePath)) {
    Write-Host "[+] Creating network folder: $BasePath"
    New-Item -Path $BasePath -ItemType Directory -Force | Out-Null
}
# Timestamped report name
$TimeStamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
$ReportPath = Join-Path -Path $BasePath -ChildPath "UserReport_$TimeStamp.html"

Write-Host "[+] Starting Enterprise Daily User Report for $Username"

if (!(Test-Path $OutDir)) {
    New-Item -Path $OutDir -ItemType Directory -Force | Out-Null
    Write-Host "[+] Created report directory: $OutDir"
}

# Cleanup old reports
Write-Host "[+] Cleaning up old reports (>$DaysToKeep days)"
$parentDir = Split-Path $OutDir -Parent
Get-ChildItem -Path $parentDir -Directory | Where-Object {
    $_.Name -match '^\d{4}-\d{2}-\d{2}$' -and
    ((Get-Date) - [datetime]($_.Name)) -gt (New-TimeSpan -Days $DaysToKeep)
} | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

# HTML Start
$reportHtml = @"
<!DOCTYPE html>
<html><head><title>User Report</title>
<style>
body { font-family: Segoe UI; background: #f4f4f4; padding: 20px }
h1 { background: #003366; color: white; padding: 10px }
div { background: white; padding: 10px; margin: 10px 0; border-radius: 4px }
b { color: #003366 }
ul { margin: 0; padding-left: 20px }
</style></head><body>
<h1>Enterprise Daily User Report for $Username</h1>
"@

$reportHtml += "<div><b>Username:</b> $Username</div>"
$reportHtml += "<div><b>Computer Name:</b> $env:COMPUTERNAME</div>"
$reportHtml += "<div><b>Date:</b> $(Get-Date)</div>"

# Accurate Logon Time
Write-Host "[+] Getting logon time..."
try {
    $userSID = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    $logon = Get-CimInstance -ClassName Win32_LogonSession |
        Where-Object { $_.LogonType -in 2,10 } |
        ForEach-Object {
            $assoc = Get-CimAssociatedInstance -InputObject $_ -ResultClassName Win32_Account |
                Where-Object { $_.SID -eq $userSID }
            if ($assoc) { return $_ }
        } |
        Sort-Object StartTime -Descending |
        Select-Object -First 1

    if ($logon -and $logon.StartTime) {
        $start = [datetime]::Parse($logon.StartTime)
        $reportHtml += "<div><b>User Logon Time:</b> $start</div>"
        $uptime = New-TimeSpan -Start $start -End (Get-Date)
        $reportHtml += "<div><b>Time Since Logon:</b> $($uptime.Hours) hrs $($uptime.Minutes) min</div>"
    } else {
        $reportHtml += "<div><b>User Logon Time:</b> Not Found</div>"
    }
} catch {
    $reportHtml += "<div><b>User Logon Time:</b> Error</div>"
}
# FSLogix Profile
Write-Host "[+] Checking FSLogix Profile..."
try {
    $fsKey = "HKCU:\SOFTWARE\FSLogix\Profiles\Session"
    if (Test-Path $fsKey) {
        $fs = Get-ItemProperty $fsKey
        if ($fs.VHDOpenedFilePath) {
            $fsSize = (Get-Item $fs.VHDOpenedFilePath).Length
            $reportHtml += "<div><b>FSLogix Profile:</b> $($fs.VHDOpenedFilePath) ($([math]::Round($fsSize / 1GB, 2)) GB)</div>"
        } else {
            $reportHtml += "<div><b>FSLogix Profile:</b> Key found but no VHD attached</div>"
        }
    } else {
        $reportHtml += "<div><b>FSLogix Profile:</b> Not detected</div>"
    }
} catch {
    $reportHtml += "<div><b>FSLogix Profile:</b> Error</div>"
}

# ODFC Detection (Hybrid)
Write-Host "[+] Scanning for ODFC container (both VHDX and metadata)..."
try {
    $odfcFound = $false
    $odfcServers = @("NAS1", "NAS2")
    $sid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value

    foreach ($server in $odfcServers) {
        $basePath = "\\$server.domain\FSLProfileDisk\$Username"

        # Check O365_Diff metadata
        $odfcMetaPath = Join-Path $basePath "O365_Diff"
        if (Test-Path $odfcMetaPath) {
            $auth = Get-ChildItem $odfcMetaPath -Filter *.authString -ErrorAction SilentlyContinue
            $cert = Get-ChildItem $odfcMetaPath -Filter *.signingCert -ErrorAction SilentlyContinue
            if ($auth -or $cert) {
                $files = ($auth + $cert | ForEach-Object { $_.Name }) -join ", "
                $reportHtml += "<div><b>ODFC Metadata:</b> $files</div>"
                $odfcFound = $true
            }
        }

        # Check SID-based folder for ODFC VHDX
        $subFolders = Get-ChildItem -Path $basePath -Directory -ErrorAction SilentlyContinue |
                      Where-Object { $_.Name -like "*$Username" -and $_.Name -like "*$sid*" }
        foreach ($folder in $subFolders) {
            $vhd = Get-ChildItem -Path $folder.FullName -Filter "ODFC_*.vhdx" -ErrorAction SilentlyContinue |
                   Select-Object -First 1
            if ($vhd) {
                $size = [math]::Round($vhd.Length / 1GB, 2)
                $reportHtml += "<div><b>ODFC Container VHDX:</b> $($vhd.FullName) ($size GB)</div>"
                $odfcFound = $true
                break
            }
        }

        if ($odfcFound) { break }
    }

    if (-not $odfcFound) {
        $reportHtml += "<div><b>ODFC Container:</b> Not found in known locations</div>"
    }
} catch {
    $reportHtml += "<div><b>ODFC Container:</b> Error during lookup</div>"
}

# OneDrive
Write-Host "[+] Checking OneDrive..."
try {
    $oneDrivePath = $env:OneDrive
    if ($oneDrivePath -and (Test-Path $oneDrivePath)) {
        $size = (Get-ChildItem -Recurse -Force -ErrorAction SilentlyContinue $oneDrivePath | Measure-Object -Property Length -Sum).Sum
        $oneDriveSize = [math]::Round($size / 1GB, 2)
        $reportHtml += "<div><b>OneDrive:</b> $oneDrivePath ($oneDriveSize GB)</div>"
    } else {
        $reportHtml += "<div><b>OneDrive:</b> Not detected</div>"
    }
} catch {
    $reportHtml += "<div><b>OneDrive:</b> Error</div>"
}
# Mapped Drives
Write-Host "[+] Gathering mapped network drives (via WMI)..."
try {
    $netDrives = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType = 4"
    if ($netDrives) {
        $reportHtml += "<div><b>Mapped Drives:</b><ul>"
        foreach ($d in $netDrives) {
            $reportHtml += "<li>Drive $($d.DeviceID): ➜ $($d.ProviderName)</li>"
        }
        $reportHtml += "</ul></div>"
    } else {
        $reportHtml += "<div><b>Mapped Drives:</b> None found</div>"
    }
} catch {
    $reportHtml += "<div><b>Mapped Drives:</b> Error</div>"
}


# Mapped Printers
Write-Host "[+] Gathering mapped printers (network only)..."
try {
    $printers = Get-CimInstance Win32_Printer | Where-Object {
        $_.Network -eq $true
    }

    if ($printers) {
        $reportHtml += "<div><b>Mapped Printers:</b><ul>"
        foreach ($p in $printers) {
            $reportHtml += "<li>$($p.Name)</li>"
        }
        $reportHtml += "</ul></div>"
    } else {
        $reportHtml += "<div><b>Mapped Printers:</b> No user-mapped printers found</div>"
    }
} catch {
    $reportHtml += "<div><b>Mapped Printers:</b> Error</div>"
}



# Network Info
Write-Host "[+] Collecting network information..."
try {
    $ipConfig = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -eq "Up" } | Select-Object -First 1
    if ($ipConfig) {
        $reportHtml += "<div><b>Default Gateway:</b> $($ipConfig.IPv4DefaultGateway.NextHop)</div>"
        $reportHtml += "<div><b>Interface:</b> $($ipConfig.InterfaceAlias) ($($ipConfig.IPv4Address.IPAddress))</div>"
        $dnsList = $ipConfig.DnsServer.ServerAddresses -join ", "
        $reportHtml += "<div><b>DNS:</b> $dnsList</div>"
    } else {
        $reportHtml += "<div><b>Network:</b> Unable to determine active adapter</div>"
    }
} catch {
    $reportHtml += "<div><b>Network:</b> Error</div>"
}

# VDI vs Thick Client Check
Write-Host "[+] Detecting session type..."
try {
    $vmServices = Get-Service | Where-Object { $_.DisplayName -like "*VMware*" -and $_.Status -eq "Running" }
    if ($vmServices -match "VMTools") {
        $reportHtml += "<div><b>Session Type:</b> VDI (VMware Tools Detected)</div>"
    } else {
        $reportHtml += "<div><b>Session Type:</b> Thick Client / Console</div>"
    }
} catch {
    $reportHtml += "<div><b>Session Type:</b> Unknown</div>"
}
# System Uptime
Write-Host "[+] Calculating system uptime..."
try {
    $os = Get-CimInstance Win32_OperatingSystem
    $uptime = (Get-Date) - $os.LastBootUpTime
    $reportHtml += "<div><b>System Uptime:</b> $($uptime.Days) days $($uptime.Hours) hrs $($uptime.Minutes) min</div>"
} catch {
    $reportHtml += "<div><b>System Uptime:</b> Error</div>"
}

# Environment Variables
Write-Host "[+] Collecting key environment variables..."
$envVars = @("USERDNSDOMAIN", "LOGONSERVER", "SESSIONNAME")
$reportHtml += "<div><b>Environment Variables:</b><ul>"
foreach ($var in $envVars) {
    try {
        $val = (Get-Item "Env:$var").Value
        $reportHtml += "<li>$($var): $val</li>"
    } catch {
        $reportHtml += "<li>$($var): Not Set</li>"
    }
}
$reportHtml += "</ul></div>"

# Logon Metrics (Event Logs - Optional, best effort)
Write-Host "[+] Parsing event log for slow logon indicators..."
try {
    $events = Get-WinEvent -LogName "Microsoft-Windows-GroupPolicy/Operational" -MaxEvents 20 -ErrorAction SilentlyContinue
    $recentLogon = $events | Where-Object { $_.Id -in 5310, 5312, 8000 } | Select-Object -First 1
    if ($recentLogon) {
        $reportHtml += "<div><b>Logon Time Metrics:</b> $($recentLogon.TimeCreated): $($recentLogon.Message)</div>"
    } else {
        $reportHtml += "<div><b>Logon Time Metrics:</b> No recent events</div>"
    }
} catch {
    $reportHtml += "<div><b>Logon Time Metrics:</b> Error reading logs</div>"
}

# Close HTML and Save
$reportHtml += "</body></html>"

Write-Host "[+] Saving HTML report to: $ReportPath"
try {
    $reportHtml | Out-File -FilePath $ReportPath -Encoding UTF8 -Force
    Write-Host "[✔] Report saved successfully."
} catch {
    Write-Host "[!] Failed to save report."
}


# CSV Summary Row (Central Log)
$CsvBase = "\\domain\Path_to_share\EnterpriseSummary"
if (-not (Test-Path $CsvBase)) {
    New-Item -Path $CsvBase -ItemType Directory -Force | Out-Null
}
$CsvFile = Join-Path $CsvBase "DailyUserSummary.csv"

# Construct summary object
$summary = [PSCustomObject]@{
    Date             = (Get-Date -Format "yyyy-MM-dd HH:mm")
    Username         = $Username
    ComputerName     = $env:COMPUTERNAME
    SessionType      = $SessionType
    FSLogixProfile   = $FSLogixProfileDisplay
    ODFC_Container   = $OdfcContainerDisplay
    OneDrivePath     = $OneDrivePath
    OneDriveSize     = $OneDriveSize
    ProfileSizeGB    = $ProfileSize
    LogonTime        = $LogonTime
    TimeSinceLogon   = $LogonDurationDisplay
    Uptime           = "$($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m"
    DefaultGateway   = $DefaultGateway
    IPAddress        = $ipAddress
    MappedDrives     = ($netDrives | ForEach-Object { $_.ProviderName }) -join "; "
    MappedPrinters   = ($printers | ForEach-Object { $_.Name }) -join "; "
}

# Append to CSV
try {
    $append = -not (Test-Path $CsvFile)
    $summary | Export-Csv -Path $CsvFile -NoTypeInformation -Append:$append
    Write-Host "[✔] Summary CSV updated: $CsvFile"
} catch {
    Write-Host "[!] Failed to update CSV: $_"
}
