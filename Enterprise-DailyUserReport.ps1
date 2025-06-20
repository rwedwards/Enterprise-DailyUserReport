#==================================================================================
# Author: Your Name for Company Name
# Script: Enterprise-UserReport.ps1
# Purpose: Daily user diagnostic report for VDI and Thick clients
# Permissions: Non-privileged (Standard User)
#==================================================================================

# -------------------
# Configuration
# -------------------
$Username      = $env:USERNAME
$Today         = Get-Date -Format "yyyy-MM-dd"
$ReportRoot    = "C:\Users\$Username\Downloads"  # <-- For testing; change to: "\\Domain\dfs\EnterpriseReports"
$CsvShareRoot  = "C:\Users\$Username\Downloads"  # <-- Future: "\\Domain\dfs\EnterpriseReports\DailyCSVs"

$UserFolder    = Join-Path $ReportRoot $Username
$OutDir        = Join-Path $UserFolder $Today
$ReportPath    = Join-Path $OutDir "Enterprise-UserReport-$Username-$Today.html"
$CsvPath       = Join-Path $CsvShareRoot "Enterprise-UserReport-Aggregated-$Today.csv"

# -------------------
# Create Output Directory
# -------------------
if (!(Test-Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
    Write-Host "[+] Created report path: $OutDir"
}

# -------------------
# Clean Old Reports (7 days back)
# -------------------
$DaysToKeep = 7
Get-ChildItem -Path (Split-Path $UserFolder) -Directory | Where-Object {
    $_.Name -match '^\d{4}-\d{2}-\d{2}$' -and
    ((Get-Date) - [datetime]$_.Name) -gt (New-TimeSpan -Days $DaysToKeep)
} | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

# -------------------
# Start HTML Report
# -------------------
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

# -------------------
# Basic Info
# -------------------
$reportHtml += "<div><b>Username:</b> $Username</div>"
$reportHtml += "<div><b>Computer Name:</b> $env:COMPUTERNAME</div>"
$reportHtml += "<div><b>Date:</b> $(Get-Date)</div>"

# -------------------
# Site Location
# -------------------
try {
    $logonServer = $env:LOGONSERVER -replace "\\", ""
    switch -Wildcard ($logonServer) {
        "*Site 1*" { $site = "Main office" }
        "*Site 2*" { $site = "Annex" }
        default { $site = "UNKNOWN" }
    }
    $reportHtml += "<div><b>Site Location:</b> $site (via $logonServer)</div>"
} catch {
    $reportHtml += "<div><b>Site Location:</b> Unknown</div>"
}

# -------------------
# Logon Time
# -------------------
try {
    Write-Host "[+] Getting logon time..."
    $userSID = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    $logon = Get-CimInstance -Class Win32_LogonSession | Where-Object { $_.LogonType -in 2,10 } |
        ForEach-Object {
            $assoc = Get-CimAssociatedInstance -InputObject $_ -ResultClassName Win32_Account |
                Where-Object { $_.SID -eq $userSID }
            if ($assoc) { return $_ }
        } |
        Sort-Object StartTime -Descending |
        Select-Object -First 1

    if ($logon -and $logon.StartTime) {
        $start = [datetime]::Parse($logon.StartTime)
        $uptime = New-TimeSpan -Start $start -End (Get-Date)
        $reportHtml += "<div><b>User Logon Time:</b> $start</div>"
        $reportHtml += "<div><b>Time Since Logon:</b> $($uptime.Hours) hrs $($uptime.Minutes) min</div>"
    }
} catch {
    $reportHtml += "<div><b>Logon Time:</b> Error</div>"
}

# -------------------
# FSLogix
# -------------------
try {
    Write-Host "[+] Checking FSLogix..."
    $fsKey = "HKCU:\SOFTWARE\FSLogix\Profiles\Session"
    if (Test-Path $fsKey) {
        $fs = Get-ItemProperty $fsKey
        $fsSize = (Get-Item $fs.VHDOpenedFilePath).Length
        $reportHtml += "<div><b>FSLogix Profile:</b> $($fs.VHDOpenedFilePath) ($([math]::Round($fsSize / 1GB, 2)) GB)</div>"
    } else {
        $reportHtml += "<div><b>FSLogix Profile:</b> Not found</div>"
    }
} catch {
    $reportHtml += "<div><b>FSLogix:</b> Error</div>"
}

# -------------------
# ODFC Container Check - Active Detection
# -------------------
Write-Host "[+] Scanning for ODFC containers at all known locations..."

try {
    $odfcActive = $null
    $odfcPassive = @()
    $odfcServers = @("ODFC Server 01", "ODFC Server 02")
    $sid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    $username = $env:USERNAME

    foreach ($server in $odfcServers) {
        $basePath = "\\$server.domain\FSLProfileDisk\$username"
        $subFolders = Get-ChildItem -Path $basePath -Directory -ErrorAction SilentlyContinue |
                      Where-Object { $_.Name -like "*$username*" -and $_.Name -like "*$sid*" }

        foreach ($folder in $subFolders) {
            $vhdx = Get-ChildItem -Path $folder.FullName -Filter "ODFC_*.vhdx" -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($vhdx) {
                $stream = $null
                try {
                    $stream = [System.IO.File]::Open($vhdx.FullName, 'Open', 'ReadWrite', 'None')
                    $stream.Close()
                    $status = "Passive (unlocked)"
                    $odfcPassive += "$($vhdx.FullName) - $status"
                } catch {
                    $status = "Active (locked)"
                    $odfcActive = "$($vhdx.FullName) - $status"
                }
            }
        }
    }

    if ($odfcActive) {
        $reportHtml += "<div><b>ODFC Container (Active):</b> $odfcActive</div>"
    }

    if ($odfcPassive.Count -gt 0) {
        $reportHtml += "<div><b>ODFC Containers (Passive):</b><ul>"
        $odfcPassive | ForEach-Object { $reportHtml += "<li>$_</li>" }
        $reportHtml += "</ul></div>"
    }

    if (-not $odfcActive -and $odfcPassive.Count -eq 0) {
        $reportHtml += "<div><b>ODFC Container:</b> None Found</div>"
    }

} catch {
    $reportHtml += "<div><b>ODFC Container:</b> Error during scan</div>"
}


# -------------------
# OneDrive Info
# -------------------
try {
    $oneDrivePath = $env:OneDrive
    if ($oneDrivePath -and (Test-Path $oneDrivePath)) {
        $size = (Get-ChildItem -Recurse -Force -ErrorAction SilentlyContinue $oneDrivePath | Measure-Object -Property Length -Sum).Sum
        $oneDriveSize = [math]::Round($size / 1GB, 2)
        $reportHtml += "<div><b>OneDrive:</b> $oneDrivePath ($oneDriveSize GB)</div>"
    } else {
        $reportHtml += "<div><b>OneDrive:</b> Not Detected</div>"
    }
} catch {
    $reportHtml += "<div><b>OneDrive:</b> Error</div>"
}

# -------------------
# Mapped Drives
# -------------------
try {
    $netDrives = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType = 4"
    if ($netDrives) {
        $reportHtml += "<div><b>Mapped Drives:</b><ul>"
        foreach ($d in $netDrives) {
            $reportHtml += "<li>$($d.DeviceID): ➜ $($d.ProviderName)</li>"
        }
        $reportHtml += "</ul></div>"
    }
} catch {
    $reportHtml += "<div><b>Mapped Drives:</b> Error</div>"
}

# -------------------
# System Info
# -------------------
try {
    $model     = (Get-CimInstance Win32_ComputerSystem).Model
    $os        = Get-CimInstance Win32_OperatingSystem
    $winReg    = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $releaseId = $winReg.DisplayVersion
    $buildLab  = $winReg.BuildLabEx

    $extendedOsName = "$($os.Caption) $releaseId"

    $reportHtml += "<div><b>System Model:</b> $model</div>"
    $reportHtml += "<div><b>Operating System:</b> $extendedOsName (Version: $($os.Version), Build: $($os.BuildNumber))</div>"
    $reportHtml += "<div><b>Build Lab:</b> $buildLab</div>"
} catch {
    $reportHtml += "<div><b>System Info:</b> Error</div>"
}

# -------------------
# Environment Variables
# -------------------
Write-Host "[+] Capturing environment variables..."
$envVars = @(
    "USERDNSDOMAIN"
    "USERDOMAIN"
    "LOGONSERVER"
    # "COMPUTERNAME"
    # "SESSIONNAME"
)

$reportHtml += "<div><b>Environment Variables:</b><ul>"
foreach ($var in $envVars) {
    try {
        $val = (Get-Item "Env:$var").Value
        $reportHtml += "<li>${var}: $val</li>"
    } catch {
        $reportHtml += "<li>${var}: Not Set</li>"
    }
}
$reportHtml += "</ul></div>"

# -------------------
# Group Memberships
# -------------------
try {
    $groups = Get-ADUser $Username -Properties MemberOf | Select-Object -ExpandProperty MemberOf |
        ForEach-Object { ($_ -split ',')[0] -replace '^CN=' }

    if ($groups) {
        $reportHtml += "<div><b>Group Memberships:</b><ul>"
        foreach ($g in $groups) {
            $reportHtml += "<li>$g</li>"
        }
        $reportHtml += "</ul></div>"
    } else {
        $reportHtml += "<div><b>Group Memberships:</b> None found</div>"
    }
} catch {
    $reportHtml += "<div><b>Group Memberships:</b> Error retrieving</div>"
}

# -------------------
# Group Policies
# -------------------
Write-Host "[+] Gathering applied Group Policies via gpresult /R..."
$gpoOutput = ""
$tries = 0
do {
    $gpoOutput = gpresult /R /scope:user 2>&1
    if ($gpoOutput -match "Applied Group Policy Objects") { break }
    Start-Sleep -Seconds 5
    $tries++
} while ($tries -lt 3)

if ($gpoOutput -match "Applied Group Policy Objects") {
    $lines = $gpoOutput -split "`r?`n"
    $startIndex = ($lines | Select-String "Applied Group Policy Objects").LineNumber
    $appliedGPOs = @()
    for ($i = $startIndex; $i -lt $lines.Length; $i++) {
        $line = $lines[$i].Trim()
        if ($line -eq "") { break }
        if ($line -notmatch "Applied Group Policy Objects") {
            $appliedGPOs += $line
        }
    }

    if ($appliedGPOs.Count -gt 0) {
        $reportHtml += "<div><b>Applied Group Policies:</b><ul>"
        $appliedGPOs | ForEach-Object { $reportHtml += "<li>$_</li>" }
        $reportHtml += "</ul></div>"
    } else {
        $reportHtml += "<div><b>Applied Group Policies:</b> None found</div>"
    }
} else {
    $reportHtml += "<div><b>Applied Group Policies:</b> Failed to parse gpresult output</div>"
}

# -------------------
# Save to CSV, for data aggregation
# -------------------
Write-Host "[+] Exporting flat data to daily CSV for metrics aggregation..."

$userSummary = [PSCustomObject]@{
    Date                  = $Today
    Username              = $Username
    ComputerName          = $env:COMPUTERNAME
    Site                  = $site
    #LogonTime             = $start
    #LogonDuration         = "$($uptime.Hours)h $($uptime.Minutes)m"
    #FSLogixProfilePath    = if ($fs -and $fs.VHDOpenedFilePath) { $fs.VHDOpenedFilePath } else { "N/A" }
    #FSLogixSizeGB         = if ($fs -and $fs.VHDOpenedFilePath) { [math]::Round((Get-Item $fs.VHDOpenedFilePath).Length / 1GB, 2) } else { 0 }
    #ODFC_VHDX             = if ($vhd) { $vhd.FullName } else { "N/A" }
    ODFC_SizeGB           = if ($vhd) { [math]::Round($vhd.Length / 1GB, 2) } else { 0 }
    #OneDrivePath          = $oneDrivePath
    OneDriveSizeGB        = $oneDriveSize
    #MappedDrives          = if ($netDrives) { ($netDrives | ForEach-Object { "$($_.DeviceID):$($_.ProviderName)" }) -join "; " } else { "None" }
    #PrinterCount          = if ($printers) { $printers.Count } else { 0 }
    #DefaultGateway        = if ($ipConfig -and $ipConfig.IPv4DefaultGateway) { $ipConfig.IPv4DefaultGateway.NextHop } else { "N/A" }
    #Interface             = if ($ipConfig) { $ipConfig.InterfaceAlias } else { "N/A" }
    #IPAddress             = if ($ipConfig -and $ipConfig.IPv4Address) { $ipConfig.IPv4Address.IPAddress } else { "N/A" }
    #DNS                   = if ($ipConfig -and $ipConfig.DNSServer -and $ipConfig.DNSServer.ServerAddresses) { $ipConfig.DNSServer.ServerAddresses -join ", " } else { "N/A" }
    SystemModel           = $model
    OSName                = $extendedOsName
    #OSVersion             = $os.Version
    OSBuild               = $os.BuildNumber
    #WindowsVersion        = if ($os.Caption -like "*Windows 11*") { "Windows 11" } elseif ($os.Caption -like "*Windows 10*") { "Windows 10" } else { "Other" }
    SessionType           = if ($vmServices) { "VDI" } else { "Thick Client" }
    #SystemUptime          = "$($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m"
    #GroupCount            = if ($groups) { $groups.Count } else { 0 }
    #AppliedGPOs           = if ($appliedGPOs) { $appliedGPOs -join "; " } else { "None" }
}


$userSummary | Export-Csv -Path $CsvPath -Append -NoTypeInformation -Encoding UTF8 -Force
Write-Host "[✓] CSV data written to $CsvPath"

# -------------------
# Save HTML Report
# -------------------
Write-Host "[+] Saving HTML report to: $ReportPath"
try {
    $reportHtml += "</body></html>"
    $reportHtml | Out-File -FilePath $ReportPath -Encoding UTF8 -Force
    Write-Host "[✓] HTML report saved successfully."
} catch {
    Write-Host "[!] Failed to write HTML report"
}
