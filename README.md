# Enterprise-DailyUserReport
A lightweight PowerShell logon script for capturing VDI and thick-client user session diagnostics in DoD STIG-compliant environments.
🔍 Features

     FSLogix Profile + ODFC Container detection (VHDX / O365_Diff)
     OneDrive usage + path
     Mapped drives (WMI-based)
     Mapped printers (clean names)
     VDI detection via VMware Tools
     Logon time + time since login
     Network info (gateway, IP, DNS)
     Environment variables (select)
     System uptime
     Optional slow logon metrics
     HTML-based, timestamped reports
     Works in non-elevated, user logon context

Output

Reports are saved as:
\\Domain\Path_to_share\$Username\UserReport_YYYY-MM-DD_HH-mm.html
     Ensure users have write access to this share. The script will create folders automatically per user.

Setup Instructions

     Copy Enterprise-DailyUserReport.ps1 to a shared location or SYSVOL path.
     Assign via GPO
        User Configuration → Policies → Windows Settings → Scripts (Logon)
        Add Enterprise-DailyUserReport.ps1
     Customize base path in script:
    BasePath = "\\Domain\Path_to_share\$Username"
         Done. Reports will generate per user, per logon.

 Platform Compatibility
    Windows Server 2019/2022
    Windows 11 Enterprise (23H2)
    VMware Horizon VDI
    FSLogix Profile Containers
    DoD STIG-hardened environments

 Requirements
    PowerShell 5.1+
    No elevation required
    No external modules
    Works under standard user context

 Example Output
Username: John.Doe
Computer Name: Windows113344
Date: 06/18/2025 10:59
Session Type: VDI (VMware Tools Detected)
Mapped Drives: Z:\ ➜ \\server\share
Mapped Printers: \\printserver\P3204
FSLogix Profile: \\server\FSLogix\profile.vhdx
ODFC Container: \\server\FSLogix\ODFC_John.Doe.vhdx
System Uptime: 11 hrs 36 min

