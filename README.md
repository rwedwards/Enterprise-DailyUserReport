# Enterprise-UserReport.ps1

## Overview
This PowerShell script is designed for **daily diagnostics and reporting** on enterprise Windows environments, supporting both **VDI** and **thick clients**. It collects key system and user session data, builds a visually formatted **HTML report**, and outputs **CSV summaries** for aggregation and monitoring.

> Authored by: Richard Edwards for Company Name  
> Permission Level: Standard user (non-privileged)

---

## Features

- Gathers system and session info:
  - User logon time and duration
  - Site location (based on logon server)
  - FSLogix profile status and size
  - ODFC (OneDrive Files On-Demand Container) checks
  - OneDrive path and size
  - Network-mapped drives and printers
  - Operating system name/version/build
  - Environment variables
  - AD group memberships
  - Group Policy Objects (via `gpresult`)
- HTML report generated per user and day
- CSV output for aggregation (includes OS release, session type, etc.)
- Supports shared network storage output
- Built-in rotation logic to clean up old reports

---

## Output Structure

```
EnterpriseReports\
├── Sherlock.Holmes\
│   ├── 2025-06-18\
│   │   ├── Enterprise-UserReport-Richard.Edwards-2025-06-18.html
│   │   └── ...
├── John.Doe\
│   └── 2025-06-18\
│       └── Enterprise-UserReport-John.Doe-2025-06-18.html
DailyCSVs\
├── Enterprise-UserReport-Aggregated-2025-06-18.csv
```

> *Each user's daily HTML report is stored in a structured folder format by username and date.*  
> *The daily aggregated CSV includes all users who ran the script that day.*

---

## Configuration Notes

Update these paths as needed:

```powershell
# For HTML report storage
$ReportRoot = "C:\Users\$env:USERNAME\Downloads"
# For CSV aggregation (to be updated to DFS share)
$CsvShareRoot = "C:\Users\$env:USERNAME\Downloads"
```

> 💡 Recommended: Update `$ReportRoot` to `\\Domainl\Share\EnterpriseReports` and `$CsvShareRoot` to your daily CSV share once testing is complete.

---

## CSV Fields (customizable)

The default exported fields include:
- `Date`, `Username`, `ComputerName`, `Site`
- `OneDriveSizeGB`, `ODFC_SizeGB`
- `SystemModel`, `OSName`, `OSVersion`, `OSBuild`, `BuildLab`
- `SessionType` (VDI vs Thick Client)

You can reorder or comment out fields directly in the `$userSummary` object block.

---

## Prerequisites

- PowerShell 5.1 or later
- AD module (for `Get-ADUser`)
- Permissions to read registry, environment vars, FSLogix keys
- Network access to ODFC profile shares (if applicable)

---

## Example Use

Run manually or via a scheduled task on login:

```powershell
.\Enterprise-UserReport.ps1
```

---

## Cleanup Logic

Old report directories (older than 7 days) are automatically deleted from the report root for each user.

---

## Security Notes

- Does **not require elevated permissions**
- Only gathers session-local data
- CSV/HTML are saved in user-writable paths unless otherwise configured

---

## To-Do / Future Enhancements

- Export to central syslog or database
- Email report via SMTP
- Add CPU/RAM diagnostics
- Track failed logins or lockouts

---

##Contact

Maintained by: **Richard Edwards**  
For use within Windows Enterprise environments

