Set-Alias -Name sudo -Value Start-ElevatedPowerShell | out-null
Set-Alias -Name sdate -Value get-sdate | out-null
 

Function Get-HostPid
{
 Foreach($p in (Get-Process pwsh))
  {
   if ($p.StartTime.Touniversaltime() -match
       (Get-Date).ToUniversalTime())
     { $host | Add-Member -NotePropertyName PID -NotePropertyValue ($p.ID)}
    }
}

function Format-TimeSpan {
    process {
      "{0:00} Days {1:00} Hours {2:00} Minutes" -f $_.Days,$_.Hours,$_.Minutes
    }
  }

function foldersize {
  param($path = ".")
  if($path -eq "-?" -or  $path -eq "?"  ){Write-host "Example: foldersize .";Write-host "Example: foldersize C:\users\public"}
  else
  {   
    $colItems = (Get-ChildItem $Path -recurse | Measure-Object -property length -sum) 
    if (($colItems.sum / 1GB) -gt 999)
    {
    "{0:N2}" -f ($colItems.sum /1TB) + " TB"
    }
    else
    {
    "{0:N2}" -f ($colItems.sum /1GB) + " GB"
    } 
      
  }
 }

Function Start-ElevatedPowerShell
{ Start-Process Pwsh -Verb Runas }

function Search {
  #add -Recurse option
  param ($term,$r)
  if(!$r){
    Get-ChildItem -Path .\* -Include $term}
  else{
    Get-ChildItem -Path .\* -Include $term -Recurse}
}

function sshb {
  param (
    [string]$pc = $(write-host " Example: sshb pi@192.168.1.106 `r`n For basic auth only no keys")
    )
  &ssh.exe -o PubkeyAuthentication=no $pc
}

function Title{
   param ($title)
$host.UI.RawUI.WindowTitle = $Title
}

Function get-sdate
{ (Get-date).tostring("yyyy-MM-dd-HH_mm_ss_ffff") }

function Uptime {
  param($computername)
  if($null -eq $computername ){Write-host "Example: uptime computername";}
  else{  
  $os = Get-WmiObject Win32_OperatingSystem  -ComputerName $computername 
  $lastBootTime = [Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
  Write-Output "Uptime: $((Get-Date) - $lastBootTime | Format-TimeSpan)"
  Write-Output "Last Boot: $($lastBootTime.tostring("MM-dd-yyyy-HH:mm"))"
     }
  }
#Commands
Set-Location c:\scripts
Get-HostPid
Write-host "Profile C:\Program Files\PowerShell\7\Profile.ps1"
Write-host -ForegroundColor Yellow "Custom function names: foldersize, search, sdate, sshb, sudo, title, uptime"
