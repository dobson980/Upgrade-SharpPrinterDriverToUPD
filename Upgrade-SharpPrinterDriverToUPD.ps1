<#
.SYNOPSIS 
    SBS Printer Driver Upgrade to Universal Print Driver
.DESCRIPTION 
    Installs SHARP UD2 PCL6 UPD to Driver Store.Installs SHARP UD2 PCL6 UPD. Upgrades existing Sharp Printers to UPD.
.EXAMPLE 
    Upgrade-SharpPrinterDriverToUPD
.NOTES 
    Name       : Upgrade-SharpPrinterDriverToUPD
    Author     : Tom Dobson & Radoslav Radoev
    Version    : 1.0
    DateCreated: 02-09-2018
    DateUpdated: 02-15-2018
        Changes: Better existing driver install detection
                 Logging verbosity
                 Variable scoping changes

.LINK 
#>


#region Defining Functions...

# Write log file
Function Write-Log
{
       [CmdletBinding()]
       Param (
              [Parameter(Mandatory = $False, HelpMessage = "Log Level")]
              [ValidateSet("INFO", "WARN", "ERROR", "FATAL", "DEBUG")]
              [string]$Level = "INFO",
              [Parameter(Mandatory = $True, Position = 0, HelpMessage = "Message to be written to the log")]
              [string]$Message,
              [Parameter(Mandatory = $False, HelpMessage = "Log file location and name")]
              [string]$Logfile = "C:\Temp\$DRIVER.log"
       )
    BEGIN {
       $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
           $Line = "$Stamp $Level $Message`r`n"
    }
    PROCESS {
       If ($Logfile) {
            [System.IO.File]::AppendAllText($Logfile, $Line)
           } Else {
                  Write-Output $Line
           }
    }
    END {}
} # END Write-Log


Function Upgrade-SharpPrinterDriverToUPD 
{

    # Variables and Constants
        if (-Not ($DRIVER)) 
    {
        New-Variable -Name "DRIVER" -Value "SHARP UD2 PCL6" -Option Constant
    }

    if (-Not ($DRIVERNAME)) 
    {
        New-Variable -Name "DRIVERNAME" -Value "SHARP UD2 PCL6,3,Windows x64" -Option Constant
    }
  
    #Validates the script is being run as admin
    Function Check-AdminRights {
        $Wid=[System.Security.Principal.WindowsIdentity]::GetCurrent()
        $Prp=new-object System.Security.Principal.WindowsPrincipal($Wid)
        $Adm=[System.Security.Principal.WindowsBuiltInRole]::Administrator
        $IsAdmin=$prp.IsInRole($Adm)
        return $IsAdmin
    }

    Function Check-ForSharpUPD {
             
        #Checks for Sharp UPD In Driver Store.
        $UPD = "$ENV:windir\System32\DriverStore\FileRepository\sfwemenu.inf_amd64_9a84be23a5070548\sfwemenu.inf"
        $WIN7UPD = "$ENV:windir\System32\DriverStore\FileRepository\sfwemenu.inf_amd64_neutral_9a84be23a5070548\sfwemenu.inf"
             
        If ((Test-Path $UPD) -or (Test-Path $WIN7UPD)) 
        {
            Write-Log "$DRIVER is already detected in the Driver Store."
            return $True
        } 
        Else 
        {
            Write-Log "Could not find $UPD." -Level WARN
            return $False
        }
    }

    Function Install-Driver {

        $infPath = "\\shcsd\sharp\drivers\Printers\Sharp Electronics\Sharp Universal Print Driver\EnglishA\PCL6\64bit\sfweMENU.inf"
        $certPath = "\\shcsd\sharp\drivers\Printers\Sharp Electronics\Sharp Universal Print Driver\SharpPrinterInstall.cer"

        certutil -addstore "TrustedPublisher" $certPath | Out-Null
        rundll32 printui.dll PrintUIEntry /ia /m $DRIVER /h "x64" /v "Type 3 - User Mode" /f $infPath
        certutil -delstore "TrustedPublisher" $certPath | Out-Null
        Write-Log "Installing $Driver"
    
    }


    Function Add-UPDtoDriverStore {

        #Adds Sharp UPD to Driver Store if its not already there.
        $installedPrinterDrivers = gwmi Win32_PrinterDriver

        if (-Not (Check-ForSharpUPD)) {
       
            Write-Log "$DRIVER is being added to Driver Store and Installed."
            Install-Driver

        } elseif ($installedPrinterDrivers.name -notcontains $DRIVERNAME) {

            Install-Driver

        } else {

            Write-Log "$DRIVER is in DriverStore and is already Installed."

        }
        #manual driver removal : printui /s /t2
    }

    Function Upgrade-ToUPD {

        #Upgrades Existing Sharp Drivers
        $installedPrinters = Get-WmiObject Win32_Printer


        for ($i = 1; $i -le 10; $i++) {
            Write-Log "Waiting for driver to load into store. Waiting for: $($i * 5) seconds"
            if (gwmi win32_printerdriver | where {$_.Name -match $DRIVER}) {break}
            Start-Sleep -Seconds 5
        }

        Write-Log "Checking for SHARP MX* printers"
        foreach($printer in ($installedPrinters|Where{$_.DriverName -like 'SHARP MX*'})){
            $name = $printer.name
            Write-Log "Upgrading $name to $DRIVER"
            & rundll32 printui.dll PrintUIEntry /Xs /n $name DriverName $DRIVER
        }
}

#endregion

#region Run Script   
    if (Check-AdminRights) {
        Add-UPDtoDriverStore
        Upgrade-ToUPD
    } else {
        $Message = "This script requires Admin Rights, please rerun as admin"
        Write-Log $Message -Level ERROR
        Write-Warning $Message
    }

#endregion   
}
