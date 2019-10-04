function Find-ADUser{
    <#
    .SYNOPSIS
    Retrieve user's account usernames based on First and/or Last name or the SAM Account Name
    .DESCRIPTION
    The Find-User function uses the Get-ADUser cmdlet to query Active Directory for all users
    .Parameter FN
    The full or partial first name of one user.
    NOTE: When providing both the first and the last name, the last name variable (LN) will not act as a wildcard.
    .Parameter LN
    The full or partial last name of one, or many users.
    NOTE: When providing both the first and the last name, the last name variable (LN) will not act as a wildcard.
    .Parameter SAM
    The full or partial SAM number or string for a user
    .Parameter v
    Pass this switch for a very verbose output of the user(s)
    .INPUTS
    None
    .OUTPUTS
    None
    .NOTES
    Version:        1.0
    Author:         Jon Duarte
    Creation Date:  06132017
    Purpose/Change: Initial script development

    .EXAMPLE
    Find-User -FN Jon
    .EXAMPLE
    Find-User -LN Duarte
    .EXAMPLE
    Find-User -LN Dua
    .EXAMPLE
    Find-User -FN Jon -LN Duarte
    .EXAMPLE
    Find-User -FN Jon,Eddie,Pavan
    .EXAMPLE
    Find-User -SAM 1111234
    .EXAMPLE
    Find-User.ps1 -FN Jon -LN Duarte -v


    #>
    #---------------------------------------------------------[Script Parameters]------------------------------------------------------
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)] [string]$FN,

        [Parameter(Mandatory=$false)] [string[]]$LN,

        [Parameter(Mandatory=$false)] [string[]]$SAM,

        [Parameter(Mandatory=$false)] [string]$SAMFile,

        [Parameter(mandatory=$false)] [switch]$RunningLog,

        [Parameter(mandatory=$false)] [switch]$CSV
    )
    #---------------------------------------------------------[Initialisations]--------------------------------------------------------

    #Set Error Action to Silently Continue
    $ErrorActionPreference = 'Stop'

    #Import Modules & Snap-ins
    Import-Module PoshRSJob
    Import-Module ActiveDirectory

    #----------------------------------------------------------[Declarations]----------------------------------------------------------


    #Any Global Declarations go here
    $computerName = $env:COMPUTERNAME
    $ScriptRoot=$PSScriptRoot
    $ScriptLogTime = Get-Date -format "yyyyMMddmmss"
    $ScriptName = (Get-Item $PSCommandPath).Basename
    $LogDirectory = $ScriptRoot
    $PSVersionReturned=$PSVersionTable.PSVersion
    $Date = Get-Date

    if($RunningLog){
    $ScriptLog= "$LogDirectory\$ScriptName`_$ScriptLogTime.log"
    }else {
    $ScriptLog= "$LogDirectory\$ScriptName.log"
    }
    #-----------------------------------------------------------[Functions]------------------------------------------------------------
    function Script_Information {
        param ()
        $Date.DateTime
        Write-Output "Computer Name: $computerName"
        Write-Output "PowerShell Version $PSVersionReturned"
        Write-Output "ScriptRoot: $ScriptRoot"
        Write-Output "ScriptName: $ScriptName"
        Write-output "ScriptLog: $ScriptLog"
    }
    function Test-FileLock {
        param ([parameter(Mandatory=$true)][string]$Path)
        $oFile = New-Object System.IO.FileInfo $Path
        if ((Test-Path -Path $Path) -eq $false){
            return $false
        }
        try{
            $oStream = $oFile.Open([System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            if ($oStream){
            $oStream.Close()
            }
            $false
        }catch{
            # file is locked by a process.
            return $true
        }
    }
    Function psjob_cleanup{
        Param()
        Write-output "Attempting to clean up the jobs"
        Get-RSJob | Remove-RSJob
    }
    Function Main {
        Param ()
        Begin {
            Write-Output '<description of what is going on>...'
            $StopWatch = [System.diagnostics.stopwatch]::StartNew()
            Script_Information
        }
        Process {
            Try {
                write-output '<code goes here>'
                #----Initialize Variables----#
                ##Mail Variables
                $ScriptBlock= {
                    # Parameter help description
                    Param($LoginInScriptBlock)
                    $LoginInScriptBlock
                    $SearchBase = "DC=usa,DC=ccu,DC=clearchannel,DC=com"
                    Try{
                        Get-ADUser -Filter "SamAccountName -eq '$LoginInScriptBlock'" -SearchBase $SearchBase -Verbose
                    }Catch{
                        Write-error $psitem -Verbose
                    }
                }
                #----Do work----#
                #If-Elses to check what has been passed
                if ($FN -and $LN)
                {
                    Write-Host "It appeats both first and last name were passed"
                    $filter = "GivenName -like '$FN*' -And Surname -like '$LN*'"
                    $UserInfo = Get-ADUser -Filter $filter
                    $UserInfo
                }
                elseif ($LN)
                {
                    Write-Host "Using last name only"
                    ForEach ($lastname in $LN)
                    {
                        write-host "$lastname"
                        $UserInfo = Get-ADUser -Filter "Surname -like '$lastname*'"
                        $UserInfo
                    }
                }
                elseif ($FN)
                {
                    Write-Host "Using first name only"
                    ForEach ($firstname in $FN)
                    {
                        write-host "$firstname"
                        $UserInfo = Get-ADUser -Filter "GivenName -like '$firstname*'"
                        $UserInfo
                    }
                }
                elseif ($SAMFile)
                {
                    Write-Host "Using Sam"
                    $SAMFile=$(Get-ChildItem $SAMFile).FullName
                    Write-Verbose "Testing if file exists"
                    If($False -eq (Test-Path -Path $SAMFile))
                    {
                        Write-Error "Files does not exist" -ErrorAction Stop
                    } elseif (condition) {

                    }


                    ##Check if files were passed, use files
                    if( $False -eq $([string]::IsNullOrWhitespace($SAMFile)) ){
                        Write-Output "Database File passed: $SAMFile"
                        $SAMFile_count=$(Get-Content $SAMFile | Measure-Object -line).Lines
                        Write-Verbose "Lines in passed file: $SAMFile_count"
                        #Use parallel threads
                        Try{
                            Write-Verbose "Attemtempting to start parallel job threads"
                            Get-Content $SAMFile | start-rsjob -ScriptBlock $ScriptBlock -ModulesToImport ActiveDirectory -Throttle 10 -ArgumentList $Login
                        }Catch{
                            psjob_cleanup
                            Write-error $psitem -Verbose
                        }

                        Write-output "Waiting for jobs to finish"
                        Get-rsjob | wait-rsjob -ShowProgress

                        $FailedJobs=Get-RSjob | Where-Object {($_.State -eq 'Failed') -or ($_.HasErrors -eq $true)}

                        if($FailedJobs){
                            Write-Output "Failed Jobs:"
                            $FailedJobs | Get-rsjob | Receive-rsjob
                            Write-Output "Successfull Jobs:"
                            $UserInfo= Get-rsjob | Receive-rsjob | Where-Object -Property state -NE 'Failed'
                        }Else{
                            Write-output "No Failed jobs were detected"
                            $UserInfo= Get-rsjob | Receive-rsjob
                        }

                        If($False -eq $CSV){
                            $UserInfo
                        }
                        #Clean up Jobs
                        psjob_cleanup
                    }

                }elseif($SAM){
                    ForEach ($samAccount in $SAM)
                    {
                        write-host "$samAccount"
                        $UserInfo=Get-ADUser -Filter "SamAccountName -like '*$samAccount'"
                        $UserInfo
                    }
                }

                If($CSV){
                    $csvpath = "$ScriptRoot\$Scriptname.csv"
                    Write-Output "Attempting to create to csv file: $csvpath"
                    Try{
                        $UserInfo | Select-Object -Property name,SamAccountName,Enabled | Export-Csv -Path $csvpath -NoTypeInformation
                    }Catch{
                        psjob_cleanup
                        Write-Error $psitem -Verbose
                    }
                }
            }Catch{
                Write-error $PSItem
            }
        }
        End {
            If ($?) {
            write-output 'Completed Successfully.'
            $StopWatch.Stop()
            Write-Output "Elapsed Seconds $($StopWatch.Elapsed.TotalSeconds)"
            }
        }
    }
    #-----------------------------------------------------------[Execution]------------------------------------------------------------
    #Call main
    if(Test-FileLock -Path $ScriptLog){
        $ScriptLog= "$LogDirectory\$ScriptName`_$ScriptLogTime.log"
    }
    Main *>&1 | Tee-Object $ScriptLog
}