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
    .INPUTS
    None
    .OUTPUTS
    None
    .NOTES
    Version:        2.0
    Author:         Jon Duarte
    Creation Date:  Tuesday, October 8, 2019 11:19:58
    Purpose/Change: A bunch of changes

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
    Find-User.ps1 -SAMFILE listofsams.txt
    .EXAMPLE
    Find-User.ps1 -SAMFILE listofsams.txt -CSV
    #>
    #---------------------------------------------------------[Script Parameters]------------------------------------------------------
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)] [string]$FN
        ,[Parameter(Mandatory=$false)] [string[]]$LN
        ,[Parameter(Mandatory=$false)] [string[]]$SAM
        ,[Parameter(Mandatory=$false)] [string]$SAMFile
        ,[Parameter(mandatory=$false)] [switch]$CSV
        ,[Parameter(mandatory=$false)] [switch]$RunningLog
        ,[Parameter(mandatory=$false)] [string]$LogDirectory
        ,[Parameter(mandatory=$false)] [switch]$NoLog
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
$script = $MyInvocation.MyCommand.Name
$scriptName = [IO.Path]::GetFileNameWithoutExtension($Script)
$ScriptLogTime = Get-Date -format "yyyyMMddmmss"
$PSVersionReturned=$PSVersionTable.PSVersion
$Date = Get-Date
if ($NoLog){
    #Do not create a log file
    Write-Verbose "No log file switch passed"
    Write-Verbose "Getting PWD"
    $PresentWorkingDirectory = Get-Location
}Else{
    Write-Verbose "Getting PWD"
    $PresentWorkingDirectory = Get-Location
    #Did you pass your own directory for the log?
    if($PSBoundParameters.ContainsKey('LogDirectory')){
        Write-Verbose "Log Directory Passed"
        Write-Verbose $LogDirectory
    }Else{
        $LogDirectory = $PresentWorkingDirectory
    }
    #Create a unique log file
    if($RunningLog){
        Write-Verbose "Running Log switch passed"
        $ScriptLog= "$LogDirectory\$ScriptName`_$ScriptLogTime.log"
    }else {
        $ScriptLog= "$LogDirectory\$ScriptName.log"
    }
}
#-----------------------------------------------------------[Functions]------------------------------------------------------------
function Script_Information {
    param ()
    Write-Verbose "Function: $($MyInvocation.MyCommand)"
    Write-Verbose $Date.DateTime
    Write-Verbose "Computer Name: $computerName"
    Write-Verbose "PowerShell Version $PSVersionReturned"
    Write-Verbose "ScriptName: $ScriptName"
    Write-Verbose "Present Working Directory: $PresentWorkingDirectory"
    if($False -eq $NoLog){
        Write-Verbose "ScriptLog: $ScriptLog"
    }
}
Function psjob_cleanup{
  Param()
  Write-output "Attempting to clean up the jobs"
  Get-RSJob | Remove-RSJob
}
#-----------------------------------------------------------[Main]------------------------------------------------------------
    Function Main {
        Param ()
        Begin {
            Write-Output 'Starting'
            $StopWatch = [System.diagnostics.stopwatch]::StartNew()
            Script_Information
        }
        Process {
            Try {
                #----Initialize Variables----#
                $SearchBase = "DC=usa,DC=ccu,DC=clearchannel,DC=com"
                $ScriptBlock= {
                    # Parameter help description
                    Param($LoginInScriptBlock)
                    $LoginInScriptBlock
                    Try{
                        Get-ADUser -Filter "SamAccountName -eq '$LoginInScriptBlock'" -SearchBase $Using:SearchBase -Verbose
                    }Catch{
                        Write-error $psitem -Verbose
                    }
                }
                #----Do work----#
                #If-Elses to check what has been passed
                if ($FN -and $LN)
                {
                    Write-Host "It appears both first and last name were passed"
                    $filter = "GivenName -like '$FN*' -And Surname -like '$LN*'"
                    $UserInfo = Get-ADUser -Filter $filter -SearchBase $SearchBase
                    $UserInfo
                }
                elseif ($LN)
                {
                    Write-Host "Using last name only"
                    ForEach ($lastname in $LN)
                    {
                        write-host "$lastname"
                        $UserInfo = Get-ADUser -Filter "Surname -like '$lastname*'" -SearchBase $SearchBase
                        $UserInfo
                    }
                }
                elseif ($FN)
                {
                    Write-Host "Using first name only"
                    ForEach ($firstname in $FN)
                    {
                        write-host "$firstname"
                        $UserInfo = Get-ADUser -Filter "GivenName -like '$firstname*'" -SearchBase $SearchBase
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
                    }


                    ##Check if files were passed, use files
                    if( $False -eq $([string]::IsNullOrWhitespace($SAMFile)) ){
                        Write-Output "SAm File passed: $SAMFile"
                        $SAMFile_count=$(Get-Content $SAMFile | Measure-Object -line).Lines
                        Write-Verbose "Lines in passed file: $SAMFile_count"
                        #Use parallel threads
                        Write-Verbose "Attemtempting to start parallel job threads"
                        Try{
                            Get-Content $SAMFile | start-rsjob -ScriptBlock $ScriptBlock -ModulesToImport ActiveDirectory -ArgumentList $Login -ErrorAction Stop | Out-Null
                        }Catch{
                            psjob_cleanup
                            Write-error $psitem -Verbose
                        }

                        Write-output "Waiting for jobs to finish"
                        Get-rsjob | wait-rsjob -ShowProgress | Out-Null

                        $FailedJobs=Get-RSjob | Where-Object {($_.State -eq 'Failed') -or ($_.HasErrors -eq $true)}

                        if($FailedJobs){
                            Write-Output "Failed Jobs:"
                            $FailedJobs | Format-Table -AutoSize
                            Write-Output "Failed Job Output:"
                            $FailedJobs | Get-rsjob | Receive-rsjob
                            Write-Output "Successfull Jobs:"
                            $AllObjects= Get-rsjob | Where-Object {$_.State -eq 'Completed' -and ($_.HasErrors -eq $False)} | Receive-rsjob
                        }Else{
                            Write-output "No Failed jobs were detected"
                            $AllObjects= Get-rsjob | Receive-rsjob
                        }

                        $AllObjects

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
                psjob_cleanup
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
    if($NoLog){
        Main *>&1
    }Else{
        Main *>&1 | Tee-Object $ScriptLog
    }
}
