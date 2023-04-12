#==========================================================================================
#
# SCRIPT NAME        :     AD-Password-Updater-KeePass.ps1
#
# AUTHOR             :     Louis GAMBART
# CREATION DATE      :     2023.04.12
# RELEASE            :     v1.3.0
# USAGE SYNTAX       :     .\AD-Password-Updater-KeePass.ps1
#
# SCRIPT DESCRIPTION :     This script updates the passwords of the users in Active Directory and in Keypass
#
#==========================================================================================

#                 - RELEASE NOTES -
# v1.0.0  2023.04.12 - Louis GAMBART - Initial version
# v1.1.0  2023.04.12 - Louis GAMBART - Change keypass secret management using external file
# v1.2.0  2023.04.12 - Louis GAMBART - Rework of new-password generation using .NET classes
# v1.3.0  2023.04.12 - Louis GAMBART - Add ShouldProcess to function where PSScriptAnalyzer ask for it
#
#==========================================================================================


###################
#                 #
#  I - VARIABLES  #
#                 #
###################

# clear error variable
$error.clear()

# get the name of the host
[String] $hostname = $env:COMPUTERNAME

# keypass infos
[SecureString] $keypassPassword = Get-Content -Path "secret.txt" | ConvertTo-SecureString
[String] $keypassProfileName = ""
[String] $keypassGroupPath = ""

# set the users search scope
[String] $usersOU = ""
[String] $usersEmployeeType = ""

####################
#                  #
#  II - FUNCTIONS  #
#                  #
####################

function Get-Datetime {
    <#
    .SYNOPSIS
    Get the current date and time
    .DESCRIPTION
    Get the current date and time
    .INPUTS
    None
    .OUTPUTS
    System.DateTime: The current date and time
    .EXAMPLE
    Get-Datetime | Out-String
    2022-10-24 10:00:00
    #>
    [CmdletBinding()]
    [OutputType([System.DateTime])]
    param()
    begin {}
    process { return [DateTime]::Now }
    end {}
}


function Write-Log {
    <#
    .SYNOPSIS
    Write log message in the console
    .DESCRIPTION
    Write log message in the console
    .INPUTS
    System.String: The message to write
    System.String: The log level
    .OUTPUTS
    None
    .EXAMPLE
    Write-Log "Hello world" "Verbose"
    VERBOSE: Hello world
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateSet('Error', 'Warning', 'Information', 'Verbose', 'Debug')]
        [string]$LogLevel = 'Information'
    )
    begin {}
    process {
        switch ($LogLevel) {
            'Error' { Write-Error $Message -ErrorAction Stop }
            'Warning' { Write-Warning $Message -WarningAction Continue }
            'Information' { Write-Information $Message -InformationAction Continue }
            'Verbose' { Write-Verbose $Message -Verbose }
            'Debug' { Write-Debug $Message -Debug Continue }
            default { throw "Invalid log level: $_" }
        }
    }
    end {}
}


function Find-Module {
    <#
    .SYNOPSIS
    Check if a module is installed
    .DESCRIPTION
    Check if a module is installed
    .INPUTS
    System.String: The name of the module
    .OUTPUTS
    System.Boolean: True if the module is installed, false otherwise
    .EXAMPLE
    Check-Module -ModuleName 'ActiveDirectory'
    True
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$ModuleName
    )
    begin {}
    process {
        $module = Get-Module -Name $ModuleName -ListAvailable
        if ($module) {
            return $true
        } else {
            return $false
        }
    }
    end {}
}


function Find-KeyPass-Configuration {
    <#
    .SYNOPSIS
    Check if the KeePass configuration exist
    .DESCRIPTION
    Check if the KeePass configuration exist
    .INPUTS
    System.String: The path to the KeePass database
    .OUTPUTS
    System.Boolean: True if the KeePass configuration is valid, false otherwise
    .EXAMPLE
    Find-KeyPass-Configuration -Name 'test'
    True
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )
    begin {}
    process {
        if (!(Get-KeePassDatabaseConfiguration -DatabaseProfileName $Name)) { return $false }
        else { return $true }
    }
    end {}
}


function Find-Keypass-Group {
    <#
    .SYNOPSIS
    Check if a KeePass group exist
    .DESCRIPTION
    Check if the KeePass group exist
    .INPUTS
    System.String: The path of the KeePass group
    .OUTPUTS
    System.Boolean: True if the KeePass group exist, false otherwise
    .EXAMPLE
    Find-Keypass-Group -GroupPath 'test/test'
    True
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$GroupPath
    )
    begin {}
    process {
        if (!(Get-KeePassGroup -DatabaseProfileName $keypassProfileName -KeePassGroupPath $GroupPath -MasterKey $keypassPassword)) { return $false }
        else { return $true }
    }
    end {}
}


function Update-AD-Account-Password {
    <#
    .SYNOPSIS
    Update the password of an AD account
    .DESCRIPTION
    Update the password of an AD account
    .INPUTS
    System.String: The name of the AD account
    System.String: The new password of the AD account
    .OUTPUTS
    None
    .EXAMPLE
    Update-AD-Account-Password -AccountName 'test' -Password 'test'
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$AccountName,
        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [SecureString]$Password,
        [Switch]$Force
    )
    begin { $account = Get-ADUser -Identity $AccountName -Properties * -ErrorAction SilentlyContinue }
    process {
        if ($account) {
            if ($PSCmdlet.ShouldProcess($AccountName, "Update the password of the account $AccountName") -or $Force) {
                $account | Set-ADAccountPassword -Reset -NewPassword $Password
            }
        } else {
            Write-Log "The account $AccountName doesn't exist!" 'Error'
        }
    }
    end {}
}


function New-Password {
    <#
    .SYNOPSIS
    Generate a random password
    .DESCRIPTION
    Generate a random password with a specific length, containing uppercase, lowercase, numbers and special characters
    .INPUTS
    None
    .OUTPUTS
    SecureString: The generated password
    .EXAMPLE
    New-Password
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([SecureString])]
    param(
        [Switch]$Force
    )
    begin {
        $passwordLength = 24
        $specialCharacters = 4..8 | Get-Random
        Add-Type -AssemblyName System.Web
    }
    process {
        if ($PSCmdlet.ShouldProcess("Generate a password", "Generate a password") -or $Force) {
            do {
                $newPassword = [System.Web.Security.Membership]::GeneratePassword($passwordLength, $specialCharacters)
                if ( ($newPassword -cmatch "[A-Z\p{Lu}\s]") -and ($newPassword -cmatch "[a-z\p{Ll}\s]") -and ($newPassword -match "[\d]") -and ($newPassword -match "[\w]") ) {
                    $passComplexCheck = $true
                }
            } while ($passComplexCheck -ne $true)
        }
    }
    end { return (ConvertTo-SecureString -String $newPassword -AsPlainText -Force) }
}


function Update-KeyPass-Entry {
    <#
    .SYNOPSIS
    Update a KeePass entry
    .DESCRIPTION
    Update a KeePass entry
    .INPUTS
    System.String: The name of the KeePass entry
    System.String: The path of the KeePass group
    SecureString: The new password of the KeePass entry
    .OUTPUTS
    None
    .EXAMPLE
    Update-KeyPass-Entry -EntryName 'test' -GroupPath 'test/test' -Password 'test'
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$EntryName,
        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$GroupPath,
        [Parameter(Mandatory = $true, Position = 2)]
        [ValidateNotNullOrEmpty()]
        [SecureString]$Password,
        [Switch]$Force
    )
    begin {
        $entry = Get-KeePassEntry -DatabaseProfileName $keypassProfileName -MasterKey $keypassPassword -Title $EntryName
    }
    process {
        if ($PSCmdlet.ShouldProcess($EntryName, "Update the password of the entry $EntryName") -or $Force) {
            Update-KeePassEntry -DatabaseProfileName $keypassProfileName -KeePassEntry $entry -KeePassEntryGroupPath $GroupPath -KeePassPassword $Password -MasterKey $keypassPassword -Force
        }
    }
    end {}
}


function New-KeyPass-Entry {
    <#
    .SYNOPSIS
    Create a KeePass entry
    .DESCRIPTION
    Create a KeePass entry
    .INPUTS
    System.String: The path of the KeePass group
    System.String: The name of the KeePass entry
    System.String: The username of the KeePass entry
    SecureString: The password of the KeePass entry
    System.String: The URL of the KeePass entry
    .OUTPUTS
    None
    .EXAMPLE
    New-KeyPass-Entry -GroupPath 'test/test' -EntryName 'test' -Username 'test' -Password 'test' -URL 'test'
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$GroupPath,
        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$EntryName,
        [Parameter(Mandatory = $true, Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string]$Username,
        [Parameter(Mandatory = $true, Position = 3)]
        [ValidateNotNullOrEmpty()]
        [SecureString]$Password,
        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateNotNullOrEmpty()]
        [string]$URL,
        [Switch]$Force
    )
    begin {}
    process {
        if ($PSCmdlet.ShouldProcess($EntryName, "Create the entry $EntryName") -or $Force) {
            New-KeePassEntry -DatabaseProfileName $keypassProfileName -KeePassEntryGroupPath $GroupPath -Title $EntryName -UserName $Username -KeePassPassword $Password -URL $URL -MasterKey $keypassPassword
        }
    }
    end {}
}


function Find-KeyPass-Entry {
    <#
    .SYNOPSIS
    Find a KeePass entry
    .DESCRIPTION
    Find a KeePass entry
    .INPUTS
    System.String: The name of the KeePass entry
    .OUTPUTS
    System.Boolean: True if the KeePass entry exists, False otherwise
    .EXAMPLE
    Find-KeyPass-Entry -EntryName 'test'
    True
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$EntryName
    )
    begin {}
    process {
        if (!(Get-KeePassEntry -DatabaseProfileName $keypassProfileName -MasterKey $keypassPassword -Title $EntryName)) { return $false }
        else { return $true }
    }
    end {}
}


#########################
#                       #
#  III - ERROR HANDLER  #
#                       #
#########################

# trap errors
trap {
    Write-Log "An error has occured: $_" 'Error'
}


###########################
#                         #
#  IV - SCRIPT EXECUTION  #
#                         #
###########################

Write-Log "Starting script on $hostname at $(Get-Datetime)" 'Verbose'
if (Find-Module -ModuleName 'PoShKeePass') {
    try { Import-Module -Name 'PoShKeePass' }
    catch { Write-Log "Unable to import the PoShKeePass module: $_" 'Error' }
    if (!(Find-KeyPass-Configuration -Name $keypassProfileName)) { Write-Log "The KeePass configuration doesn't exist! Please refer to 'New-KeePassDatabaseConfiguration' command to create it." 'Error' }
    if (!(Find-Keypass-Group -GroupPath $keypassGroupPath)) { Write-Log "Your KeePass group doesn't exist!" 'Error' }

    $accounts = Get-ADUser -Filter "employeeType -eq $usersEmployeeType" -SearchBase $usersOU | Select-Object SamAccountName, DisplayName

    foreach ($account in $accounts) {
        if (!(Find-KeyPass-Entry -EntryName $account.SamAccountName)) {
            Write-Log "Creating KeyPass entry for $($account.DisplayName) - $($account.SamAccountName)" 'Verbose'
            $NewPassword = New-Password -Force
            Update-AD-Account-Password -Account $account.SamAccountName -Password $NewPassword -Force
            New-KeyPass-Entry -GroupPath $keypassGroupPath -EntryName $account.SamAccountName -Username $account.SamAccountName -Password $NewPassword -URL $account.DisplayName -Force
        } else {
            Write-Log "Updating KeyPass entry for $($account.DisplayName) - $($account.SamAccountName)" 'Verbose'
            $NewPassword = New-Password -Force
            Update-AD-Account-Password -Account $account.SamAccountName -Password $NewPassword -Force
            Update-KeyPass-Entry -EntryName $account.SamAccountName -GroupPath $keypassGroupPath -Password $NewPassword -Force
        }
    }
} else {
    Write-Log "The PoShKeePass module is not installed! Please run 'Install-Module -Name PoShKeePass' to install it." 'Error'
}