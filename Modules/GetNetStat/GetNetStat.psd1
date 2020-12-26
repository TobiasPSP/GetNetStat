

@{

# Module Loader File
RootModule = 'GetNetStat.psm1'

# Version Number
ModuleVersion = '1.0'

CompatiblePSEditions = @('Desktop', 'Core')

# Unique Module ID
GUID = 'f17e4420-a7de-4230-a03c-9d28b08f1d8b'

# Module Author
Author = 'tobia'

# Company
CompanyName = 'https://powershell.one'

# Copyright
Copyright = '(c) 2021 Dr. Tobias Weltner. All rights reserved.'

# Module Description
Description = 'implements a fast alternative to netstat.exe'

# Minimum PowerShell Version Required
PowerShellVersion = '5.1'

# Name of Required PowerShell Host
PowerShellHostName = ''

# Minimum Host Version Required
PowerShellHostVersion = ''

# Minimum .NET Framework-Version
DotNetFrameworkVersion = ''

# Minimum CLR (Common Language Runtime) Version
CLRVersion = ''

# Processor Architecture Required (X86, Amd64, IA64)
ProcessorArchitecture = ''

# Required Modules (will load before this module loads)
# RequiredModules = @()

# Required Assemblies
# RequiredAssemblies = @()

# PowerShell Scripts (.ps1) that need to be executed before this module loads
# ScriptsToProcess = @()

# Type files (.ps1xml) that need to be loaded when this module loads
# TypesToProcess = @()

# Format files (.ps1xml) that need to be loaded when this module loads
FormatsToProcess = @("connection.format.ps1xml")

# 
# NestedModules = @()

# List of exportable functions
FunctionsToExport = 'Get-NetStat','Resolve-HostNameProperty'

# List of exportable cmdlets
# CmdletsToExport = '*'

# List of exportable variables
# VariablesToExport = '*'

# List of exportable aliases
# AliasesToExport = '*'

# List of all modules contained in this module
# ModuleList = @()

# List of all files contained in this module
# FileList = @()

# Private data that needs to be passed to this module
PrivateData          = @{

        PSData = @{

            # Tags applied to this module. These help with module discovery in online galleries.
            Tags       = @(
                'Network'
                'netstat'
                'Resolve'
                'DNS'
                'Threading'
                'powershell.one'
                'Windows'
                'MacOS'
                'Linux'
            )

            # A URL to the license for this module.
            #LicenseUri = 'https://github.com/xxx/blob/master/LICENSE'

            # A URL to the main website for this project.
            # ProjectUri = 'https://github.com/xxx'

            # A URL to an icon representing this module.
            # IconUri = ''

            # ReleaseNotes of this module
            # ReleaseNotes = ''

        } # End of PSData hashtable

    } # End of PrivateData hashtable

}