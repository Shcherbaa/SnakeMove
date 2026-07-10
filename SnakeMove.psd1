@{
    RootModule        = 'SnakeMove.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '377c3a00-fc92-4c18-a3c5-cddbc0536f3f'
    Author            = 'Ihar Shcharbitski'
    Description       = 'Enumerates lateral movement opportunities on Windows hosts. Maps findings to MITRE ATT&CK T1021.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Get-SnakeMove')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags         = @('Security', 'PenTest', 'MITRE', 'LateralMovement', 'Windows', 'OffensiveSecurity', 'Audit', 'RedTeam')
            ProjectUri   = 'https://github.com/Shcherbaa/SnakeMove'
            LicenseUri   = 'https://github.com/Shcherbaa/SnakeMove/blob/main/LICENSE'
            ReleaseNotes = 'Initial public release. Five lateral movement checks mapped to MITRE ATT&CK T1021, with console, CSV, and HTML report output.'
        }
    }
}