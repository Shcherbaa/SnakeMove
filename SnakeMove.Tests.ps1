BeforeAll {
    Import-Module "$PSScriptRoot\SnakeMove.psm1" -Force
}

Describe "Get-SnakeMove" {

    It "Returns exactly 5 results" {
        $results = Get-SnakeMove -Quiet
        $results.Count | Should -Be 5
    }

    It "Each result has all required properties" {
        $requiredProperties = @(
            "Technique",
            "MITRE_ID",
            "Status",
            "Risk",
            "Detail",
            "ComputerName",
            "ScanUser",
            "ScanTime"
        )
        $results = Get-SnakeMove -Quiet
        foreach ($result in $results) {
            foreach ($property in $requiredProperties) {
                $result.PSObject.Properties.Name | Should -Contain $property
            }
        }
    }

    It "Status values are always valid" {
        $validStatuses = @("OPEN", "PARTIAL", "CLOSED", "ERROR")
        $results = Get-SnakeMove -Quiet
        foreach ($result in $results) {
            $result.Status | Should -BeIn $validStatuses
        }
    }

    It "Risk values are always valid" {
        $validRisks = @("High", "Medium", "Low")
        $results = Get-SnakeMove -Quiet
        foreach ($result in $results) {
            $result.Risk | Should -BeIn $validRisks
        }
    }

    It "Returns PSCustomObject array" {
        $results = Get-SnakeMove -Quiet
        foreach ($result in $results) {
            $result | Should -BeOfType [PSCustomObject]
        }
    }

    It "ComputerName matches local machine" {
        $results = Get-SnakeMove -Quiet
        foreach ($result in $results) {
            $result.ComputerName | Should -Be $env:COMPUTERNAME
        }
    }

}
