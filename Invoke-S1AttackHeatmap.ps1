<#
Script aims to grab all Mitre Attack named Custom Rules and output a json attack map. Currently working through compat issues.
#>
Param (
    [String]$LayerName = $(throw "-LayerName required"),
    [String]$OutFile = $(throw "-OutFile required")
)
Import-Module PSExcel

# SecOps API Key (view only) - Expires 12/14/2021
$S1_APIkey = "my_api_key_hahahaha"
$S1_Console = "https://console.sentinelone.net/"

# AttackData pulled from tab 1 of Enterprise Techniques Excel file.
# https://attack.mitre.org/resources/working-with-attack/
$Techniques_Download = "https://attack.mitre.org/docs/enterprise-attack-v9.0/enterprise-attack-v9.0-techniques.xlsx"
If (-not( Test-Path -Path "C:\Windows\Temp\attack_techniques.xslx" )) {
    Invoke-WebRequest -Uri $Techniques_Download -UseBasicParsing -OutFile "C:\Windows\Temp\attack_techniques.xslx"
}
$AttackData = Import-XLSX -Path "C:\Windows\Temp\attack_techniques.xslx" -Header ID, name, description, url, created, 'last modified', version, tactics, detection, platforms, 'data sources', 'is sub-technique', 'sub-technique of', contributors, 'permissions required', 'defenses bypassed', 'supports remote'

$template = @"
{
	"name": "",
	"versions": {
		"attack": "9",
		"navigator": "4.3",
		"layer": "4.2"
	},
	"domain": "enterprise-attack",
	"description": "Auto imported from SentinelOne STAR rules.",
	"filters": {
		"platforms": [
			"Linux",
			"macOS",
			"Windows"
		]
	},
	"sorting": 0,
	"layout": {
		"layout": "side",
		"aggregateFunction": "average",
		"showID": false,
		"showName": true,
		"showAggregateScores": false,
		"countUnscored": false
	},
	"hideDisabled": true,
	"techniques": [],
	"gradient": {
		"colors": [
			"#ff6666",
			"#ffe766",
			"#8ec843"
		],
		"minValue": 0,
		"maxValue": 100
	},
	"legendItems": [
		{
			"label": "Blocked",
			"color": "#31a354"
		},
		{
			"label": "Detected and Remediate",
			"color": "#c7e9c0"
		},
		{
			"label": "Detect",
			"color": "#fcf26b"
		}
	],
	"metadata": [],
	"showTacticRowBackground": false,
	"tacticRowBackground": "#dddddd",
	"selectTechniquesAcrossTactics": true,
	"selectSubtechniquesWithParent": false
}
"@
$LayerData = $template | ConvertFrom-Json
$LayerData.Name = $LayerName

# Load custom detections from the STAR API
$headers = @{"Authorization" = "APIToken $S1_APIkey"; "Content-Type" = "application/json"}
$Uri = $S1_Console + "web/api/v2.1/cloud-detection/rules?limit=150&status=Active&expirationMode=Permanent"
$request = Invoke-WebRequest -Headers $headers -Uri $Uri # Get Custom Rules. Limited to 150 active and permanent rules.

If ( $request.StatusCode -eq 401 ) {
    Write-Host "The following SentinelOne API key has expired." -ForegroundColor Red
    Exit
} Elseif ( $request.StatusCode -eq 400 ) {
    Write-Host "The query failed due to input validation or API changes." -ForegroundColor Red
    Exit
} Else {
    $data = $request.Content | ConvertFrom-Json | Select -ExpandProperty Data
    $TechniqueList = New-Object System.Collections.Generic.List[System.Object]
    [System.Collections.ArrayList]$ProcessedTechniques = @()

    ForEach ( $rule in $data ) {
        If ( $rule.name -match '^T[0-9]{4}.*' ) { # match mitre named rules only
            $TechniqueID = $($rule.Name -split "\s+")[0]
            If (-Not( $processedTechniques -contains $TechniqueID )) {
                $tactics = $AttackData | Where-Object { $_.ID -eq $techniqueID } | Select tactics
                $tactics = $tactics.tactics -split ", "
                ForEach ( $tactic in $tactics ) {
                    $technique = [PSCustomObject]@{
                        techniqueID = ""
                        tactic = ""
                        color = ""
                        comment = ""
                        enabled = $true
                        metadata = "[]"
                        showSubtechniques = $false
                    }
                    $technique.techniqueID = $TechniqueID
                    $technique.tactic = $tactic

                    If ( $rule.treatAsThreat -eq "null" ) {
                        # No mitigation, suspicious or malicious
                        $technique.color = "#fcf26b"
                    } Else {
                        # Mitigation tied to detection
                        $technique.color = "#c7e9c0"
                    }
                    #$technique.comment = $rule.description
                    $TechniqueList.Add($technique)
                    $ProcessedTechniques.Add($TechniqueID) # Help dedupe json output, doesn't help add weight to map with colors for coverage
                }
            }
        }  
    }
    $LayerData.techniques = $TechniqueList
    $LayerData | ConvertTo-Json | Out-File $OutFile -Force
}
