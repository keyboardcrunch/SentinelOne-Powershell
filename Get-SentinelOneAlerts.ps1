<#
Send MS Teams push notifications for SentinelOne Custom Rule Alerts.
Includes link to Storyline, prevents repeat alerts, notifies on unresolved only, checks last 2 days of alerts, sends API error notifications.

I have this running as a 10min scheduled task tied to MS Teams for push notifications with useful details and links for investigating,
without having to copy paste rule queries and run them manually in DV. 
#>

Import-Module PSTeams

$SiteURL = "https://yourconsole.sentinelone.net"
$APIkey = "API_KEY"
$Expiration = "SecOps API Key: 10/13/2022"
$TeamsID = "https://yourcompany.webhook.office.com/webhookb2/webby-web-hook"
$MsgLimit = 10 # limits push notifications
$AppTitle = "Get-SentinelOneAlerts"
$MessageTitle = "New SentinelOne Alert"

$headers = @{"Authorization" = "APIToken $APIkey"; "Content-Type" = "application/json"}
$DateGreater = $(get-date).AddDays(-1) | Get-Date -Format "yyyy-MM-ddT00:00:00.000000Z" # Last 2 days of alert API results
$NotificationDB = Join-Path $env:TEMP -ChildPath "s1adb.dat"

# NotificationDB maintenance
If ( -Not ( Test-Path $NotificationDB ) ) { New-Item -Path $NotificationDB -ItemType File | Out-Null } # Create missing file
If ( $(Get-Item $NotificationDB).Length -gt 4000 ) { New-Item -Path $NotificationDB -ItemType File -Force | Out-Null } # Null file if over 4Mb
$db = get-content $NotificationDB

# Pull API Data
$request = Invoke-WebRequest -Headers $headers -Uri "$SiteURL/web/api/v2.1/cloud-detection/alerts?reportedAt__gt=$DateGreater"

#$U.alertInfo.alertId

If ( $request.StatusCode -eq 401 ) { # API Expired
    Send-TeamsMessage -Uri $TeamsID -MessageTitle $AppTitle -MessageText "The following SentinelOne API key has expired.`r`n$Expiration" -Color Amber
} Elseif ( $request.StatusCode -eq 400 ) { # API Error
    Send-TeamsMessage -Uri $TeamsID -MessageTitle $AppTitle -MessageText "The query failed due to input validation or API changes." -Color Amber
} Else {
    $data = $request.Content | ConvertFrom-Json | Select -ExpandProperty Data
    $Unresolved = $data | where-object { $_.alertInfo.IncidentStatus -ne "Resolved" }

    $counter = 0
    ForEach ( $U in $Unresolved ) {
        If ( $counter -le $MsgLimit ) {
            If ( -Not ( $db -contains $U.alertInfo.alertId ) ) {
                $counter++ # increment counter
                $U.alertInfo.alertId | Out-File $NotificationDB -Append | Out-Null # log alertId to db
                $reported = $U.alertInfo.reportedAt | Get-Date
                $RuleQuery = Invoke-WebRequest -Headers $headers -Uri "$SiteURL/web/api/v2.1/cloud-detection/rules?ids=$($U.ruleInfo.id)" # Snag rule query for 'Run Rule' button/link
                $RuleInfo = $RuleQuery.Content | ConvertFrom-Json | Select -ExpandProperty Data
                $EncodedQuery = [System.Web.HttpUtility]::UrlEncode($RuleInfo.s1ql)
                $QueryURL = "$SiteURL/dv/hunting?queryString=$EncodedQuery"

                New-AdaptiveCard -Uri $TeamsID {
                    New-AdaptiveTextBlock -Size ExtraLarge -Weight Bolder -Text $MessageTitle
                    New-AdaptiveContainer {
                        New-AdaptiveColumnSet {
                            New-AdaptiveColumn {
                                New-AdaptiveFactSet {
                                    New-AdaptiveFact -Title "Rule" -Value $($U.ruleInfo.name)
                                    New-AdaptiveFact -Title "Description" -Value $($U.ruleInfo.description)

                                    New-AdaptiveFact -Title "Reported" -Value $reported
                                    New-AdaptiveFact -Title "Resolved" -Value $($U.alertInfo.incidentStatus)
                                    New-AdaptiveFact -Title "Machine" -Value $($U.agentDetectionInfo.name)
                                    New-AdaptiveFact -Title "OS" -Value $($U.agentDetectionInfo.osName)
                                    New-AdaptiveFact -Title "Agent Version" -Value $($U.agentDetectionInfo.version)
                                    New-AdaptiveFact -Title "Severity" -Value $($U.ruleInfo.severity)
                                    New-AdaptiveFact -Title "Remediation" -Value $($U.ruleInfo.treatAsThreat)
                            
                                    New-AdaptiveFact -Title "Process" -Value $($U.sourceProcessInfo.filePath)
                                    New-AdaptiveFact -Title "Commandline" -Value $($U.sourceProcessInfo.commandline)
                                    New-AdaptiveFact -Title "Username" -Value $($U.sourceProcessInfo.user)
                                }
                            } -Width Auto
                        }
                    } -Spacing None

                } -Action {
                    New-AdaptiveAction -Title 'Open Storyline' -Type Action.OpenUrl -ActionUrl "$SiteURL/dv?queryString=SrcProcStorylineId%20%3D%20%22$($U.sourceProcessInfo.storyline)%22%20OR%20TgtProcStorylineId%20%3D%20%22$($U.sourceProcessInfo.storyline)%22&timeFrame=Last7Days&isRunQuery=true"
                    New-AdaptiveAction -Title 'Run Rule' -Type Action.OpenUrl -ActionUrl "$QueryURL"
                }
            }
        }
    }
}
