<#
Send MS Teams push notifications for SentinelOne Custom Rule Alerts.

Includes link to Storyline, prevents repeat alerts, checks last 40 minutes of alerts (assumes being run as SchedTask 30min), sends API error notifications.
#>

Import-Module PSTeams

# SecOps API Key (view only) - Expires 12/14/2021
$AppTitle = "Get-SentinelOneAlerts"
$Expiration = "SecOps API Key: 12/14/2021"
$APIkey = "MY_API_KEY_HERE" # CHANGE THIS
$headers = @{"Authorization" = "APIToken $APIkey"; "Content-Type" = "application/json"}
$SiteURL = "https://console.sentinelone.net" # CHANGE THIS


$TeamsID = "https://organizationhere.webhook.office.com/webhookb2/234345/IncomingWebhook/asdf223f23"
$MessageTitle = "New SentinelOne Alert"
$MsgLimit = 3 # limits query for alerts


$request = Invoke-WebRequest -Headers $headers -Uri "$SiteURL/web/api/v2.1/cloud-detection/alerts?limit=$MsgLimit"

If ( $request.StatusCode -eq 401 ) {
    Send-TeamsMessage -Uri $TeamsID -MessageTitle $AppTitle -MessageText "The following SentinelOne API key has expired.`r`n$Expiration" -Color Amber
} Elseif ( $request.StatusCode -eq 400 ) {
    Send-TeamsMessage -Uri $TeamsID -MessageTitle $AppTitle -MessageText "The query failed due to input validation or API changes." -Color Amber
} Else {
    $data = $request.Content | ConvertFrom-Json | Select -ExpandProperty Data
    $Unresolved = $data | where-object { $_.alertInfo.IncidentStatus -eq "Unresolved" }

    ForEach ($U in $Unresolved) {
        $reported = $U.alertInfo.reportedAt | Get-Date
        $RuleQuery = Invoke-WebRequest -Headers $headers -Uri "$SiteURL/web/api/v2.1/cloud-detection/rules?ids=$($U.ruleInfo.id)"
        $RuleInfo = $RuleQuery.Content | ConvertFrom-Json | Select -ExpandProperty Data
        $EncodedQuery = [System.Web.HttpUtility]::UrlEncode($RuleInfo.s1ql) # URLEncode query for link creation
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
