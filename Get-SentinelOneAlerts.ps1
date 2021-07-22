<#
Send MS Teams push notifications for SentinelOne Custom Rule Alerts.

Includes link to Storyline, prevents repeat alerts, checks last 40 minutes of alerts (assumes being run as SchedTask 30min), sends API error notifications.
#>

Import-Module PSTeams

$AppTitle = "Get-SentinelOneAlerts" # App name for error alerts
$Expiration = "SecOps API Key: 05/14/2023" # API Expiration note for teams alert
$APIkey = ""
$LastX = $(Get-Date).AddMinutes(-40) | Get-Date -Format 'yyyy-MM-ddThh:mm:sZ' # Current time/date minus 40 minutes
$TeamsID = "" # https://org.webhook.office.com/huh/huh/huh
$MessageTitle = "New SentinelOne Alert"
$TeamsMsgLimit = 5 # Max 5 alerts at once

$headers = @{"Authorization" = "APIToken $APIkey"; "Content-Type" = "application/json"}
$console = "" # https://location.sentinelone.huh
$query = "/web/api/v2.1/cloud-detection/alerts?reportedAt__gt=$LastX&limit=50"
$URI = $console + $query

$AlertDb = Join-Path $env:TEMP -ChildPath S1AlertIDs.dat
If (-Not(Test-path $AlertDb)) { Add-Content -Path $AlertDb -Value "" -Force }


$request = Invoke-WebRequest -Headers $headers -Uri $URI

If ( $request.StatusCode -eq 401 ) {
    Send-TeamsMessage -Uri $TeamsID -MessageTitle $AppTitle -MessageText "The following SentinelOne API key has expired.`r`n$Expiration" -Color Amber
} Elseif ( $request.StatusCode -eq 400 ) {
    Send-TeamsMessage -Uri $TeamsID -MessageTitle $AppTitle -MessageText "The query failed due to input validation or API changes." -Color Amber
} Else {
    $data = $request.Content | ConvertFrom-Json | Select -ExpandProperty Data
    $Unresolved = $data | where-object { $_.alertInfo.IncidentStatus -eq "Unresolved" }
    $c = 0
    While ( $c -le $TeamsMsgLimit ) {
        ForEach ($U in $Unresolved) {
            If ( Select-String -Path $AlertDb -Pattern $U.alertInfo.alertId -SimpleMatch -Quiet ) {
            } Else {
                Add-Content -Path $AlertDb -Value $U.alertInfo.alertId
                $c += 1
                $reported = $U.alertInfo.reportedAt | Get-Date
                $report = @"
**Reported:**`t`t $reported

**Resolved:**`t`t $($U.alertInfo.incidentStatus)

**Machine:**`t`t $($U.agentDetectionInfo.name)

**OS:**`t`t`t`t $($U.agentDetectionInfo.osName)

**Agent Ver:**`t`t $($U.agentDetectionInfo.version)

**Rule:**`t`t`t $($U.ruleInfo.name)

**Severity:**`t`t $($U.ruleInfo.severity)

**Remediation:**`t $($U.ruleInfo.treatAsThreat)

**Description:**`r`n $($U.ruleInfo.description)

**CommandLine:**`t $($U.sourceProcessInfo.commandline)

**UserName:**`t`t $($U.sourceProcessInfo.user)

**Storyline:**`t`t $($U.sourceProcessInfo.storyline)

"@
                $SLButton = New-TeamsButton -Name "Open Storyline" -Link "$($console)/dv?queryString=SrcProcStorylineId%20%3D%20%22$($U.sourceProcessInfo.storyline)%22%20OR%20TgtProcStorylineId%20%3D%20%22$($U.sourceProcessInfo.storyline)%22&timeFrame=Last7Days&isRunQuery=true"
                $SLSection = New-TeamsSection -Buttons $SLButton
                Send-TeamsMessage -Uri $TeamsID -MessageTitle $MessageTitle -MessageText $report -Color Amber -Sections $SLSection
            }
        }
    }
}
