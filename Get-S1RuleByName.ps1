Param (
    [string]$RuleNameContains = $(throw "-RuleNameContains required!"),
    [switch]$RunQuery
)

$SiteURL = "https://yourconsole.sentinelone.net"
$APIkey = ""
$Expiration = "SecOps API Key: 2/14/2021"
$headers = @{"Authorization" = "APIToken $APIkey"; "Content-Type" = "application/json"}

$RuleQuery = Invoke-WebRequest -Headers $headers -Uri "$SiteURL/web/api/v2.1/cloud-detection/rules?name__contains=$RuleNameContains" # Rule name contains (returns only first result)

If ( $request.StatusCode -eq 401 ) { # API Expired
    Write-Host "The following SentinelOne API key has expired.`r`n$Expiration" -ForegroundColor Red
} Elseif ( $request.StatusCode -eq 400 ) { # API Error
    Write-Host "The query failed due to input validation or API changes." -ForegroundColor Red
} Else {
    $RuleInfo = $($RuleQuery.Content | ConvertFrom-Json | Select -ExpandProperty Data) | select -First 1
    $EncodedQuery = [System.Web.HttpUtility]::UrlEncode($RuleInfo.s1ql)
    $QueryURL = "$SiteURL/dv/hunting?queryString=$EncodedQuery"

    Write-Host $RuleInfo.s1ql -ForegroundColor Yellow
    If ($RunQuery) {
        [System.Diagnostics.Process]::Start($QueryURL) | Out-Null
    }
}
