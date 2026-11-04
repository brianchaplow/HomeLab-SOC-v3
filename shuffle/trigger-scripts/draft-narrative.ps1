# Trigger WF-NARRATIVE (Escalation Narrative Drafter) for a TheHive case.
# Usage: .\draft-narrative.ps1 923
# The draft posts to the #soc-alerts Discord channel; edit and approve before
# carrying it into the ticket. Runs on demand from ADMIN-WS - no cron entry.
param(
    [Parameter(Mandatory = $true)][int]$CaseNumber
)

$WF_ID = "5bdf5dd7-8d5a-4efc-bdf8-e080b99e7cca"
$BACKEND = "http://172.20.2.14:5001"

$envLine = Get-Content "C:\Projects\.env" | Where-Object { $_ -match '^SHUFFLE_API_KEY=' }
if (-not $envLine) { throw "SHUFFLE_API_KEY not found in C:\Projects\.env" }
$key = $envLine -replace '^SHUFFLE_API_KEY=', ''

$arg = @{ case_number = $CaseNumber } | ConvertTo-Json -Compress
$body = @{ execution_argument = $arg } | ConvertTo-Json -Compress

$r = Invoke-RestMethod -Uri "$BACKEND/api/v1/workflows/$WF_ID/execute" -Method Post `
    -Headers @{ Authorization = "Bearer $key" } -ContentType 'application/json' `
    -Body $body -TimeoutSec 30
Write-Output "WF-NARRATIVE started for case #$CaseNumber (execution $($r.execution_id))"
Write-Output "Draft will arrive in #soc-alerts within ~1-2 minutes."
