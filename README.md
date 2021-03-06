posh-pingdom
============

API Wrapper for Pingdom

[https://www.pingdom.com/features/api/documentation/](https://www.pingdom.com/features/api/documentation/)

Implemented Interfaces
----

- Get-PingdomActions [API](https://www.pingdom.com/features/api/documentation/#MethodGet+Actions+%28Alerts%29+List "Get Actions")
- Get-PingdomAnalysis [API](https://www.pingdom.com/features/api/documentation/#MethodGet+Root+Cause+Analysis+Results+List "Get Root Cause Analysis Results List")
- Get-PingdomAnalysisRaw [API](https://www.pingdom.com/features/api/documentation/#MethodGet+Raw+Analysis+Results "Get Raw Analysis Results")
- Get-PingdomCheck [API](https://www.pingdom.com/features/api/documentation/#MethodGet+Check+List "Get Check List")
- New-PingdomCheck [API](https://www.pingdom.com/features/api/documentation/#MethodCreate+New+Check "Create New Check")
- Set-PingdomCheck [API](https://www.pingdom.com/features/api/documentation/#MethodModify+Check "Modify Check")
- Set-PingdomBulkCheck [API](https://www.pingdom.com/features/api/documentation/#MethodModify+Multiple+Checks "Modify Multiple Checks")

Examples
----

    # View A List of Checks
    $secpasswd = ConvertTo-SecureString 'password' -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential ('username', $secpasswd)

    $authParams = @{Credential = $cred
                ApiKey = "abc123xyz456"}

    $checks = Get-PingdomCheck @authParams

    $checks.checks | select Name, Hostname, @{n="LastTestTime";e={ConvertFrom-UnixTimestamp -TimeStamp $_.lasttesttime}}, Status | ft -AutoSize