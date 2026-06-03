# PowerShell wrapper for healthcheck
$env:BASE_URL = $env:BASE_URL -or 'http://localhost:3000'
node .\healthcheck.js
exit $LASTEXITCODE
