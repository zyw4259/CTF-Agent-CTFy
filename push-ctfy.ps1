$ErrorActionPreference = 'Stop'

$image = 'ctf-agent-ctfy:v3'
$reference = 'registry.ctfy.io/687ab0c2-68a7-4474-8198-9d76d2b9f123/ctf-agent:v3'
$secureToken = Read-Host 'Enter the CTFy token (input is hidden)' -AsSecureString
$pointer = [IntPtr]::Zero
$token = $null
$loggedIn = $false

try {
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
    $token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    $token | docker login registry.ctfy.io --username ctfy-agent --password-stdin
    if ($LASTEXITCODE -ne 0) { throw 'Docker registry login failed.' }
    $loggedIn = $true

    docker tag $image $reference
    if ($LASTEXITCODE -ne 0) { throw 'Docker image tag failed.' }

    docker push $reference
    if ($LASTEXITCODE -ne 0) { throw 'Docker image push failed.' }

    Write-Host "Published image: $reference"
}
finally {
    $token = $null
    if ($pointer -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
    if ($secureToken) { $secureToken.Dispose() }
    if ($loggedIn) { docker logout registry.ctfy.io | Out-Null }
}
