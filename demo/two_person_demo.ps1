# End-to-end HIG-TLC demo: Alice sends a file to Bob over HTTP or HTTPS.
# Alice, Bob and the server each get their own folder, so nothing is shared except
# what would really cross the network: .pub files, ca.crt, and the sealed .hig.
#
#   powershell -ExecutionPolicy Bypass -File demo\two_person_demo.ps1            # HTTPS
#   powershell -ExecutionPolicy Bypass -File demo\two_person_demo.ps1 -Scheme http
param(
    [ValidateSet("https", "http")] [string]$Scheme = "https",
    [int]$Port = 8765,
    [int]$RadiusM = 300,
    [int]$MaxAccuracyM = 150
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$hig = Join-Path $root ".venv\Scripts\higtlc.exe"
$work = Join-Path $root "demo_run"
if (Test-Path $work) { Remove-Item -Recurse -Force $work }
$alice = New-Item -ItemType Directory -Force (Join-Path $work "alice")
$bob = New-Item -ItemType Directory -Force (Join-Path $work "bob")
$srv = New-Item -ItemType Directory -Force (Join-Path $work "server")
$env:HIGTLC_PASSPHRASE = "demo-passphrase"   # demo only: skips the passphrase prompts
$url = "${Scheme}://127.0.0.1:$Port"

function Step($text) { Write-Host "`n=== $text" -ForegroundColor Cyan }
function Run { & $hig @args; if ($LASTEXITCODE -ne 0) { throw "higtlc $($args[0]) failed" } }

Step "SERVER: start LTA + relay on $url"
$serveArgs = @("serve", "--state", "$srv\state", "--port", "$Port")
$caArgs = @()
if ($Scheme -eq "https") {
    Run tls-cert --host 127.0.0.1 --host localhost --out "$srv\certs"
    Copy-Item "$srv\certs\ca.crt" $alice; Copy-Item "$srv\certs\ca.crt" $bob
    $serveArgs += @("--tls-cert", "$srv\certs\server.crt", "--tls-key", "$srv\certs\server.key")
    $caArgs = @("--ca", "ca.crt")
}
$server = Start-Process -FilePath $hig -ArgumentList $serveArgs -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput "$srv\server.log" -RedirectStandardError "$srv\server.err"
try {
    Start-Sleep -Seconds 3

    Step "ALICE + BOB: create identities and swap public keys"
    Push-Location $alice; Run keygen --name alice --out alice.id; Pop-Location
    Push-Location $bob;   Run keygen --name bob --out bob.id;     Pop-Location
    Copy-Item "$bob\bob.pub" $alice
    Copy-Item "$alice\alice.pub" $bob

    Step "BOB: where will I open the file? (device location)"
    Push-Location $bob
    $loc = & $hig locate
    Pop-Location
    $loc | Write-Host
    if ($loc[0] -notmatch "lat=([-\d.]+) lon=([-\d.]+)") { throw "no location" }
    $lat, $lon = $Matches[1], $Matches[2]

    Step "ALICE: seal report.txt for bob.pub, ${RadiusM} m around ($lat, $lon), valid 1 hour, and send"
    Push-Location $alice
    "Quarterly numbers - for Bob's eyes only, at the office, today." | Set-Content -Encoding utf8 report.txt
    Run seal report.txt --from alice.id --to bob.pub --lta $url @caArgs `
        --circle "$lat,$lon,$RadiusM" --max-accuracy $MaxAccuracyM --not-after +1h --send
    Pop-Location

    Step "NETWORK VIEW: the sealed file contains no plaintext"
    $bytes = [IO.File]::ReadAllText("$alice\report.txt.hig")
    Write-Host ("plaintext visible in .hig: " + $bytes.Contains("Quarterly numbers"))

    Step "BOB: check inbox"
    Push-Location $bob
    Run inbox --id bob.id --server $url @caArgs

    Step "BOB (pretending to be 1000 km away): must be refused"
    Run receive --id bob.id --server $url @caArgs --sender alice.pub --open --lat ($([double]$lat) + 9) --lon $lon --accuracy 10

    Step "BOB (real device location): download, decrypt with private key, LTA checks place + time"
    Run receive --id bob.id --server $url @caArgs --sender alice.pub --open --delete
    Write-Host "`ncontent of received\report.txt:" -ForegroundColor Green
    Get-Content received\report.txt
    Pop-Location

    Step "SERVER AUDIT LOG"
    & (Join-Path $root ".venv\Scripts\python.exe") -c "import sqlite3,sys; [print(r) for r in sqlite3.connect(sys.argv[1]).execute('select ts,action,outcome,reason from audit')]" "$srv\state\lta.sqlite3"
}
finally {
    Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
}
