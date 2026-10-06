param([Parameter(Mandatory=$true)][string]$RepositoryUrl)
$ErrorActionPreference='Stop'
Set-Location $PSScriptRoot
if ($RepositoryUrl -notmatch '^https://(github\.com|gitlab\.com)/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(\.git)?/?$') { throw 'Provide your empty GitHub/GitLab HTTPS repository URL.' }
if (Test-Path -LiteralPath '.git') { throw 'This folder already has Git history. Inspect it rather than reinitializing.' }
if (!(Get-Command git -ErrorAction SilentlyContinue)) { throw 'Install Git for Windows first.' }
git init -b main
if ($LASTEXITCODE -ne 0) { throw 'Git initialization failed.' }
git add .
if ($LASTEXITCODE -ne 0) { throw 'Git staging failed.' }
git commit -m 'CS6338 Milestone 2: architecture, schema, prompts and source-derived benchmarks'
if ($LASTEXITCODE -ne 0) { throw 'Commit failed. Configure your Git name/email, then inspect before retrying.' }
git remote add origin $RepositoryUrl
if ($LASTEXITCODE -ne 0) { throw 'Remote setup failed.' }
git push -u origin main
if ($LASTEXITCODE -ne 0) { throw 'Push failed; preserve this folder. No force push was attempted.' }
Write-Host 'Repository checkpoint uploaded. Submit its URL with the design PDF.'
