# Setup pre-commit hooks (PowerShell)
# Usage: .\scripts\setup-pre-commit.ps1

Write-Host "Installing pre-commit..." -ForegroundColor Green
pip install pre-commit

Write-Host "Installing pre-commit hooks..." -ForegroundColor Green
pre-commit install

Write-Host "Running pre-commit on all files (first time)..." -ForegroundColor Yellow
pre-commit run --all-files

Write-Host "Pre-commit hooks installed successfully!" -ForegroundColor Green
Write-Host "Hooks will now run automatically on 'git commit'" -ForegroundColor Cyan
