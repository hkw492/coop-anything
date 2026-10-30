$JAVA_HOME = "C:\Program Files\Microsoft\jdk-21.0.12.101-hotspot"
$env:PATH = "$JAVA_HOME\bin;$env:PATH"

$ghidraSupport = "C:\HK\COOP\coop-anything\tools\ghidra\ghidra_12.1.4_PUBLIC\support"
$projectDir = "C:\HK\COOP\coop-anything\tools\ghidra_projects"
$projectName = "SleepingDogsFresh"
$binaryPath = "C:\HK\COOP\coop-anything\local\sleeping-dogs-test\sdhdship.exe"
$scriptPath = "C:\HK\COOP\coop-anything\tools\ghidra_scripts"
$scriptName = "AnalyzeUE3.java"
$logPath = "C:\HK\COOP\coop-anything\local\sleeping-dogs-test\ghidra_fresh_log.txt"

Write-Host "Starting fresh Ghidra project with Java script..."
Write-Host "JAVA_HOME: $JAVA_HOME"

Set-Location $ghidraSupport

$cmd = "& .\analyzeHeadless.bat `"$projectDir`" `"$projectName`" -import `"$binaryPath`" -scriptPath `"$scriptPath`" -postScript $scriptName -deleteProject"
Write-Host "Command: $cmd"

$output = Invoke-Expression $cmd 2>&1
$output | Out-File -FilePath $logPath -Encoding utf8
Write-Host "Analysis complete. Exit code: $LASTEXITCODE"
Write-Host "Log written to: $logPath"
Get-Content $logPath