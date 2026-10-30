$url = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip"
$outputPath = "C:\HK\COOP\coop-anything\tools\ghidra\ghidra_12.1.4_PUBLIC_20260921.zip"
$extractPath = "C:\HK\COOP\coop-anything\tools\ghidra"

Write-Host "Downloading Ghidra 12.1.4..."
Invoke-WebRequest -Uri $url -OutFile $outputPath -UseBasicParsing

Write-Host "Download complete. Extracting..."
Expand-Archive -Path $outputPath -DestinationPath $extractPath -Force

Write-Host "Extraction complete."
Write-Host "Contents:"
Get-ChildItem "$extractPath\ghidra_12.1.4_PUBLIC" -Force