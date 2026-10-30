$release = Invoke-RestMethod 'https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest'
$asset = $release.assets | Where-Object { $_.name -like '*PUBLIC*' -and $_.name -like '*.zip' } | Select-Object -First 1
if ($asset) {
    Write-Host "Tag: $($release.tag_name)"
    Write-Host "URL: $($asset.browser_download_url)"
    $asset.browser_download_url | Out-File -Encoding utf8 "C:\HK\COOP\coop-anything\tools\ghidra\ghidra_download_url.txt"
} else {
    Write-Host 'No PUBLIC zip asset found'
}