$content = [System.IO.File]::ReadAllBytes('C:\Program Files (x86)\Steam\steamapps\common\SleepingDogsDefinitiveEdition\sdhdship.exe')
$sb = New-Object System.Text.StringBuilder
$results = @()
foreach ($byte in $content) {
    if ($byte -ge 32 -and $byte -le 126) {
        [void]$sb.Append([char]$byte)
    } else {
        if ($sb.Length -ge 4) {
            $s = $sb.ToString()
            if ($s -match '(?i)(unreal|cryengine|havok|engine|steam|network|replication|lobby|matchmaking|physx|fmod|wwise|scaleform|directx|d3d|dxgi|gamebryo|unity|ue4|ue5|rage|source|id tech|bullet|awesomium|cef|chromium|steamworks|steam_api|steamclient|steamnetworking|p2p|relay|natpunch|upnp|stun|turn|ice|dtls|srtp|webrtc|openssl|mbedtls|wolfssl)') {
                $results += $s.Substring(0, [Math]::Min(200, $s.Length))
            }
        }
        $sb.Clear()
    }
}
if ($sb.Length -ge 4) {
    $s = $sb.ToString()
    if ($s -match '(?i)(unreal|cryengine|havok|engine|steam|network|replication|lobby|matchmaking|physx|fmod|wwise|scaleform|directx|d3d|dxgi|gamebryo|unity|ue4|ue5|rage|source|id tech|bullet|awesomium|cef|chromium|steamworks|steam_api|steamclient|steamnetworking|p2p|relay|natpunch|upnp|stun|turn|ice|dtls|srtp|webrtc|openssl|mbedtls|wolfssl)') {
        $results += $s.Substring(0, [Math]::Min(200, $s.Length))
    }
}
$results | Sort-Object -Unique | Select-Object -First 50