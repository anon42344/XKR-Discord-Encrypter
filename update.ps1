.\xkr_discord_encrypter\extrascript.ps1

del xkr_discord_encrypter -R


$url = "https://github.com/anon42344/XKR-Discord-Encrypter/archive/master.zip"
$output = "$PSScriptRoot\master.zip"
$start_time = Get-Date

Import-Module BitsTransfer
Start-BitsTransfer -Source $url -Destination $output

Expand-Archive -Force master.zip .

del master.zip


Move-Item -Path ".\XKR-Discord-Encrypter-master\xkr_discord_encrypter" -Destination "."

del XKR-Discord-Encrypter-master -R


pause