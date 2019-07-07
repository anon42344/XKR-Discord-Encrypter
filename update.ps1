$url = "https://github.com/anon42344/XKR-Discord-Encrypter/archive/master.zip"
$output = "$PSScriptRoot\master.zip"
$start_time = Get-Date

Import-Module BitsTransfer
Start-BitsTransfer -Source $url -Destination $output

Expand-Archive -Force C:\Users\admin\Downloads\xkr-update\master.zip .

del master.zip

del XKR-Discord-Encrypter-master -R

Move-Item -Path "C:\Users\admin\Downloads\xkr-update\XKR-Discord-Encrypter-master\xkr_discord_encrypter" -Destination "C:\Users\admin\Downloads\xkr-update"
