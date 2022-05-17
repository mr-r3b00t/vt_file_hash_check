# Quick Example for SHA256 Hashing of files in a directory and checking virus total using v2 of the PUBLIC API
# required an API key - is rate limited
# idea from Pry0c
# use at own risk
# crappy script by mRr3b00t
# add ur own API key etc.

$apikey = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

cd C:\users\tenet\Desktop\test

#One liner to create hash report
Get-ChildItem -Recurse -Force -File | Get-FileHash -Algorithm SHA256 | Export-Csv -Path c:\users\tenet\documents\hashes1.csv -NoTypeInformation


#Object based method for granular actions

$files = Get-ChildItem -Recurse -Force -File

foreach($file in $files){
write-host "Sleeping for 15 seconds..." -ForegroundColor Cyan

#Sleep for 15 seconds to not hit the api limit
Start-Sleep -Seconds 15

#get file hash
$hash = Get-FileHash -Algorithm SHA256 -Path $file.FullName
$hash.Hash
$hash.Algorithm
$hash.Path
#call Virus Total
$request = @{resource = $hash.Hash; apikey = $apikey}
$APILookup = Invoke-RestMethod -Method GET -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body $request

if($APILookup.response_code -eq 0){write-host "Not found in virus total"}

else{

$APILookup.resource
$APILookup.response_code
$APILookup.verbose_msg
$APILookup.positives
$APILookup.total
$APILookup.scan_date
$APILookup.permalink
$APILookup | Export-Csv C:\users\tenet\Documents\malwaredetections.csv -Append -Force -NoTypeInformation
}
                     

}
