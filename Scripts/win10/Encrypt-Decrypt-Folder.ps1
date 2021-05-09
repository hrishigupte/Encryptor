param([Parameter(Mandatory=$true)][string][ValidateSet("--d","--e")]$Operation,
[Parameter()][string]$KeyFileLocation,
[Parameter()][string]$InputFolder,
[Parameter(Mandatory=$false)][string]$FileFilter,
[Parameter(Mandatory=$false)][bool]$RemoveFilesAfterEncryption,
[Parameter(Mandatory=$false)][bool]$Base64OutputOnly)
Import-Module Microsoft.Powershell.Security
#Import-Module System.Windows.Forms
Add-Type -AssemblyName System.Windows.Forms

$Encrypt_Directory = "C:\hrishi\Encryptor\win10-x64\publish"
$filter = "*.enc"
$remove = $false
<#
if( $args[0] -eq "--help")
{
    #echo "1st argument --d for Decryption or --e for Encryption"
    echo "Operation: --d for Decryption or --e for Encryption"
    #echo "2nd argument location of key file (public for encryption, private for decryption)"
    echo "KeyFileLocation location of key file (public for encryption, private for decryption)"
    #echo "3rd argument folder to be encrypted/decrypted"
    echo "InputFolder folder to be encrypted/decrypted"
    #echo "4th parameter (Optional) --base64 for decrypting only base64 encoded files"
    echo "Base64OutputOnly (true/false) for decrypting only base64 encoded files"
    #echo "5th parameter (Optional) filter to choose specific files to encrypt such as *.pdf, *.doc"
    echo "FileFilter filter to choose specific files to encrypt such as *.pdf, *.doc"
    #echo "6th parameter (Optional) --remove will remove the original file from the location after encryption"
    echo "RemoveFilesAfterEncryption (true/false) will remove the original file from the location after encryption"
    exit
}#>


if (($KeyFileLocation -eq $null) -or ($KeyFileLocation -eq ""))
{ 
    echo "Key File is required ... Please select Key File"
    $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{InitialDirectory = [System.Environment]::GetFolderPath('Desktop')}
    if ($Operation -eq "--d")
    {
        $FileBrowser.Filter='Private Key (*.pem)|*.pem' 
    }
    elseif ($Operation -eq "--e")
    {
        $FileBrowser.Filter='Public Key (*.pub)|*.pub' 
    }
    $null = $FileBrowser.ShowDialog()
    $KeyFileLocation = $FileBrowser.FileName
    if (($KeyFileLocation -eq $null) -or ($KeyFileLocation.Trim() -eq ""))
    {
        throw "Cannot proceed without Key File"
    }
}

$keyfile = $KeyFileLocation

if (($InputFolder -eq $null) -or ($InputFolder -eq ""))
{ 
    echo "Input Folder required ... Please select Input Folder"
    $FolderBrowserDialog = New-Object System.Windows.Forms.FolderBrowserDialog #-Property @{RootFolder = [System.Environment]::GetFolderPath('Desktop')}
    $null = $FolderBrowserDialog.ShowDialog()
    $InputFolder = $FolderBrowserDialog.SelectedPath
    if (($InputFolder -eq $null) -or ($InputFolder.Trim() -eq ""))
    {
        throw "Cannot proceed without Input Folder"
    }
}

#if ($args.Length -ilt 3 ) 
#{
#    echo "All requred arguments not provided"
#    exit
#}
#$keyfile = $args[1]



#if ($args[0] -eq "--d")
if ($Operation.Trim() -eq "--d")
{
   # if ($args.Length -ge 4)
   # {
   #     for($i=3;$i -le $args.Length-1;$i++)
   #     {
   #         echo $args[$i]
   #         switch($args[$i]) 
   #         {
   #             "--base64" { $filter ="*.enc.base64"; break }
   #             "--remove" {$remove=$true; break}
   #         }
   #     }
    #}
    if ($FileFilter.Trim() -ne "")
    {
        if( $FileFilter -match "\*\.{1}[a-z,A-Z]*$")
        {
            if ($Base64OutputOnly)
            {
                $filter = "$FileFilter.enc.base64"
            }
            else
            {
                $filter = "$FileFilter.enc"
            }
        }
    }
    
    echo "Filter to be applied :$filter"
    echo "Operation: $Operation"
    $index = $filter.LastIndexOf(".")
    $replacefilter = $filter.Substring(1,$filter.Length -1)
    $pvkeyflag = $false
    $pvkeypwd = ""
    Read-Host -Prompt "Is the Private Key Encrypted" -OutVariable ispvkeyencrypted
    if (($ispvkeyencrypted -eq "Yes") -or ($ispvkeyencrypted -eq "yes"))
    {
        $pvkeyflag = $true
        $pvkeypwd = Read-Host -Prompt "Please enter Private Key Password" -AsSecureString
    }

    echo "Starting Decryption process"
    #foreach ($result in Get-ChildItem -Path $args[2] -File -Recurse -Filter $filter)
    foreach ($result in Get-ChildItem -Path $inputfolder -File -Recurse -Filter $filter)
    {
        echo "Decrypting $result"
        #echo "$pvkeyflag"
       
        #echo $pvpwd
                
        $outputfilename = $result.FullName.Replace($replacefilter,"")
        $inputfilename = $result.FullName
        if ($pvkeyflag)
        {
             $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pvkeypwd)
             $pvpwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            #echo  "--d --k $keyfile --i ""$inputfilename"" --o ""$outputfilename"" --privatekeypassword ""$pvpwd"""
            Start-Process -NoNewWindow -Wait -FilePath "$Encrypt_Directory\Encryptor.exe" -ArgumentList "--d --k $keyfile --privatekeypassword ""$pvpwd"" --i ""$inputfilename"" --o ""$outputfilename""" -OutVariable $message
        }
        else 
        {
            Start-Process -NoNewWindow -Wait -FilePath "$Encrypt_Directory\Encryptor.exe" -ArgumentList "--d --k $keyfile --i ""$inputfilename"" --o ""$outputfilename""" -OutVariable $message
        }
        echo $message
        #echo "--d --k $keyfile --i $inputfilename --o $outputfilename"
    }
    exit
} 

#if ($args.Length -ge 4)
#{
#    for($i=3;$i -le $args.Length-1;$i++)
#    {
#        echo $args[$i]
#        switch($args[$i]) 
#        {
#            "--remove" {$remove=$true; break}
#            default {if ($args[$i] -match "\*\."){$filter=$args[$i];} break}
#        }
#    }
#}
if ($removefilesafterencryption)
{
    $remove=$true
}

#if ($args[0] -eq "--e")
if ($operation -eq "--e")
{
    echo "Starting Encryption process"
    #foreach ($result in Get-ChildItem -Path $args[2] -File -Recurse -Filter $filter)
    if( $FileFilter -match "\*\.{1}[a-z,A-Z]*$")
    {
        $filter = $FileFilter
    }
    else 
    {
        $filter = "*.*"
    }
    foreach ($result in Get-ChildItem -Path $inputfolder -File -Recurse -Filter $filter -Exclude "*.enc,*.enc.info,*.enc.base64")
    {
        echo "Encrypting $result"
        $outputfilename = $result.FullName + ".enc"
        $inputfilename = $result.FullName
        if ($Base64OutputOnly)
        {
            -Process -NoNewWindow -Wait -FilePath "$Encrypt_Directory\Encryptor.exe" -ArgumentList "--e --k $keyfile --base64 --i ""$inputfilename"" --o ""$outputfilename"""
        }
        else
        {
            Start-Process -NoNewWindow -Wait -FilePath "$Encrypt_Directory\Encryptor.exe" -ArgumentList "--e --k $keyfile --i ""$inputfilename"" --o ""$outputfilename"""
        }
        if ($remove)
        {
            echo "Removing " + $result.FullName
            Remove-Item $result.FullName

        }
        #echo "--e --k $keyfile --i $inputfilename --o $outputfilename"
    }


}

Function TestKeyPath()
{
   
}
#Start-Process -FilePath C:\hrishi\Encryptor\win10-x64\Encryptor.exe -ArgumentList $args