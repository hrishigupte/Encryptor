param([Parameter(Mandatory=$true)][string][ValidateSet("--d","--e")]$Operation,
[Parameter()][string]$KeyFileLocation,
[Parameter()][string]$InputFolder,
[Parameter(Mandatory=$false)][string]$FileFilter,
[Parameter(Mandatory=$false)][bool]$RemoveFilesAfterEncryption,
[Parameter(Mandatory=$false)][bool]$Base64OutputOnly=$true)
Import-Module Microsoft.Powershell.Security
Add-Type -AssemblyName System.Windows.Forms

$Encrypt_Directory = "..\publish"
$filter = "*.enc"
$remove = $false

echo "NOTE: The script is defaulted to process Base64 output files for Decryption Operation, Base64OutputOnly should be set to false to output binary file"
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

if ($Operation.Trim() -eq "--d")
{

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
    Read-Host -Prompt "Is the Private Key Encrypted(yes/no)" -OutVariable ispvkeyencrypted
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
        $arguments="--d --k $keyfile --i ""$inputfilename"" --o ""$outputfilename"""
        if ($pvkeyflag)
        {
             $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pvkeypwd)
             $pvpwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
             if ($Base64OutputOnly)
             {
                $inputfilename += ".base64"
                $arguments = "--d --k $keyfile --privatekeypassword ""$pvpwd"" --base64 --i ""$inputfilename"" --o ""$outputfilename"""
             }
             else
             {
                $arguments = "--d --k $keyfile --privatekeypassword ""$pvpwd"" --i ""$inputfilename"" --o ""$outputfilename"""
             }

            #Start-Process -NoNewWindow -Wait -FilePath "$Encrypt_Directory\Encryptor.exe" -ArgumentList $arguments -OutVariable $message
        }
        Start-Process -NoNewWindow -Wait -FilePath "$Encrypt_Directory\Encryptor.exe" -ArgumentList $arguments -OutVariable $message
        echo $message
        #echo "--d --k $keyfile --i $inputfilename --o $outputfilename"
    }
    exit
} 

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
            Start-Process -NoNewWindow -Wait -FilePath "$Encrypt_Directory\Encryptor.exe" -ArgumentList "--e --k $keyfile --base64 --i ""$inputfilename"" --o ""$outputfilename"""
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