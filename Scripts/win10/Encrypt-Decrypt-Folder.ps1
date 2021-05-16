param([Parameter(Mandatory=$true)][string][ValidateSet("--d","--e")]$Operation,
[Parameter()][string]$KeyFileLocation,
[Parameter()][string]$InputFolder,
[Parameter(Mandatory=$false)][string]$FileFilter,
[Parameter(Mandatory=$false)][bool]$RemoveFilesAfterEncryption,
[Parameter(Mandatory=$false)][bool]$Base64InputOnly=$false)
Import-Module Microsoft.Powershell.Security
Add-Type -AssemblyName System.Windows.Forms

$Encrypt_Directory = "..\publish"
$filter = "*.enc"
$remove = $false

echo "NOTE: The script checks if encrypted files are Binary or Base64 encoded and decrypts only Base64 encoded files if they are available"
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
    $BinaryFiles = $false
    $Base64Files = $false
    
    Get-ChildItem -Path $InputFolder -Filter "*.enc" | Where-Object { if ($_.FullName.ToString() -match ".enc") { $BinaryFiles=$true}}
    Get-ChildItem -Path $InputFolder -Filter "*.base64" | Where-Object {if ($_.FullName.ToString() -match ".base64"){ $Base64Files=$true}}

    if (($BinaryFiles -eq $false) -and ($Base64Files -eq $true))
    {
        $Base64InputOnly = $true
    }
        

    if ($FileFilter.Trim() -ne "")
    {
        if($FileFilter -match "\*\.{1}[a-z,A-Z]*$")
        {
            if ($Base64InputOnly)
            {
                $filter = "$FileFilter.enc.base64"
            }
            else
            {
                $filter = "$FileFilter.enc"
            }
        }
    }
    else 
    {
        if ($Base64InputOnly)
        {
            $filter = "*.enc.base64"
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
   
    foreach ($result in Get-ChildItem -Path $inputfolder -File -Recurse -Filter $filter)
    {
        echo "Decrypting $result"
        $outputfilename = $result.FullName.Replace($replacefilter,"")
        $inputfilename = $result.FullName
        $arguments="--d --k $keyfile --i ""$inputfilename"" --o ""$outputfilename"""
        if ($Base64InputOnly)
        {
            $arguments="--d --k $keyfile --base64 --i ""$inputfilename"" --o ""$outputfilename"""
        }
        if ($pvkeyflag)
        {
             $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pvkeypwd)
             $pvpwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
             if ($Base64InputOnly)
             {
                $arguments = "--d --k $keyfile --privatekeypassword ""$pvpwd"" --base64 --i ""$inputfilename"" --o ""$outputfilename"""
             }
             else
             {
                $arguments = "--d --k $keyfile --privatekeypassword ""$pvpwd"" --i ""$inputfilename"" --o ""$outputfilename"""
             }
        }
        
        Start-Process -NoNewWindow -Wait -FilePath "$Encrypt_Directory\Encryptor.exe" -ArgumentList $arguments -OutVariable $message
        echo $message
    }
    exit
} 

if ($RemoveFilesAfterEncryption)
{
    $remove=$true
}

if ($operation -eq "--e")
{
    echo "Starting Encryption process"
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
        Start-Process -NoNewWindow -Wait -FilePath "$Encrypt_Directory\Encryptor.exe" -ArgumentList "--e --k $keyfile --i ""$inputfilename"" --o ""$outputfilename"""
        if ($remove)
        {
            echo "Removing " + $result.FullName
            Remove-Item $result.FullName

        }
    }

}