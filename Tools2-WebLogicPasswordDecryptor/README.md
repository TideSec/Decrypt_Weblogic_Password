WebLogic Password Decryptor
=========

PowerShell script and Java code to decrypt WebLogic passwords

```
Import the module

Import-Module .\Invoke-WebLogicPasswordDecryptor.psm1
```

```
Decrypt AES

Invoke-WebLogicPasswordDecryptor -SerializedSystemIni C:\SerializedSystemIni.dat -CipherText "{AES}8/rTjIuC4mwlrlZgJK++LKmAThcoJMHyigbcJGIztug="
```

```
Decrypt 3DES

Invoke-WebLogicPasswordDecryptor -SerializedSystemIni C:\SerializedSystemIni.dat -CipherText "{3DES}JMRazF/vClP1WAgy1czd2Q=="
```

```
Java

WebLogicPasswordDecryptor "C:\SerializedSystemIni.dat" "{AES}8/rTjIuC4mwlrlZgJK++LKmAThcoJMHyigbcJGIztug="

WebLogicPasswordDecryptor "C:\SerializedSystemIni.dat" "{3DES}JMRazF/vClP1WAgy1czd2Q=="

```
