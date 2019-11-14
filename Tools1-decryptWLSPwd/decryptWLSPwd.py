import os
import weblogic.security.internal.SerializedSystemIni
import weblogic.security.internal.encryption.ClearOrEncryptedService
def decrypt(agileDomain, encryptedPassword):
    agileDomainPath = os.path.abspath(agileDomain)
    encryptSrv = weblogic.security.internal.SerializedSystemIni.getEncryptionService(agileDomainPath)
    ces = weblogic.security.internal.encryption.ClearOrEncryptedService(encryptSrv)
    password = ces.decrypt(encryptedPassword)
    print "Plaintext password is:" + password
try:
    if len(sys.argv) == 3:
        decrypt(sys.argv[1], sys.argv[2])
    else:
                   print "Please input arguments as below"
                   print "                Usage 1: java weblogic.WLST decryptWLSPwd.py  "
                   print "                Usage 2: decryptWLSPwd.cmd "
                   print "Example:"
                   print "                java weblogic.WLST decryptWLSPwd.py C:\Agile\Agile933\agileDomain {AES}JhaKwt4vUoZ0Pz2gWTvMBx1laJXcYfFlMtlBIiOVmAs="
                   print "                decryptWLSPwd.cmd {AES}JhaKwt4vUoZ0Pz2gWTvMBx1laJXcYfFlMtlBIiOVmAs="
except:
    print "Exception: ", sys.exc_info()[0]
    dumpStack()
raise