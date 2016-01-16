import socket, sys
import hashlib
from Crypto.Hash import MD5
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

def md5hash(text):
    m = hashlib.md5()
    m.update(text)
    return m.digest()

def produceMessage(header, row):
    package = clientPublicKey.encrypt(row,32)[0]
    signer = PKCS1_v1_5.new(myPrivateKey)

    h = MD5.new()
    h.update(package)
    signature = signer.sign(h)

    while len(header) < 512:
        header += "\000"
    header += signature
    while len(header) < 1024:
        header += "\000"

    return header + package + md5hash(header + package)

def checkHash(message):
    Trail = message[-16:]
    notTrail = message[:len(message) - 16]
    return md5hash(notTrail) == Trail

def checkSignature(message):
    signer = PKCS1_v1_5.new(clientPublicKey)
    #Package
    encryptPackage = message[1024: len(message) - 16]
    #signal
    #Because we adding zero byte to match the length of header, we should get the part actually be
    signaturePart = ""
    for i in range(1024):
        if message[i] != '\000':
            signaturePart += message[i]

    h = MD5.new()
    h.update(encryptPackage)
    return signer.verify(h, signaturePart)



def getPackage(message):
    encryptPackage = message[1024: len(message) - 16]
    return myPrivateKey.decrypt(encryptPackage)

 
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error, msg:
    sys.stderr.write("[ERROR] %s\n" % msg[1])
    sys.exit(1)

privateKey = open('server_privateKey','r').read()
myPrivateKey = RSA.importKey(privateKey)

publicKey = open('client_publicKey','r').read()
clientPublicKey = RSA.importKey(publicKey)
Auths = ["IamAuth", "IamAuth1", "IamAuth2"]


sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #reuse tcp
sock.bind(('', 54321))
sock.listen(5)

# open patch
patch = open('patch.txt', 'r')
patchMsg = patch.read()

 
while True:
    #Connection Start
    (csock, adr) = sock.accept()
    msg = csock.recv(1024)
    print msg
    csock.send("Hello I am server!\r\n")

    if patchMsg != '':
        #Send Notification
        csock.send("NewPatchDeployed")
        #Get Response
        msg = csock.recv(4096)
        #Check Data Integrity
        if checkHash(msg):
            if checkSignature(msg):
                clientAuth = getPackage(msg)
                if clientAuth in Auths:
                    print patchMsg
                    sendMsg = produceMessage('', patchMsg)
                    csock.send(sendMsg)
                    csock.close()
                else:
                    print "Auth Fail"
            else:
                print "Signature Fail"
        else:
            print "Hash Fail"

    else:
        print "No update version for patch"
        csock.send("No New Patch")


