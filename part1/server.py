import socket, sys
import hashlib
from Crypto.PublicKey import RSA

def md5hash(str):
    m = hashlib.md5()
    m.update(str)
    return m.digest()

def produceMessage(header, row):
    package = clientPublicKey.encrypt(row,32)[0]
    while len(header) < 1024:
        header += "\000"
    return header + package + md5hash(header + package)

def checkHash(message):
    Trail = message[-16:]
    notTrail = message[:len(message) - 16]
    return md5hash(notTrail) == Trail

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
    print "Client Info: ",csock, adr
    msg = csock.recv(1024)
    print msg
    csock.send("Hello I am server!")

    if patchMsg != '':
        #Send Notification
        csock.send("NewPatchDeployed")
        #Get Response
        msg = csock.recv(4096)
        #Check Data Integrity
        if checkHash(msg):
            clientAuth = getPackage(msg)
            if clientAuth in Auths:
                sendMsg = produceMessage('', patchMsg)
                csock.send(sendMsg)
                csock.close()
            else:
                print "Auth Fail"
        else:
            print "Hash Fail"

    else:
        print "No update version for patch"
        csock.send("No New Patch")


