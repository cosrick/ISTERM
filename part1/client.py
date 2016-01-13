import socket, sys
import hashlib
from Crypto.PublicKey import RSA

def md5hash(str):
    m = hashlib.md5()
    m.update(str)
    return m.digest()

def produceMessage(header, package):
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

privateKey = open('client_privateKey','r').read()
myPrivateKey = RSA.importKey(privateKey)

publicKey = open('server_publicKey','r').read()
serverPublicKey = RSA.importKey(publicKey)
Auth = "IamAuth"


try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error, msg:
    sys.stderr.write("[ERROR] %s\n" % msg[1])
    sys.exit(1)
 
try:
    sock.connect(('', 54321))
except socket.error, msg:
    sys.stderr.write("[ERROR] %s\n" % msg[1])
    exit(1)
 
sock.send("Hello I'm Rick2.\r\n")
serverMsg = sock.recv(1024)
print serverMsg
serverMsg = sock.recv(1024)

if serverMsg == "NewPatchDeployed":
	#Send Auth
	package = serverPublicKey.encrypt(Auth,32)[0]
	sendMsg = produceMessage('', package)
	sock.send(sendMsg)

	#Get Response
	serverMsg = sock.recv(4096)
	if checkHash(serverMsg):
	    newPatch = getPackage(serverMsg)
	    print newPatch
	else:
		print "Hash Fail"
elif serverMsg == "No New Patch":
	print serverMsg
	sock.close()
