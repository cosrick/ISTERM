import socket, sys
import hashlib
from Crypto.Hash import MD5
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from base64 import b64decode 

def md5hash(text):
    m = hashlib.md5()
    m.update(text)
    return m.digest()

def produceMessage(header, row):
	package = serverPublicKey.encrypt(row,32)[0]
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

def getPackage(message):
    encryptPackage = message[1024: len(message) - 16]
    return myPrivateKey.decrypt(encryptPackage)

def checkSignature(message):
    signer = PKCS1_v1_5.new(serverPublicKey)
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
 
sock.send("Hello I'm Rick.\r\n")
serverMsg = sock.recv(1024)
print serverMsg
serverMsg = sock.recv(1024)

if serverMsg == "NewPatchDeployed":
	#Send Auth
	
	sendMsg = produceMessage('', Auth)
	sock.send(sendMsg)

	#Get Response
	serverMsg = sock.recv(4096)

	if checkHash(serverMsg):
		if checkSignature(serverMsg):
		    newPatch = getPackage(serverMsg)
		    print newPatch
		else:
			print "Signature Fail"
	else:
		print "Hash Fail"
elif serverMsg == "No New Patch":
	print serverMsg
sock.close()
