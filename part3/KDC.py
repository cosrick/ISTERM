import socket, sys
import hashlib
from Crypto.Hash import MD5
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

def produceKDCMessage(randomInfo, key):
    package = randomInfo + '||' + key

    signer = PKCS1_v1_5.new(myPrivateKey)

    h = MD5.new()
    h.update(package)
    signature = signer.sign(h)

    while len(signature) < 512:
        signature += '\000'
    return signature + package
 
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error, msg:
    sys.stderr.write("[ERROR] %s\n" % msg[1])
    sys.exit(1)

clientPublicKey = open('client_publicKey','r').read()

serverPublicKey = open('server_publicKey','r').read()

publicKey = open('authority_publicKey','r').read()
myPublicKey = RSA.importKey(publicKey)

privateKey = open('authority_privateKey','r').read()
myPrivateKey = RSA.importKey(privateKey)

# IPLIST = {'127.0.0.1': ['127.0.0.1',serverPublicKey], '10.122.184.95': ['10.122.184.95',clientPublicKey]}
IPLIST = {'127.0.0.1': ['127.0.0.1',serverPublicKey], '10.122.184.95': ['10.122.184.95',clientPublicKey]}

sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #reuse tcp
sock.bind(('', 25618))
sock.listen(5)

KDCresponse = ""
while True:
    #Connection Start
    (csock, adr) = sock.accept()
    print "Client Info: ",csock, adr
    
    if adr[0] in IPLIST:
        csock.send("Hi")
        msg = csock.recv(4096)
        #msg is request side's request
        msgSplit = msg.split('||')
        request = msgSplit[0]
        T1 = msgSplit[1]

        if request == 'client':
            # KDCresponse = produceKDCMessage(T1, IPLIST['10.122.184.95'][1], IPLIST['127.0.0.1'][1])
            KDCresponse = produceKDCMessage(T1, IPLIST['10.122.184.95'][1])
        elif request == 'server':
            # KDCresponse = produceKDCMessage(T1, IPLIST['127.0.0.1'][1], IPLIST['10.122.184.95'][1])
            KDCresponse = produceKDCMessage(T1, IPLIST['127.0.0.1'][1])
        csock.send(KDCresponse)
        csock.close()




    else:
        print "This is a stranger"


