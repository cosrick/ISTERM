from Crypto.PublicKey import RSA

newPrivateKey = RSA.generate(1024)
newPublickKey = newPrivateKey.publickey().exportKey('PEM')
newPrivateKey = newPrivateKey.exportKey('PEM')

f = open('publicKey','w')
f.write(newPublickKey)
f.close()

f = open('privateKey','w')
f.write(newPrivateKey)
f.close()
