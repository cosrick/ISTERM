from Crypto.PublicKey import RSA

newPrivateKey = RSA.generate(1024)
newPublickKey = newPrivateKey.publickey()

newPrivateKey.exportKey()
newPublickKey.exportKey()