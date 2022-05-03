import glob
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
    
def encrypt():
    key = get_random_bytes(32)
    publicKey = RSA.import_key(open("publicKey.pem").read())
    rsaCipher = PKCS1_OAEP.new(publicKey)
    encryptedKey = rsaCipher.encrypt(key)
    file = open("encryptedData.bin", "wb")
    file.write(encryptedKey)
    file.close()
    
    filenames = []
    for filename in glob.glob("*.jpg"):
        filenames.append(filename)
        
    iv = bytes("0123456789abcdef", "utf-8")    
    for filename in filenames:
        file = open(filename, "rb")
        data = file.read()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(data, AES.block_size))
        file.close()
        
        file = open(filename, "wb")
        file.write(ciphertext)
        file.close()
        
        ciphertextString = b64encode(ciphertext).decode("utf-8")
        iv = ciphertextString[-16:].encode("utf-8")
        print("Encrypted " + filename)
    
def decrypt():
    filenames = []
    for filename in glob.glob("*.jpg"):
        filenames.append(filename)
    
    keyFile = open("encryptedData.bin", "rb")
    privateKey = RSA.import_key(open("privateKey.pem").read())
    encryptedData = keyFile.read(privateKey.size_in_bytes())
    rsaCipher = PKCS1_OAEP.new(privateKey)
    key = rsaCipher.decrypt(encryptedData)
    keyFile.close()
    
    iv = bytes("0123456789abcdef", "utf-8")
    for filename in filenames:
        file = open(filename, "rb")
        encryptedData = file.read()
        ciphertextString = b64encode(encryptedData).decode("utf-8")
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(encryptedData), AES.block_size)
        file.close()
        file = open(filename, "wb")
        file.write(plaintext)
        iv = ciphertextString[-16:].encode("utf-8")
        file.close()
        print("Decrypted " + filename)

userInput = "0"
while userInput != "3":
    print("Enter '1' to encrypt files")
    print("Enter '2' to decrypt files")
    print("Enter '3' to quit")
    userInput = input("...: ")
    
    if userInput == "1":
        encrypt()
    if userInput == "2":
        decrypt()
