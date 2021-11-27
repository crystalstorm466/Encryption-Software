import cryptography
from cryptography.fernet import Fernet
import os
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import rsa
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from rsa.key import PrivateKey, PublicKey
import base64
 

privateKey = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
)

public_Key = privateKey.public_key()


def encrypt(message):
    print("The current message is: ", message)
    public_Keyfile = input("What is the name of your public key file again? ")
    public_Keyfile = public_Keyfile + ".pem"
    # public_Key = serialization.load_pem_public_key(
    #     public_Key = open(public_Keyfile, "r"),
    #     password = None,    
    # )
    
    # with open(public_Keyfile, "r") as key_file:
    #     publicKey = serialization.load_pem_public_key(
    #         key_file.read(),
    #         password= None,
    #     )

    

    ciphertext = public_Key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label = None
        )
    )
    encryptedtext = open("encryptedtext.txt", "wb")
    #ciphertext.decode('utf-8')
    encryptedtext.write(ciphertext)
    encryptedtext.close()
    print("The current encrypted message is: ", ciphertext)
# def encrypt():
#     key = Fernet.generate_key()
#     fernet = Fernet(key)
#     encrypted = fernet.encrypt(message.encode())
#     print("Alright loser I did it, ", encrypted)
#     print("However I am not done.")
#     encrypted = rsa.encrypt(encrypted, publicKey)
#     print("okay now I am done here it is: ", encrypted)
#     #os.system('cls' if os.name == 'nt' else 'clear')



def decrypt(ciphertext, privateKey_file, password):
    password = password.encode()
    ciphertext = base64.b64decode(ciphertext)

    with open(privateKey_file, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password,
            
        )  
        privateKey_file = privateKey_file.encode()


    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print(plaintext)


    
    

print("Welcome to Encryption Software v3")

mode = int(input("What would like to do? 1: Encryption 2: Decryption "))

if mode == 1:
    

    passchoice = input("Create a password: ")
    password = open("password.txt", "w")
    password.write(passchoice)
    password.close()
    passchoice = passchoice.encode()
    

    encrypted_pem_private_key = privateKey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passchoice)
    )
    filename = input("What is the name of your private .pem file? ")
    filename = filename + ".pem"
    privateKey_file = open(filename, "w")
    privateKey_file.write(encrypted_pem_private_key.decode())
    privateKey_file.close()
    
    pem_public_key = privateKey.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    publicfilename = input("What is then name of your public .pem file? ")
    publicfilename = publicfilename + ".pem"
    publicKey_file = open(publicfilename, "w")
    publicKey_file.write(pem_public_key.decode())
    publicKey_file.close()

    
    


    print(encrypted_pem_private_key.splitlines()[0])
    # message = input("Please provide the message you would like to encrypt in quotation marks: ")
    
    # print("The current message is: ", message)

    encrypt(
            message = input("Please provide the message you would like to encrypt in quotation marks. ")
        )
   
elif mode ==2:

    decrypt(
        privateKey_file = input("Provide the file name of your password: ") + ".pem",
        ciphertext = input("Provide the file name of the encrypted text: "),
        password = input("What is your password? "),
    )


   




