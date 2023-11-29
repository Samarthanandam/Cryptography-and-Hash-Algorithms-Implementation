import hashlib
from Cryptodome.Cipher import AES
from Cryptodome.Cipher import DES
import base64
from urllib import parse
import streamlit as st

#MD-5 Algorithm
def md_5(data):
    text = hashlib.md5()
    text.update(data.encode())
    return text.hexdigest()

#SHA-256 Algorithm
def sha_256(data):
    hash_object = hashlib.sha256(data.encode())
    return hash_object.hexdigest()

#SHA-1 Algorithm
def sha_1(data):
    hash_object = hashlib.sha1(data.encode())
    return hash_object.hexdigest()

#SHA-512 Algorithm
def sha_512(data):
    hash_object = hashlib.sha512(data.encode())
    return hash_object.hexdigest()

# <------------------------------------------------------DES Algorithm--------------------------------------------------------------------->
# -*- coding: utf-8 -*-

class DES_ENCRYPT(object):
    def __init__(self, mode,key):
        self.key = key
        if mode == 'CBC':
            self.mode = DES.MODE_CBC
        elif mode == 'CFB':
            self.mode = DES.MODE_CFB
        elif mode == 'OFB':
            self.mode = DES.MODE_OFB
        elif mode == 'CTR':
            self.mode = DES.MODE_CTR

    # Encryption function
    def encrypt(self, text):
        cryptor = DES.new(self.key.encode("utf8"), self.mode, IV.encode("utf8"))
        self.ciphertext = cryptor.encrypt(bytes(pad(text), encoding="utf8"))
        # The strings obtained during AES encryption are not necessarily ASCII character sets. There may be problems when they are output to the terminal or saved. Base64 encoding is used
        return base64.b64encode(self.ciphertext)

    # Decryption function
    def decrypt(self, text):
        decode = base64.b64decode(text)
        cryptor = DES.new(self.key.encode("utf8"), self.mode, IV.encode("utf8"))
        plain_text = cryptor.decrypt(decode)
        return unpad(plain_text)




# <------------------------------------------------------AES Algorithm--------------------------------------------------------------------->
# -*- coding: utf-8 -*-


class AES_ENCRYPT(object):
    def __init__(self, mode,key):
        self.key = key
        if mode == 'CBC':
            self.mode = AES.MODE_CBC
        elif mode == 'CFB':
            self.mode = AES.MODE_CFB
        elif mode == 'OFB':
            self.mode = AES.MODE_OFB
        elif mode == 'CTR':
            self.mode = AES.MODE_CTR

    # Encryption function
    def encrypt(self, text):
        cryptor = AES.new(self.key.encode("utf8"), self.mode, IV.encode("utf8"))
        self.ciphertext = cryptor.encrypt(bytes(pad(text), encoding="utf8"))
        # The strings obtained during AES encryption are not necessarily ASCII character sets. There may be problems when they are output to the terminal or saved. Base64 encoding is used
        return base64.b64encode(self.ciphertext)

    # Decryption function
    def decrypt(self, text):
        decode = base64.b64decode(text)
        cryptor = AES.new(self.key.encode("utf8"), self.mode, IV.encode("utf8"))
        plain_text = cryptor.decrypt(decode)
        return unpad(plain_text)



# Web Application Code
st.title("Cryptography and Hash Algorithms")
st.write("""
## Explore different cryptography and hash algorithms
""")

st.markdown(""" <style>
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
</style> """, unsafe_allow_html=True)

algo = st.selectbox("Select the Algorithm", ("AES", "DES", "SHA-1", "SHA-256","SHA-512", "MD-5"))
if algo == "MD-5":
    user_input = st.text_input("Enter the text that needs to be hashed: ")
    x = md_5(user_input)
    if st.button("Generate Hash"):
        st.success("The hash of "+user_input+" is: "+x)
elif algo == "SHA-256":
    user_input = st.text_input("Enter the text that needs to be hashed: ")
    x = sha_256(user_input)
    if st.button("Generate Hash"):
        st.success("The hash of " + user_input + " is: " + x)
elif algo == "SHA-1":
    user_input = st.text_input("Enter the text that needs to be hashed: ")
    x = sha_1(user_input)
    if st.button("Generate Hash"):
        st.success("The hash of " + user_input + " is: " + x)
elif algo == "SHA-512":
    user_input = st.text_input("Enter the text that needs to be hashed: ")
    x = sha_512(user_input)
    if st.button("Generate Hash"):
        st.write("The hash of " + user_input + " is: " + x)
elif algo == "DES":
    mode = st.selectbox("Choose the mode: ", ("CBC", "CFB", "OFB"))
    selector = st.selectbox("Encryption/Decryption", ("Encryption", "Decryption"))
    if selector == "Encryption":
        key = st.text_input("Enter the Key of length 8: ", "12345678")
        if (len(key) != 8):
            st.error("Please ensure that length of key should be 8")
            st.stop()
        IV = st.text_input("Enter the Initialisation vector of length 8: ", "12345678")
        if (len(IV) != 8):
            st.error("Please ensure that length of Initialisation Vector should be 8")
            st.stop()
        text = st.text_input("Enter the text: ")
        BS = len(key)
        pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
        unpad = lambda s: s[0:-ord(s[-1:])]
        des_encrypt = DES_ENCRYPT(mode, key)
        e = str(des_encrypt.encrypt(text))
        if st.button("Generate the Cipher text"):
            res = e[2:len(e) - 1]
            st.success("Cipher text:" + res)
    else:
        key = st.text_input("Enter the Key of length 8: ", "12345678")
        if (len(key) != 8):
            st.error("Please ensure that length of key should be 8")
            st.stop()
        IV = st.text_input("Enter the Initialisation vector of length 8: ", "12345678")
        if (len(IV) != 8):
            st.error("Please ensure that length of Initialisation Vector should be 8")
            st.stop()
        text = st.text_input("Enter the cipher text: ", "Wsq88FHNVavKA9GClEIuAQ==")
        try:
            BS = len(key)
            pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
            unpad = lambda s: s[0:-ord(s[-1:])]
            des_encrypt = DES_ENCRYPT(mode, key)
            e = str(des_encrypt.decrypt(text))
            if st.button("Generate the plain text"):
                res = e[2:len(e) - 1]
                st.success(res)
        except:
            st.error("Please enter the correct cipher text")
            st.stop()

elif algo == "AES":
    mode = st.selectbox("Choose the mode: ", ("CBC", "CFB", "OFB"))
    selector = st.selectbox("Encryption/Decryption", ("Encryption", "Decryption"))
    if selector == "Encryption":
        key = st.text_input("Enter the Key of length 16 or 32: ", "1234567812345678")
        if (len(key) != 16 and len(key) != 32):
            st.error("Please ensure that length of key should be 16 or 32")
            st.stop()
        IV = st.text_input("Enter the Initialisation vector of length 16: ", "1234567812345678")
        if (len(IV) != 16):
            st.error("Please ensure that length of Initialisation Vector should be 16")
            st.stop()
        text = st.text_input("Enter the text: ")
        BS = len(key)
        pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
        unpad = lambda s: s[0:-ord(s[-1:])]
        aes_encrypt = AES_ENCRYPT(mode, key)
        e = str(aes_encrypt.encrypt(text))
        if st.button("Generate the Cipher text"):
            res = e[2:len(e)-1]
            st.success(res)
    else:
        key = st.text_input("Enter the Key of length 16 or 32: ", "1234567812345678")
        if (len(key) != 16 and len(key) != 32):
            st.error("Please ensure that length of key should be 16 or 32")
            st.stop()
        IV = st.text_input("Enter the Initialisation vector of length 16: ", "1234567812345678")
        if (len(IV) != 16):
            st.error("Please ensure that length of Initialisation Vector should be 16")
            st.stop()
        text = st.text_input("Enter the cipher text: ", "Wsq88FHNVavKA9GClEIuAQ==")
        try:
            BS = len(key)
            pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
            unpad = lambda s: s[0:-ord(s[-1:])]
            aes_encrypt = AES_ENCRYPT(mode, key)
            e = str(aes_encrypt.decrypt(text))
            if st.button("Generate the plain text"):
                res = e[2:len(e) - 1]
                st.success("Cipher text:" + res)
        except:
            st.error("Please enter the correct cipher text")
            st.stop()







