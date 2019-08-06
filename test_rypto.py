from AESCipher import AESCipher
import base64


string = "something"
key = "somekey"
cipher = AESCipher(key)
string = cipher.encrypt(string)
print(string)
string = string.decode()
print(string)
string = string.encode("utf-8")
print(string)
string = cipher.decrypt(string)
print(string)
