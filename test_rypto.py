from AESCipher import AESCipher
import base64


string = "something"
key = "somekey"
cipher = AESCipher(key)
string = cipher.encrypt(string)
print(string)
tmp = str(string)
string = tmp.encode("utf-8")
print(string)
string = string.decode("utf-8")
print(string)
string = cipher.decrypt(string)
print(string)
