import random as rn
import sys

def generatePassword(len=8):
    pattern=""
    lowercase = "abcdefghijklmnopqrstuvwxyz"
    uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    digits = "0123456789"
    specials = "@/$&"
    for i in range(0, len):
        pattern += rn.choice([lowercase[0], uppercase[0], digits[0], specials[0]])

    result = ""
    for i in pattern:
        if(i == "a"):
            result = result + rn.choice(lowercase)
        elif(i == "A"):
            result = result + rn.choice(uppercase)
        elif(i == "@"):
            result = result + rn.choice(specials)
        else:
            result = result + rn.choice(digits)
    return result
