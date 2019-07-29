import random as rn
import sys

def generatePassword(pattern="aa@AAaA000A"):
    lowercase = "abcdefghijklmnopqrstuvwxyz"
    uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    digits = "0123456789"
    specials = "@/$&"
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


if __name__ == "__main__":
	if(len(sys.argv) > 1):
	    print(generatePassword(sys.argv[1]))
	else:
	    print(generatePassword())
