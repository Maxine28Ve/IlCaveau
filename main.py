#!/usr/bin/python3
import os
import xml.etree.ElementTree as ET
import hashlib

# ============ UTILITIES =======================================================
def print_header(text):
    text = " " + text + " "
    htl = int(len(text)/2)
    total_len = (number_of_hashes - htl) if number_of_hashes - htl > 0 else 2
    print("\n" + "#"*total_len + text + "#"*total_len)
    print_separator(number_of_hashes)

def print_separator(number_of_hashes):
    print("-"*(number_of_hashes * 2 + 1))

def print_error(text):
    text = " " + text + " "
    htl = int(len(text)/2)
    number_of_dashes = 20
    total_len = (number_of_dashes - htl) if number_of_dashes - htl > 0 else 2
    print("\n" + "<!>"*total_len + text + "<!>"*total_len)

def hash_string(string):
    """
    Return a SHA-256 hash of the given string
    """
    return hashlib.sha256(string.encode('utf-8')).hexdigest()
# ============= PASSWORD FUNCTIONS =============================================
def menu():
    choice = -1
    root = None
    tuples = []
    while(choice != 0):
        print_header("Main Menu")
        print("1) Print everything")
        print("")
        print("2) Load from file")
        print("3) Change master password") # TODO
        print("0) Quit")
        try:
            choice = int(input(">> Choice: "))
        except KeyboardInterrupt:
            print_error("Bye Bye")
            break
        except ValueError:
            os.system("clear")
            print_error("I need an integer")
        if(choice == 1):
            tuples = get_all_tuples(root)
            print_all_tuples(tuples)
        elif(choice == 2):
            root = load_from_file()
        elif(choice == 3):
            change_master_password()

# ============= PASSWORDS FUNCTIONS =================================================
def get_all_tuples(root):
    if(root == None):
        return []
    tuples = []
    tmp = []
    for item in root:
        for subitem in item:
            tmp.append(subitem.text)
        tuples.append(tmp)
        tmp = []
    return tuples[1:]

def print_all_tuples(tuples):
    counter = 1
    str = ""
    max_len = 0
    os.system("clear")
    print_header("Your passwords")
    for tuple in tuples:
        str = "{}) {} | {} | {}".format(counter, tuple[0], tuple[1], tuple[2])
        counter += 1
        if(max_len < len(str)):
            max_len = len(str)
        print(str)
    print("-" * max_len + "\n")

def change_master_password():
    new_master_password = "a"
    confirm_new_master_password = "b"
    while(new_master_password != confirm_new_master_password):
        print_header("Changing Master Password")
        new_master_password = input("Input the new master password:")
        confirm_new_master_password = input("Confirm the new master password:")
        if(new_master_password != confirm_new_master_password):
            print_error("The passwords do not correspond. Retry")
            continue
        new_master_password_digest = hash_string(new_master_password)
        set_master_password(new_master_password_digest)

def set_master_password(new_master_password_digest):

# ============= FILES FUNCTIONS =================================================
def load_from_file():
    os.system("clear")
    default_dir = "passwords/"
    files = get_all_xml_files_from_filenames_array(get_all_files(default_dir))
    counter = list_xml_files(files, default_dir)
    choice = int(input(">> Load from: "))
    while(choice >= counter):
        os.system("clear")
        dir = input(">> Dir: ")
        files = get_all_xml_files_from_filenames_array(get_all_files(dir))
        counter = list_xml_files(files, dir)
        choice = int(input(">> Load from: "))
    os.system("clear")

    return ET.parse(files[choice - 1]).getroot()


def get_all_files(dir):
    files =  []
    for dirpath, dirnames, filenames in os.walk(dir):
        files.extend(filenames)
    return files
def get_all_xml_files_from_filenames_array(filenames):
    return [filename for filename in filenames if ".xml" in filename]

def list_xml_files(files, dir):
    os.system("clear")
    print("Listing {}. Load from:".format(dir))
    counter = 1
    for file in files:
        if(".xml" in file):
            print("{}) {}".format(counter, file))
            counter += 1
    print("\n{}) Load from another directory".format(counter))
    return counter



def main():
    menu()

if __name__ == '__main__':
    main()