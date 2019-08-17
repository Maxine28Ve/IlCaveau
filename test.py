import xml.etree.ElementTree as ET
import os
def print_header(text):
    text = " " + text + " "
    htl = int(len(text)/2)
    number_of_hashes = 20
    total_len = (number_of_hashes - htl) if number_of_hashes - htl > 0 else 2
    print("\n" + "#"*total_len + text + "#"*total_len)
    print_separator(number_of_hashes)

def print_separator(number_of_hashes):
    print("-"*(number_of_hashes * 2 + 1))

def print_all_entries(entries):
    counter = 1
    str = ""
    max_len = 0
    os.system("clear")
    print_header("Your passwords")
    service_len = 0
    username_len = 0
    for entry in entries:
        if(service_len < len(entry[0])):
            service_len = len(entry[0])
        if(username_len < len(entry[1])):
            username_len = len(entry[1])

    for entry in entries:
        str = "{}) {}{}| {}{}| {}".format(counter, entry[0], " " * (service_len
        - len(entry[0]) + 1), entry[1], " " *  (username_len - len(entry[1]) + 1),
        entry[2])
        counter += 1
        # We calculate how long the separator has to be for it to look nice
        if(max_len < len(str)):
            max_len = len(str)
        print(str)
    print("-" * max_len + "\n")

def __import():
    os.system('clear')
    path = input("> Import from: ")
    root = ET.parse(path).getroot()
    entries = []
    for entry in root.findall('entry_tag'):
        entries.append([list.text for list in entry[0:]])
    return entries

entries = __import()
print_all_entries(entries)
