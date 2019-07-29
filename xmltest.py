#!/usr/bin/python3
import xml.etree.ElementTree as ET

root = ET.parse('test.xml').getroot()

for item in root:
    for subitem in item:
        print(subitem.text)
