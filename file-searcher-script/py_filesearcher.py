##Simple recursively file searcher script for python 3
##Developed by Joshia Rheinier P.

import glob

#In this line, we need to pass the directory as a string to glob with star (i.e. C:\)
directory = glob.glob('C:\*')

def py_finder(directory):  #Search the file recursively in this function
    if type(directory)== str:
        if directory[-3:]=='.py' or directory[-4:]=='.pyw':
            main(directory)
    elif type(directory)==list:
        for i in directory:
            try:
                if glob.glob(i+'/*') != []:
                    py_finder(glob.glob(i+'\*'))
                else:
                    py_finder(i)
            except:
                pass
            
def main(file):
    print(file+" is found.")

a = py_finder(directory)
print('Searching complete')
while True:
    out = input('type q and <Return> to continue...')
    if out == 'q':
        break
