##XEcryption Encryption Program for python 3 (with GUI)
##Developed by Joshia Rheinier P.
##Compatible with versions of Python 3 and above
##Downloaded module used: none

from tkinter import *
from tkinter import filedialog
from tkinter.scrolledtext import *
from tkinter.messagebox import showerror
import random

class XEcryption_decrypter:

    def __init__(self,code,pwd=None):
        self.encrypted_code = code[1:]
        if pwd:
            intPass = 0
            for part in pwd:
                intPass += ord(part)
            self.password = intPass
        else:
            self.password = pwd
        self.sumCode = []

    def decrypt(self):
        numcodes = self.encrypted_code.split('.')
        codeIndex = 0
        try:
            for i in range(len(numcodes)//3):
                codeSum = int(numcodes[codeIndex])+int(numcodes[codeIndex+1])+\
                              int(numcodes[codeIndex+2])
                self.sumCode.append(codeSum)
                codeIndex += 3
        except ValueError:
            showerror(title='Decrypt Error',\
                      message='The text is not an encryption of XEcryption algorithm.')
        return self.crack()

    def crack(self):
        passFlag = False
        if not self.password:
            passFlag = True
            sumCodePart = {}
            for code in self.sumCode:
                if code not in sumCodePart:
                    sumCodePart[code] = 1
                else: sumCodePart[code] += 1
            mostOccurTotal = 0
            for index in sumCodePart:
                if sumCodePart[index] > mostOccurTotal:
                    mostOccurTotal = sumCodePart[index]
                    mostOccurNumber = index
            self.password = mostOccurNumber-32
        decrypted_code = ''
        try:
            for part in self.sumCode:
                asciiNum = part-self.password
                decrypted_code += chr(asciiNum)
        except ValueError:
            if passFlag:
                smallestCode = self.sumCode[0]
                for code in self.sumCode[1:]:
                    if code < smallestCode:
                        smallestCode = code
                self.password = smallestCode-32
                decrypted_code = ''
                for part in self.sumCode:
                    asciiNum = part-self.password
                    decrypted_code += chr(asciiNum)
            else: return "Invalid Password!"
        return decrypted_code
                
class XEcryption_encrypter:

    def __init__(self,text,pwd=None):
        self.text = text
        if pwd:
            intPass = 0
            for part in pwd:
                intPass += ord(part)
            self.password = intPass
        else:
            self.password = 0

    def encrypt(self):
        codedString = ''
        for char in self.text:
            asciiChar = ord(char)
            codedChar = asciiChar + self.password
            code0 = random.randint(0,codedChar)
            code1 = random.randint(0,codedChar-code0)
            code2 = codedChar - (code0+code1)
            codedString += ('.'+str(code0)+'.'+str(code1)+'.'+str(code2))
        return codedString

class XEcryption_display:

    def __init__(self):
        window = Tk()
        window.resizable(width=False,height=False)
        window.title('XEcrypter v1.0.0')
        frame = Frame(window,bg='blue')
        frame.pack()
        titleLabel = Label(frame,text='XEcrypter',font='Courier 28 bold',\
                           bg='blue',fg='yellow')
        titleLabel.grid(row=1,column=1,columnspan=3,pady=5)
        fileLabel = Label(frame,font='Courier 12 bold',bg='blue',fg='yellow',\
                          text='Select your text file:')
        fileLabel.grid(row=2,column=1,sticky=E)
        self.file = StringVar()
        self.fileEntry = Entry(frame,textvariable=self.file,width=35,\
                               bg='black',fg='#00ff00',insertbackground='#00ff00')
        self.fileEntry.grid(row=2,column=2,sticky=E)
        browseButton = Button(frame,text='Browse..',command=self.selectFile,\
                              font='Courier 8 bold',bg='#000066',fg='yellow',\
                              activebackground='#000066',activeforeground='yellow',\
                              underline=1)
        browseButton.grid(row=2,column=3,sticky=W)
        window.bind('r',self.selectFile)
        pwdLabel = Label(frame,font='Courier 12 bold',bg='blue',fg='yellow',\
                         text='Password(optional):')
        pwdLabel.grid(row=3,column=1,sticky=E)
        self.pwd = StringVar()
        pwdEntry = Entry(frame,textvariable=self.pwd,show='*',width=35,\
                         bg='black',fg='#00ff00',insertbackground='#00ff00')
        pwdEntry.grid(row=3,column=2,sticky=E)
        rbFrame = Frame(frame)
        rbFrame.grid(row=4,column=1,columnspan=3)
        self.EnOrDe = StringVar()
        rbEncrypt = Radiobutton(rbFrame,text="Encrypt",variable=self.EnOrDe,\
                                font='Courier 12 bold',value='en',\
                                selectcolor='#000066',bg='blue',fg='yellow',\
                                activebackground='blue',activeforeground='yellow')
        rbEncrypt.grid(row=1,column=1)
        rbDecrypt = Radiobutton(rbFrame,text="Decrypt",variable=self.EnOrDe,\
                                font='Courier 12 bold',value='de',\
                                selectcolor='#000066',bg='blue',fg='yellow',\
                                activebackground='blue',activeforeground='yellow')
        rbDecrypt.grid(row=1,column=2)
        self.EnOrDe.set('en')
        processButton = Button(frame,text='Process',font='Courier 12 bold',\
                               command=self.process,bg='#000066',fg='yellow',\
                               activebackground='#000066',activeforeground='yellow')
        processButton.grid(row=5,column=1,columnspan=3,pady=5)
        window.bind('<Return>',self.process)
        self.textArea = ScrolledText(frame,width=60,height=12,insertbackground='#00ff00',\
                                     bg='black',fg='#00ff00')
        self.textArea.grid(row=6,column=1,columnspan=3)
        note='Note:\n-The decryption is not 100% accurate if the encrypted text is not long enough\n\
-The decryption will be more accurate if there is a valid password(if it has)\n\
-The XEcrypter cannot decrypt only 1 word correctly without the valid password'
        noteLabel = Label(frame,font='Courier 8',text=note,justify=LEFT,\
                          bg='blue',fg='yellow')
        noteLabel.grid(row=7,column=1,columnspan=3,sticky=W)
        window.mainloop()

    def selectFile(self,*event):
        fileDir = filedialog.askopenfilename()
        self.file.set('')
        self.file.set(fileDir)

    def process(self,*event):
        try:
            targetFile = open(self.file.get(),'r').read()
        except(FileNotFoundError,OSError):
            showerror(title='File Not Found',\
                      message='Sorry, there is no such file:'+self.file.get())
            return
        self.textArea.delete('1.0','end')
        if self.EnOrDe.get() == 'en':
            if self.pwd.get():
                encrypter = XEcryption_encrypter(targetFile,self.pwd.get())
            else: encrypter = XEcryption_encrypter(targetFile)
            self.textArea.insert(INSERT,encrypter.encrypt())
        elif self.EnOrDe.get() == 'de':
            if self.pwd.get():
                decrypter = XEcryption_decrypter(targetFile,self.pwd.get())
            else: decrypter = XEcryption_decrypter(targetFile)
            checkDecrypted = decrypter.decrypt()
            if checkDecrypted=='Invalid Password!':
                showerror(title='Invalid Password',\
                          message='Sorry, the password is invalid.')
            else: self.textArea.insert(INSERT,checkDecrypted)

ob=XEcryption_display()
