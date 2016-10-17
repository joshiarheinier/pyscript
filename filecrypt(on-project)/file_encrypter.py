#Python Encryption Program
#Edited and Developed by Joshia Rheinier P.
#Compatible with versions of Python 3 and above

from tkinter import *
from tkinter import filedialog
from tkinter.scrolledtext import *
from tkinter.messagebox import showerror
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
import os, random, sys, time, hashlib


class ByteCrypt:

	def __init__(self):
		window=Tk()
		window.resizable(width=False,height=False)
		window.title('ByteCrypt v1.0.0')
		frame = Frame(window,bg='blue')
		frame.pack()
		titleLabel = Label(frame,text="ByteCrypt")
		titleLabel.pack()
		rbFrame = Frame(frame)
		rbFrame.pack()
		self.folder = StringVar()
		folderEntry = Entry(frame,textvariable=self.folder)
		folderEntry.pack()
		browseBtn = Button(frame,text="Select Folder",\
							command=self.selectFolder)
		browseBtn.pack()
		self.choice = StringVar()
		rbEncrypt = Radiobutton(rbFrame,variable=self.choice,\
								text="Encrypt",value="en")
		rbEncrypt.pack()
		rbDecrypt = Radiobutton(rbFrame,variable=self.choice,\
								text="Decrypt",value="de")
		rbDecrypt.pack()
		self.choice.set("en")
		pwdLabel = Label(frame,text="Password:")
		pwdLabel.pack()
		self.pwd = StringVar()
		pwdEntry = Entry(frame,textvariable=self.pwd,show='*')
		pwdEntry.pack()
		processBtn = Button(frame,text="Process",command=self.process)
		processBtn.pack()
		window.mainloop()

	def selectFolder(self,*event):
		folderDir = filedialog.askdirectory()
		self.folder.set('')
		self.folder.set(folderDir)

	def process(self,*event):
		if self.pwd.get() == "":
			return
		password = self.pwd.get()
		filesInDir = self.allFiles()
		if self.choice.get() == "en":
			for file in filesInDir:
				if os.path.basename(file) == "log.txt":
					pass
				elif os.path.basename(file).endswith(".enc"):
					print(str(file)+" is already encrypted")
				elif file != os.path.join(os.getcwd(),sys.argv[0]):
					self.encrypt(SHA256.new(password.encode('utf-8')).digest(),str(file))
					print(str(file)+" encrypted successfully.")
					os.remove(file)
			#write a log after encryption
			self.logSave("log.txt",password)
		elif self.choice.get() == "de":
			if not self.logCheck("log.txt",self.folder.get(),password):
				print("Invalid password or they are already decrypted")
				return
			for file in filesInDir:
				if os.path.basename(file) == "file_encrypter.py" or os.path.basename(file) == "log.txt":
					pass
				elif not os.path.basename(file).endswith(".enc"):
					print("File "+str(file)+" is not encrypted.")
				else:
					self.decrypt(SHA256.new(password.encode('utf-8')).digest(),str(file))
					print(file+" decrypted successfully.")
					os.remove(file)
		return

	def logSave(self,logfile,pwd):
		with open(logfile,"a") as logText:
			logText.write("Encrypted Directory:{}\n".format(self.folder.get()))
			logText.write(time.strftime("Timestamp:%A %D %H.%M.%S\n"))
			#encrypt password using sha1
			savePass = hashlib.sha1(pwd.encode('utf-8'))
			savePass = savePass.hexdigest()
			logText.write("Encryption ID:{}\n".format(savePass))
			logText.write("Decrypted:No\n")
			logText.close()

	def logCheck(self,logfile,folder,pwd):
		with open(logfile,"r") as logText:
			logLines = logText.readlines()
			checkPass = hashlib.sha1(pwd.encode('utf-8'))
			checkPass = checkPass.hexdigest()
			logList = []
			i = 0
			while i < len(logLines)-1:
				logDict = {}
				encDir = logLines[i].split(":")
				timest = logLines[i+1].split(":")
				encID = logLines[i+2].split(":")
				decFlag = logLines[i+3].split(":")
				logDict[encDir[0]] = encDir[1]
				logDict[timest[0]] = timest[1]
				logDict[encID[0]] = encID[1]
				logDict[decFlag[0]] = decFlag[1]
				logList.append(logDict)
				i += 4
			logFlag = False
			for logData in logList:
				if logData["Encrypted Directory"][:-1]==folder:
					if logData["Encryption ID"][:-1]==checkPass:
						if logData["Decrypted"][:-1]=="No":
							logFlag = True
							logData["Decrypted"] = "Yes\n"
			logText.close()
			self.logUpdate(logfile,logList)
			return logFlag

	def logUpdate(self,logfile,logList):
		with open(logfile,"w") as logText:
			for logData in logList:
				logText.write("Encrypted Directory:{}".format(logData["Encrypted Directory"]))
				logText.write(time.strftime("Timestamp:{}".format(logData["Timestamp"])))
				logText.write("Encryption ID:{}".format(logData["Encryption ID"]))
				logText.write("Decrypted:{}".format(logData["Decrypted"]))
			logText.close()


	def allFiles(self):
		"""allFiles method will be used for collecting files from the directory.\nFunction: allFiles()"""
		filesList = []
		for root,subfiles,files in os.walk(self.folder.get()):
			for filename in files:
				filesList.append(os.path.join(root,filename))
		return filesList

	def encrypt(self, key, file):
		"""Encryption method will be used for encrypt file(s).\nFunction: encrypt(key,file)\nParameter:\n-key\nKey will be used for hashing the file\n-file\nFile will pass file(s) needed to be encrypted"""
		chunkSize = 2**16
		outFile = os.path.join(os.path.dirname(file),\
			os.path.basename(file)+".enc")
		fileSize = str(os.path.getsize(file)).zfill(16)
		fileSize = bytes(fileSize.encode('utf-8'))
		initVector = os.urandom(16)
		#initiate the encryptor
		encryptor = AES.new(key,AES.MODE_CBC,initVector)
		#open the file
		with open(file,"rb") as inputFile:
			with open(outFile,"wb") as outputFile:
				outputFile.write(fileSize)
				outputFile.write(initVector)
				chunkFlag = True
				while chunkFlag:
					chunk = inputFile.read(chunkSize)
					if len(chunk) == 0:
						chunkFlag = False
					elif len(chunk)%16 != 0:
						chunk += bytes((' ' * (16-(len(chunk)%16))).encode('utf-8'))
					outputFile.write(encryptor.encrypt(chunk))
		return

	def decrypt(self, key, file):
		"""Decryption method will be used for decrypt file.\nFunction: decrypt(key,file)\nParameter:\n-key\nKey will be used for matching the hashed file\n-file\nFile will pass file(s) needed to be decrypted"""
		outFile = os.path.join(os.path.dirname(file), \
			os.path.basename(file[:-4]))
		chunkSize = 2**16
		with open(file,"rb") as inputFile:
			fileSize = inputFile.read(16)
			initVector = inputFile.read(16)
			#initiate the decryptor
			decryptor = AES.new(key,AES.MODE_CBC,initVector)
			with open(outFile,"wb") as outputFile:
				chunkFlag = True
				while chunkFlag:
					chunk = inputFile.read(chunkSize)
					if len(chunk) == 0:
						chunkFlag = False
					outputFile.write(decryptor.decrypt(chunk))
				outputFile.truncate(int(fileSize))
		return

#Start the program
ob=ByteCrypt()