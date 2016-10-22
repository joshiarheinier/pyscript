##Python Encryption Program
##Edited and Developed by Joshia Rheinier P.
##Compatible with versions of Python 3 and above
##Downloaded module used: pycrypto

from tkinter import *
from tkinter import filedialog
from tkinter.scrolledtext import *
from tkinter.messagebox import showerror,showwarning
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
import os, random, sys, time, hashlib


class SuspectZero:

	def __init__(self):
		window=Tk()
		window.resizable(width=False,height=False)
		window.title('SuspectZero v1.0.0')
		frame = Frame(window,bg='black')
		frame.pack()
		titleLabel = Label(frame,text="SuspectZero",bg="black",\
							fg="#00FF00",font="Courier 28 bold")
		titleLabel.grid(row=1,column=1,columnspan=3)
		folderLabel = Label(frame,text="Folder:",bg="black",\
							fg="#00FF00",font="Courier 14 bold")
		folderLabel.grid(row=2,column=1,sticky=E)
		self.folder = StringVar()
		folderEntry = Entry(frame,textvariable=self.folder,bg="black",\
							insertbackground="#00FF00",fg="#00FF00",font="Courier 14")
		folderEntry.grid(row=2,column=2)
		browseBtn = Button(frame,text="Browse..",fg="black",padx="1px",pady="2px",activeforeground="black",\
							command=self.selectFolder,bg="#00FF00",font="Courier 10 bold",activebackground="#00FF00")
		browseBtn.grid(row=2,column=3)
		pwdLabel = Label(frame,text="Password:",bg="black",\
						fg="#00FF00",font="Courier 14 bold")
		pwdLabel.grid(row=3,column=1,sticky=E)
		self.pwd = StringVar()
		pwdEntry = Entry(frame,textvariable=self.pwd,show='*',bg="black",\
						insertbackground="#00FF00",fg="#00FF00",font="Courier 14")
		pwdEntry.grid(row=3,column=2)
		rbFrame = Frame(frame,bg="black")
		rbFrame.grid(row=4,column=1,columnspan=3)
		self.choice = StringVar()
		rbEncrypt = Radiobutton(rbFrame,variable=self.choice,bg="black",activebackground="black",selectcolor="black",\
								text="Encrypt",value="en",fg="#00FF00",font="Courier 12 bold",activeforeground="#00FF00")
		rbEncrypt.grid(row=1,column=1,pady=3)
		rbDecrypt = Radiobutton(rbFrame,variable=self.choice,bg="black",activebackground="black",selectcolor="black",\
								text="Decrypt",value="de",fg="#00FF00",font="Courier 12 bold",activeforeground="#00FF00")
		rbDecrypt.grid(row=1,column=2,pady=3)
		self.choice.set("en")
		processBtn = Button(frame,text="Process",command=self.process,bg="#00FF00",activebackground="#00FF00",\
							fg="black",font="Courier 14 bold",padx="2px",pady="2px",activeforeground="black")
		processBtn.grid(row=5,column=1,columnspan=3)
		window.bind("<Return>",self.process)
		self.outputVar = StringVar()
		outputLabel = Label(frame,textvariable=self.outputVar,fg="white",wraplength=300,\
							bg="#111111",width=40,height=6,font="Courier 10")
		outputLabel.grid(row=6,column=1,columnspan=3,pady=10)
		window.mainloop()

	def selectFolder(self,*event):
		"""selectFolder method will be used for opening a directory.\nFunction: selectFolder()"""
		folderDir = filedialog.askdirectory()
		self.folder.set('')
		self.folder.set(folderDir)

	def process(self,*event):
		"""process method will be used for processing the input.\nFunction: process()"""
		self.outputVar.set("")
		self.outputVar.set("Please wait for a while...")
		if self.folder.get() == "":
			showerror(title="Folder Error",\
						message="Please input a folder!")
			self.outputVar.set("")
			return
		if self.pwd.get() == "":
			showerror(title="Password Error",\
						message="Please enter the password!")
			self.outputVar.set("")
			return
		password = self.pwd.get()
		filesInDir = self.allFiles()
		if filesInDir == []:
			showwarning(title="No File Exists",\
						message="There are no files in this directory.")
			self.outputVar.set("")
			return
		if self.choice.get() == "en":
			fileList = []
			enFlag = False
			for file in filesInDir:
				if os.path.basename(file) == "log.szl":
					pass
				elif os.path.basename(file).endswith(".enc"):
					showwarning(title="Encryption Warning",\
								message="The following file is already encrypted:\n"+str(file)+"\nAny change of this file will be ignored at this time.")
				elif file != os.path.join(os.getcwd(),sys.argv[0]):
					self.encrypt(SHA256.new(password.encode('utf-8')).digest(),str(file))
					fileList.append(str(file)+".enc")
					enFlag = True
					os.remove(file)
			#write a log after encryption
			if enFlag:
				self.outputVar.set("Encryption Status: Success\n\nNew record is made in log.szl")
				self.logSave("log.szl",fileList,password)
			else: self.outputVar.set("Encryption Status: Failed\n\nAll files in the folder are probably encrypted already.")
		elif self.choice.get() == "de":
			encryptedFile = self.logCheck("log.szl",self.folder.get(),password)
			if not encryptedFile:
				self.outputVar.set("Decryption Status: Failed\n\nEither the password is invalid or they are already decrypted")
				return
			for file in filesInDir:
				if os.path.basename(file) == "file_encrypter.py" or os.path.basename(file) == "log.szl":
					pass
				elif not os.path.basename(file).endswith(".enc"):
					showwarning(title="Decryption Warning",\
								message="The following file is not encrypted:\n"+str(file)+"\nAny change of this file will be ignored at this time.")
				else:
					if file in encryptedFile.split(","):
						self.decrypt(SHA256.new(password.encode('utf-8')).digest(),str(file))
						os.remove(file)
			self.outputVar.set("Decryption Status: Success\n\nFile(s) decrypted successfully")
		return

	def logSave(self,logfile,files,pwd):
		"""logSave method will be used for saving the encryption recorded to a log file.\nFunction: logSave(logfile,files,pwd)\nParameter:\n-logfile\nlogfile will be used for the log file\n-files\nfiles will pass all encrypted files to be recorded\n-pwd\npwd will pass the password used for encryption"""
		try:
			self.decrypt(SHA256.new("SuspectZero".encode('utf-8')).digest(),logfile)
		except FileNotFoundError:
			pass
		with open(logfile[:-4],"a") as logText:
			logText.write("Encrypted Directory:{}\n".format(self.folder.get()))
			logText.write(time.strftime("Timestamp:%A %D %H.%M.%S\n"))
			#encrypt password using sha1
			savePass = hashlib.sha1(pwd.encode('utf-8'))
			savePass = savePass.hexdigest()
			fileString = ""
			for file in files:
				fileString += file
				fileString += ","
			fileString = fileString[:-1]
			logText.write("Files:{}\n".format(fileString))
			logText.write("Encryption ID:{}\n".format(savePass))
			logText.write("Decrypted:No\n")
			logText.close()
		self.encrypt(SHA256.new("SuspectZero".encode('utf-8')).digest(),logfile[:-4])
		os.remove(logfile[:-4])

	def logCheck(self,logfile,folder,pwd):
		"""logCheck method will be used for checking the input for decryption.\nFunction: logCheck(logfile,folder,pwd)\nParameter:\n-logfile\nlogfile will be used for the log file\n-folder\nfolder will pass folder needed to be checked\n-pwd\npwd will be used for checking the password"""
		try:
			self.decrypt(SHA256.new("SuspectZero".encode('utf-8')).digest(),logfile)
		except FileNotFoundError:
			pass
		with open(logfile[:-4],"r") as logText:
			logLines = logText.readlines()
			checkPass = hashlib.sha1(pwd.encode('utf-8'))
			checkPass = checkPass.hexdigest()
			logList = []
			i = 0
			while i < len(logLines)-1:
				logDict = {}
				encDir = logLines[i].split(":")
				timest = logLines[i+1].split(":")
				file = logLines[i+2].split(":")
				encID = logLines[i+3].split(":")
				decFlag = logLines[i+4].split(":")
				logDict[encDir[0]] = encDir[1]
				logDict[timest[0]] = timest[1]
				logDict[file[0]] = file[1]
				logDict[encID[0]] = encID[1]
				logDict[decFlag[0]] = decFlag[1]
				logList.append(logDict)
				i += 5
			logFlag = False
			encryptedFile =""
			for logData in logList:
				#check if the target is the right one
				if logData["Encrypted Directory"][:-1]==folder:
					if logData["Encryption ID"][:-1]==checkPass:
						if logData["Decrypted"][:-1]=="No":
							logFlag = True
							if encryptedFile != "":
								comma = ","
							else: comma = ""
							encryptedFile += comma
							encryptedFile += logData["Files"][:-1]
							logData["Decrypted"] = "Yes\n"
			logText.close()
			self.logUpdate(logfile,logList)
			self.encrypt(SHA256.new("SuspectZero".encode('utf-8')).digest(),logfile[:-4])
			os.remove(logfile[:-4])
			if logFlag == True:
				return encryptedFile
			else: return None


	def logUpdate(self,logfile,logList):
		"""logUpdate method will be used for updating the log after decryption.\nFunction: decrypt(logFile,logList)\nParameter:\n-logFile\nlogFile will be used for the log file\n-logList\nlogList will be used for the updated logs"""
		with open(logfile[:-4],"w") as logText:
			for logData in logList:
				logText.write("Encrypted Directory:{}".format(logData["Encrypted Directory"]))
				logText.write("Timestamp:{}".format(logData["Timestamp"]))
				logText.write("Files:{}".format(logData["Files"]))
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
		if file == "log":
			outFile = os.path.join(os.path.dirname(file),\
				os.path.basename(file)+".szl")
		else: outFile = os.path.join(os.path.dirname(file),\
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
ob=SuspectZero()