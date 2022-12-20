
#YOSEF SIRAK ATR/1452/11 COMPUTER STREAM

from tkinter import *
from OneTimePad import Ontime
from TripleDes import triple_des,base64
import aes
import os
import subprocess
#initial value used for CBC BLOCK CIPHER MODES OF OPERATION AES AND TRIPLE DES
iv = os.urandom(16)
#always changes set it back to known 16bytes

#draw
root = Tk()
root.title("Encrypt/Decrypt(YOSEF SIRAK ATR/1452/11 computer)")
root.resizable(0,0)


frameE = LabelFrame(root,text="Encryption",padx=50,pady=50)
frameD = LabelFrame(root,text="Decryption",padx=50,pady=50,height=frameE.winfo_height(),width=frameE.winfo_width())
frameE.grid(row=0,column=0,padx=10,pady=10)
frameD.grid(row=0,column=1,padx=10,pady=10)

frameEout = LabelFrame(frameE,text="Output(BASE64)",padx=9,pady=5)
frameDout = LabelFrame(frameD,text="Output(BASE64)",padx=9,pady=5)
frameEout.grid(row=4,column=0,padx=9,pady=10)
frameDout.grid(row=4,column=0,padx=9,pady=10)

frameEalg =  LabelFrame(frameE,text="Symetric Encryption Algorithim",padx=10,pady=5,width=400)
frameEalg.grid(row=6)

frameDalg =  LabelFrame(frameD,text="Symetric Decryption Algorithim",padx=10,pady=5,width=400)
frameDalg.grid(row=6)


labelE = Label(frameE,text="Message to Encrypt",font='Helvetica 12 bold')
labelE.grid(row=0,column=0)

labelD = Label(frameD,text="Message to Decrypt",font='Helvetica 12 bold')
labelD.grid(row=0,column=0)

frameEk=LabelFrame(frameE,text="",padx=5,pady=20,border=0)
frameEk.grid(row=2,column=0,padx=10,pady=0)

frameEkeys=LabelFrame(frameE,text="",padx=10,pady=0,border=0)
frameEkeys.grid(row=3,column=0,padx=10,pady=10)


frameEkeyEnc=LabelFrame(frameEkeys,text="",padx=20,pady=0,border=0)
frameEkeyEnc.grid(row=0,column=0,padx=10,pady=10)

frameEkeyCop=LabelFrame(frameEkeys,text="",padx=20,pady=0,border=0)
frameEkeyCop.grid(row=0,column=1,padx=10,pady=10)


frameDk=LabelFrame(frameD,text="",padx=5,pady=20,border=0)
frameDk.grid(row=2,column=0,padx=10,pady=0)

frameDkeys=LabelFrame(frameD,text="",padx=10,pady=0,border=0)
frameDkeys.grid(row=3,column=0,padx=10,pady=10)



frameDkeyEnc=LabelFrame(frameDkeys,text="",padx=20,pady=0,border=0)
frameDkeyEnc.grid(row=0,column=0,padx=10,pady=10)

frameDkeyCop=LabelFrame(frameDkeys,text="",padx=20,pady=0,border=0)
frameDkeyCop.grid(row=0,column=1,padx=10,pady=10)



encryptEntry = Text(frameE, height = 3, width = 31)
encryptEntry.grid(row=1,column=0)

decryptEntry = Text(frameD, height = 3, width = 31)
decryptEntry.grid(row=1,column=0)

labelEkey = Label(frameEk,text="Encryption Key",fg='orange')
labelEkey.grid(row=0,column=0)

encrypKey = Text(frameEk, height = 1, width = 20)
encrypKey.grid(row=0,column=1)

labelDkey = Label(frameDk,text="Decryption Key",fg='orange')
labelDkey.grid(row=0,column=0)

decrypKey = Text(frameDk, height = 1, width = 20)
decrypKey.grid(row=0,column=1)


encryptOutput = Text(frameEout, height = 5, width = 31)
encryptOutput.grid(row=4,column=0)


decryptOutput = Text(frameDout, height = 5, width = 31)
decryptOutput.grid(row=4,column=0)


encryptionAlg = IntVar()

def encryptF():
    
    if encryptionAlg.get() == 0:
         encryptOutput.delete(1.0, 'end-1c')
         encryptOutput.insert(END,Ontime(encryptEntry.get('1.0','end-1c'),encrypKey.get('1.0','end-1c')))
         pass
    elif encryptionAlg.get() == 1:
        encryptOutput.delete(1.0, 'end-1c')
        data = bytes(encryptEntry.get('1.0','end-1c'),"utf-8")
        CBC = 1
        try:
            k = triple_des(encrypKey.get('1.0','end-1c'), CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=2)
            d = k.encrypt(data)
            encryptOutput.insert(END,base64.b64encode(d))
        except Exception as e:
            encryptOutput.insert(END,e)
    else:
        encryptOutput.delete(1.0, 'end-1c')
        try:
            key = bytes(encrypKey.get('1.0','end-1c'), 'utf-8')
            encrypted = aes.AES(key).encrypt_ctr(bytes(encryptEntry.get('1.0','end-1c'),"utf-8"),iv)
            encryptOutput.insert(END,base64.b64encode(encrypted))
        except  Exception as e:
            encryptOutput.insert(END,"ERROR CHECK MESSAGE OR KEY LENGTH")
        pass

def decrypF():
    
    if encryptionAlg.get() == 0:
         decryptOutput.delete(1.0, 'end-1c')
         try:
            decryptOutput.insert(END,base64.b64decode(Ontime( base64.b64decode(decryptEntry.get('1.0','end-1c')).decode('utf-8'),decrypKey.get('1.0','end-1c'))))
         except Exception as e:
            decryptOutput.insert(END,"Expecting message to decrypt tobe in BASE64")
         pass
    elif encryptionAlg.get() == 1:
        decryptOutput.delete(1.0, 'end-1c')
        try:
            data =base64.b64decode(decryptEntry.get('1.0','end-1c'))
            CBC = 1
            k = triple_des(decrypKey.get('1.0','end-1c'), CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=2)
            d = k.decrypt(data)
            decryptOutput.insert(END,d)
        except Exception as e:
            decryptOutput.insert(END,e)
        pass
    else:
        decryptOutput.delete(1.0, 'end-1c')
        try:
            data =base64.b64decode(decryptEntry.get('1.0','end-1c'))
            key = bytes(decrypKey.get('1.0','end-1c'), 'utf-8')
            decryptOutput.insert(END,aes.AES(key).decrypt_ctr(data, iv))
        except Exception as e:
            decryptOutput.insert(END,"ERROR CHECK MESSAGE OR KEY LENGTH")
        pass


def copyEncryption():
    return subprocess.check_call('echo '+(encryptOutput.get('1.0','end-1c')).strip()+'|clip',shell=True)
    pass
def copyDecryption():
    return subprocess.check_call('echo '+(decryptOutput.get('1.0','end-1c')).strip()+'|clip',shell=True)
    pass


encrypt =Button(frameEkeyEnc,text="Encrypt",bg='green',fg='white',padx=15,pady=2,command=encryptF)
encrypt.grid(row=0,column=0)


copyEncrypt =Button(frameEkeyCop,text="CopyEncryption",bg='#C70039',fg='white',command=copyEncryption)
copyEncrypt.grid(row=0,column=0)


decrypt =Button(frameDkeyEnc,text="Decrypt",bg='green',fg='white',padx=15,pady=2,command=decrypF)
decrypt.grid(row=0,column=0)

copyDecrypt =Button(frameDkeyCop,text="CopyDecryption",bg='#C70039',fg='white',command=copyDecryption)
copyDecrypt.grid(row=0,column=0)




Radiobutton(frameEalg ,text="OTP",variable=encryptionAlg,value=0).grid(row=6,column=0)
Radiobutton(frameEalg ,text="3DES",variable=encryptionAlg,value=1).grid(row=6,column=1)
Radiobutton(frameEalg ,text="AES",variable=encryptionAlg,value=2).grid(row=6,column=2)

Radiobutton(frameDalg ,text="OTP",variable=encryptionAlg,value=0).grid(row=6,column=0)
Radiobutton(frameDalg ,text="3DES",variable=encryptionAlg,value=1).grid(row=6,column=1)
Radiobutton(frameDalg ,text="AES",variable=encryptionAlg,value=2).grid(row=6,column=2)


root.mainloop()