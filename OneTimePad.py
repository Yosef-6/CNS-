#since one time pad uses the same XOR operation to encrypt and decrypt its implemented in this function
#returns encrypted/decrypted/or error message with code
import base64
def Ontime(plainText:str,Key:str) -> str:
    if(len(plainText) != len(Key)):
        return "Message and Key should have equal length"
    b = bytearray()
    for v1,v2 in zip(plainText,Key):
        b.append ((ord(v1) ^ ord(v2)))
    return (base64.b64encode(b)).decode('utf-8')
    pass
