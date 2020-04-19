import sys, getopt
from Crypto.Cipher import AES
from Crypto import Random


def autoformatter(bytestring, desiredlength):
    for i in range(0, (desiredlength - len(bytestring))):
        bytestring += b'\x00'
    return bytestring

    # usage: ID is a string < 8 chars
    #        sKey_file is the bytestring key in hex (len(32))
    #        CMD_string is a 3 char string command code
    #        Filename is a string
    #       FileContents is the file name where the data will be
    #      CTR is the sequence counter, in Int format.

def encrypt(ID_string, SKey, CMD_string,
            fileNameString, filecontentsFile, CTR_int, outputFile):

    #read fileContents
    f = open(filecontentsFile, "r")
    fileContents = f.read()
    print(fileContents)

    IV = Random.get_random_bytes(8) # may need to change this
    ID = ID_string.encode('ascii')
    CMD = CMD_string.encode('ascii')
    FN = fileNameString.encode('ascii')
    FC = fileContents.encode('ascii')
    CTR = CTR_int.to_bytes(4, byteorder='big')

    FNLength = len(FN).to_bytes(4, byteorder='big')
    FCLength = len(FC).to_bytes(4, byteorder='big')

    ID = autoformatter(ID, 8)
    CMD = autoformatter(CMD, 4)

    print("IV: ", IV)
    print("CTR: ", CTR)
    print("ID: ", ID)
    print("CMD: ",  CMD, "CMD len: ", len(CMD))
    print("FN: ", FN, "FNLength: ", FNLength)
    print("FC: " , FC, "FCLenght: ", FCLength)
    print("SKey: ", SKey)

    header = FNLength + FCLength + IV
    payload = ID + CTR + CMD + FN + FC
    
    print("header: " , header)
    print("payload: ", payload)
    authtag_length = 12

    AE = AES.new(SKey, AES.MODE_GCM, nonce=IV, mac_len=authtag_length)

    AE.update(header)
    encrypted_payload, authtag = AE.encrypt_and_digest(payload)
    print("Encrypting...")

    print("encrypted payload :", encrypted_payload)
    print("authtag: ", authtag)

    message = header + encrypted_payload + authtag
    print("message: ", message)

    f = open(outputFile, "w+")
    f.write(message.hex())
    f.close()

def main():
    #encryptHardCode();
    sKeyInput = b'\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01'

    encrypt("User1", sKeyInput, "TST", "TestFile.txt", "FileContentsTester.txt", 70, "Output1.txt")

main()
