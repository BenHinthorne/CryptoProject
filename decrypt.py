import sys, getopt
from Crypto.Cipher import AES

def decrypt(sKeyInput, inputFile, outputFile):

    inputFile = "Output1.txt"
    f= open(inputFile, "r")
    message = bytes.fromhex(f.read())
    print("message: ", message)
    f.close()

    FNLength = int.from_bytes(message[0:4], byteorder='big')
    FCLength = int.from_bytes(message[4:8], byteorder='big')
    IV = message[8:16]
    authtag_length = 12
    authtag = message[-12:]
    header = message[0:16]
    encrypted_payload = message[16:-12]

    print("FNLength: ", FNLength)
    print("FCLength: ", FCLength)
    print("IV: ", IV)
    print("authtag: ", authtag)
    print("header: ", header)
    print("sKeyInput: ", sKeyInput)
    print("encrypted_payload: ", encrypted_payload)

    print("attempting decryption")
    AE = AES.new(sKeyInput, AES.MODE_GCM, nonce=IV, mac_len=authtag_length)
    AE.update(header)

    try:
        payload = AE.decrypt_and_verify(encrypted_payload, authtag)
    except Exception as e:
        print("Error: Operation failed!")
        print("Processing completed.")
        sys.exit(1)
    print("Operation was successful: message is intact, content is decrypted.")

    print("Decoded payload: ", payload.decode('ascii'))

def main():
    sKeyInput = b'\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01'
    decrypt(sKeyInput, "Output1.txt", "Output_decrypted.txt" )

main()
