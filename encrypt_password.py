from Crypto.Cipher import AES
from Crypto import Random


def autoformatter(bytestring, desiredlength):
    for i in range(0, (desiredlength - len(bytestring))):
        bytestring += b'\x00'
    return bytestring


def encrypt_password(ID_string, SKey, passwordHex):
    print("encrypting password")
    CMD_string = "PWD"
    CMD = CMD_string.encode('ascii')


    IV =  Random.get_random_bytes(8)  # may need to change this
    password = bytes.fromhex(passwordHex)
    ID = ID_string.encode('ascii')
    ID = autoformatter(ID, 8)
    CMD = autoformatter(CMD, 4)
    print(len(password))

    # message format ID|CMD|password|IV
    message = ID + CMD + SKey
    print(message)
    print("len(message): ", len(message))
    authtag_length = 12

    print("password: ", password)
    print("IV: ", IV)

    AE = AES.new(password, AES.MODE_GCM, nonce=IV, mac_len=authtag_length)
    encrypted_payload, authtag = AE.encrypt_and_digest(message)
    print("Encrypting...")
    print("encrypted payload :", encrypted_payload)
    print("len(encrypted_payload): ", len(encrypted_payload))
    print("authtag: ", authtag)

    encryptedMessage = encrypted_payload + IV + authtag
    print("encryptedMessage: ", encryptedMessage)
    return encryptedMessage, authtag


def main():
    print("Hello world")
    sKeyInput = b'\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01'
    passwordInput = "12345678123456781234567812345678"  # hex string, len of 32

    encrypt_password("User1", sKeyInput, passwordInput)


main()
