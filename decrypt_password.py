import sys
from Crypto.Cipher import AES


def decrypt_password(message, passwordInput):
    print("attempting decryption")
    IV = message[28:-12]
    authtag = message[-12:]
    innerMessage = message[0:28]

    print("encryptedMsg: ", message)
    print("IV: ", IV)
    print("authtag: ", authtag)
    password = bytes.fromhex(passwordInput)
    print("password: ", password)

    AE = AES.new(password, AES.MODE_GCM, nonce=IV, mac_len=12)
    try:
        payload = AE.decrypt_and_verify(innerMessage, authtag)

    except Exception as e:
        print("Error: Operation failed!")
        print("Processing completed.")
        sys.exit(1)
    print("Operation was successful: message is intact, content is decrypted.")
    print(payload)

    posSessionKey = payload[12:28]
    return posSessionKey


def main():
    encrypted_msg =  b'\xa2U..\xd9+\xc0\x16\x83eg\x8d[\xda4\x19T@\x03\xa9\xf3pw*\xcef3\x15\xae0\x15\xdd\x1a*\x00\x99\x85\\\xd2\x07Qp\xad\x9f\xe5\xab\\\xa9'
    passwordInput = "12345678123456781234567812345678"
    decrypt_password(encrypted_msg, passwordInput)


main()
