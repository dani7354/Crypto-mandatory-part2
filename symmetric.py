#!/usr/local/bin/python3
from nacl.secret import SecretBox
import argparse


def encrypt(message, key, output):
    message_bytes = message.encode('ascii')
    with open(key, mode="rb") as key_file:
        key = key_file.read()
    with open(output, "wb") as output_file:
        secret_box = SecretBox(key)
        output_file.write(secret_box.encrypt(message_bytes))


def decrypt(ciphertext, key):
    with open(key, mode="rb") as key_file:
        key_bytes = key_file.read()
    with open(ciphertext, mode="rb") as ciphertext_file:
        ciphertext = ciphertext_file.read()
    secret_box = SecretBox(key_bytes)
    plaintext = secret_box.decrypt(ciphertext)
    print(f"Plaintext: {plaintext.decode('ascii')}")


try:
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mode", dest="mode", type=str, required=True, choices=["encrypt", "decrypt"])
    parser.add_argument("-k", "--key-path", dest="key-path", type=str, required=True)
    parser.add_argument("-c", "--cipher-text", dest="cipher-text", type=str, required=False)
    parser.add_argument("-p", "--plaintext-message", dest="plaintext", type=str, required=False)
    parser.add_argument("-o", "--output", dest="output", type=str, required=False)

    arguments = vars(parser.parse_args())

    if arguments["mode"] == "encrypt":
        encrypt(arguments["plaintext"], arguments["key-path"], arguments["output"])
    else:
        decrypt(arguments["cipher-text"], arguments["key-path"])

except Exception as ex:
    print(f"An error occurred: {ex}")





