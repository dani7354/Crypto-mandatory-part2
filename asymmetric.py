from nacl.public import PublicKey, SealedBox
import argparse


def encrypt(message, key, output):
    message_bytes = message.encode('ascii')
    with open(key, mode="rb") as key_file:
        key_bytes = key_file.read()
    with open(output, "wb") as output_file:
        pub_key = PublicKey(key_bytes)
        sealed_box = SealedBox(pub_key)
        output_file.write(sealed_box.encrypt(message_bytes))


try:
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mode", dest="mode", type=str, choices=["encrypt"], required=True)
    parser.add_argument("-p", "--plaintext", dest="plaintext", type=str, required=True)
    parser.add_argument("-pk", "--public-key", dest="public-key", type=str, required=True)
    parser.add_argument("-o", "--output", dest="output", type=str, required=True)
    arguments = vars(parser.parse_args())

    if arguments["mode"] == "encrypt":
        encrypt(arguments["plaintext"], arguments["public-key"], arguments["output"])
    else:
        print("Invalid option!")

except Exception as ex:
    print(f"An error occurred: {ex}")
