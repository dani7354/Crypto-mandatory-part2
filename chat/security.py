from nacl.secret import SecretBox
from nacl.public import PublicKey, PrivateKey, SealedBox
from nacl.utils import random


# Key generation
def generate_random_secret(length):
    return random(length)


def generate_keypair():
    keypair = PrivateKey.generate()
    return keypair


# Asymmetric encryption
def encrypt_symmetric_key(pk_bytes):
    public_key = PublicKey(pk_bytes)
    sealed_box = SealedBox(public_key)
    secret = generate_random_secret(32)
    return sealed_box.encrypt(secret), secret


def decrypt_symmetric_key(private_key, encrypted_sym_key):
    key = SealedBox(private_key)
    secret = key.decrypt(encrypted_sym_key)
    return secret


# Symmetric encryption
def encrypt_message(message, secret):
    message_bytes = message.encode('utf-8', 'ignore')
    secret_box = SecretBox(secret)
    return secret_box.encrypt(message_bytes)


def decrypt_message(message_bytes, secret):
    secret_box = SecretBox(secret)
    message = secret_box.decrypt(message_bytes).decode('utf-8', 'ignore')
    return message
