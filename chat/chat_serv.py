#!/usr/bin/env python3
"""Server for multithreaded (asynchronous) chat application."""
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
from security import generate_keypair, decrypt_symmetric_key, encrypt_message, decrypt_message


def accept_incoming_connections():
    """Sets up handling for incoming clients."""
    while True:
        client, client_address = SERVER.accept()
        print("%s:%s has connected." % client_address)
        addresses[client] = client_address
        Thread(target=handle_client, args=(client,)).start()


def handle_client(client):  # Takes client socket as argument.
    """Handles a single client connection."""
    # Setting up secret with client
    print(f"Sending server public key to client {addresses[client][0]}:{addresses[client][1]}...")
    client.send(bytes(keypair.public_key))
    secret_enc = client.recv(BUFSIZ)

    print(f"Secret recieved from client {addresses[client][0]}:{addresses[client][1]}...")
    secret = decrypt_symmetric_key(keypair, secret_enc)
    secrets[client] = secret

    # Get client name
    client.send(encrypt_message("Greetings from the cave! Now type your name and press enter!", secret))
    name_enc = client.recv(BUFSIZ)
    name = decrypt_message(name_enc, secret)
    clients[client] = name

    # Say hello to new client and notify other clients
    client.send(encrypt_message("Welcome %s! If you ever want to quit, type {quit} to exit." % name, secret))
    broadcast("%s has joined the chat!" % name)

    while True:
        msg_enc = client.recv(BUFSIZ)
        msg = decrypt_message(msg_enc, secret)
        if msg != "{quit}":
            broadcast(msg, name+": ")
        else:
            client.send(encrypt_message("{quit}", secret))
            client.close()
            print(f"{addresses[client][0]}:{addresses[client][1]} leaving...")
            del clients[client]
            del secrets[client]
            del addresses[client]
            broadcast("%s has left the chat." % name)
            break


def broadcast(msg, prefix=""):  # prefix is for name identification.
    """Broadcasts a message to all the clients."""
    for sock in clients:
        msg_enc = encrypt_message(f"{prefix}{msg}", secrets[sock])
        sock.send(msg_enc)


clients = {}
addresses = {}
secrets = {}
keypair = generate_keypair()

HOST = ''
PORT = 33000
BUFSIZ = 4096
ADDR = (HOST, PORT)

SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind(ADDR)

if __name__ == "__main__":
    SERVER.listen(5)
    print("Waiting for connection...")
    ACCEPT_THREAD = Thread(target=accept_incoming_connections)
    ACCEPT_THREAD.start()
    ACCEPT_THREAD.join()
    SERVER.close()