#!/usr/bin/env python3

# Author: Romario A. Maxwell
# Course Code: COMP2190
# Course Title: Netcentric Computing
# Lecturer: Dr. Fokum
# Semester I 2015
# 13-11-2015
# The University of the West Indies, Mona

# Server to implement simplified RSA algorithm. 
# The server waits for the client to say Hello. Once the client says hello,
# the server sends the client a public key. The client uses the public key to
# send a session key with confidentiality to the server. The server then sends
# a nonce (number used once) to the client, encrypted with the server's private
# key. The client decrypts that nonce and sends it back to server encrypted 
# with the session key. 

import os
import sys
import time
import socket

import math
import random

import hashlib

import simplified_AES

def handleRemoteHostDisappear(conn):
    print("")
    print("Remote host closed the connection.")
    print("Shutting down connection...")

    conn.shutdown(socket.SHUT_RDWR)
    conn.close()

    print("Closed this connection's local endpoint.")
    print("")

def handleProtocolError(msg, conn):
    print("")
    print("Invalid protocol message.")

    print("\t" + "Mesage: " + str(msg))
    print("")

    print("Sending error message to remote host...")
    
    try:
        conn.sendall(bytes("401 Bad Request", "utf-8"))
    except socket.error:
            print("")
            print("Error sending data to remote host")

            sys.exit(1)
    
    print("Sent.")

    print("Shutting down the connection...")

    conn.shutdown(socket.SHUT_RDWR)
    conn.close()

    print("Closed this connection's local endpoint.")
    print("")

def handleConnection(p, q, n, e, d, conn, addr):
    # Protocol
    strHello = "100 Hello"
    strHelloResp = "105 Hello"
    strSessionKey = "112 SessionKey"
    strSessionKeyResp = "113 Nonce"
    strNonceResp = "130"

    print("Waiting to receive hello message from client...")
    buff = conn.recv(1024).decode("utf-8")

    if not buff:
        handleRemoteHostDisappear(conn)
        return

    if buff.find(strHello) >= 0:
        print("Received hello message.")

        msg = clientHelloResp(n, e)

        print("Pending response:")
        print("\t" + str(msg))
        
        print("Sending...")

        try:
            conn.sendall(bytes(msg, "utf-8"))
        except socket.error:
            print("")
            print("Error sending data to client")

            sys.exit(1)

        print("Response sent.")
        print("")
    else:
        handleProtocolError(buff, conn)
        return

    print("Waiting to receive public key from client...")
    buff = conn.recv(1024).decode("utf-8")

    if not buff:
        handleRemoteHostDisappear(conn)
        return

    if buff.find("110 PB") >= 0: # I'll pretend that this will somehow be useful. Hmmm...
        print("Public key received.")

        print("Parsing response...")
        
        data = buff.split(" ")
        n_remote_host = int(data[2]) # Modulus for public key encryption
        e_remote_host =  int(data[3]) # Exponent for public key encryption

        print("Client's public key: (" + str(n_remote_host)+ ", " + str(e_remote_host) + ")")

        print("Sending receipt ack...")

        try:
            conn.sendall(bytes("111 ACK PB", "utf-8"))
        except socket.error:
            print("")
            print("Error sending data to client")

            sys.exit(1)

        print("Receipt ack sent.")
        print("")
    else:
        handleProtocolError(buff, conn)
        return

    print("Waiting to retrieve session key from client...")
    buff = conn.recv(1024).decode("utf-8")

    if not buff:
        handleRemoteHostDisappear(conn)
        return

    if buff.find(strSessionKey) >= 0:
        print("Received session key.")

        encryptedSymmKey = int(buff.split(" ")[2])

        print("Encrypted session key: " + str(encryptedSymmKey))

        print("Decrypting session key...")
        SymmKey = RSAdecrypt(encryptedSymmKey, d, n)

        print("Decrypted session key: " + str(SymmKey))

        print("Creating challenge....")

        # The next line generates the round keys for simplified AES
        simplified_AES.keyExp(SymmKey)

        challenge = generateNonce()
        while challenge >= n: # Nonce sometimes exceeds n and gives me 400 Error >:(
           challenge = generateNonce() 
        
        print("Encrypted challenge: " + str(challenge))

        print("Decrypting challenge/creating nonce...")

        msg = SessionKeyResp(RSAdecrypt(challenge, d, n))
        
        print("Pending message with challenge for client:")
        print("\t" + str(msg))

        print("Sending...")
        try:
            conn.sendall(bytes(msg, "utf-8"))
        except socket.error:
            print("")
            print("Error sending data to client")

            sys.exit(1)

        print("Challenge sent.")
        print("")
    else:
        handleProtocolError(buff, conn)
        return

    print("Waiting on challenge response from client...")
    buff = conn.recv(1024).decode("utf-8")

    if not buff:
        handleRemoteHostDisappear(conn)
        return

    if buff.find(strNonceResp) >= 0:
        print("Received challenge response.")
        
        encryptedChallenge = int(buff.split(" ")[1])

        print("Encrypted challenge response: " + str(encryptedChallenge))

        print("Decrypting...")

        # The next line runs AES decryption to retrieve the key.
        decryptedChallenge = simplified_AES.decrypt(encryptedChallenge)

        print("Decrypted challenge response: " + str(decryptedChallenge))

        msg = nonceVerification(challenge, decryptedChallenge)

        print("Pending message to client:")
        print("\t" + str(msg))

        print("Sending...")
        try:
            conn.sendall(bytes(msg, "utf-8"))
        except socket.error:
            print("")
            print("Error sending data to client")

            sys.exit(1)

        print("Message sent.")
        print("")
    else:
        handleProtocolError(buff, conn)
        return

    print("Closing connection...")

    conn.close()

    print("Connection closed.")
    print("")

def serverSocket(host, port):
    listeningSocket = None

    for res in socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM, 0, socket.AI_PASSIVE):
        af, socktype, proto, canonname, sa = res

        try:
            listeningSocket = socket.socket(af, socktype, proto)

            #Allow a socket in the TIME_WAIT state to be reused
            listeningSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except socket.error as msg:
            listeningSocket = None

            continue

        try:
            listeningSocket.bind(sa)

            listeningSocket.listen(5)
        except socket.error as msg:
            listeningSocket.close()

            listeningSocket = None

            continue

        break

    if listeningSocket is None:
        print("Could not open socket")
        print("")

        sys.exit(1)

    return listeningSocket

def expMod(b, n, m):
    """Computes the modular exponent of a number"""
    """returns (b^n mod m)"""

    if n == 0:
        return 1
    elif n % 2 == 0:
        return expMod((b * b) % m, n / 2, m)
    else:
        return(b * expMod(b, n - 1, m)) % m

def RSAencrypt(m, e, n):
    """Encryption side of RSA"""

    return expMod(m, e, n)

def RSAdecrypt(c, d, n):
    """Decryption side of RSA"""

    return expMod(c, d, n)


def gcd_iter(u, v):
    """Iterative Euclidean algorithm"""

    while v:
        u, v = v, u % v

    return abs(u)

def ext_Euclid(m,n):
    """Extended Euclidean algorithm"""

    A1, A2, A3 = 1, 0, m
    B1, B2, B3 = 0, 1, n

    while True:
        if B3 == 0: 
            return A3 # No inverse

        if B3 == 1:
            while B2 < 0: # This is important...
                B2 += m

            return B2 # B2 = (1 / n) % m

        Q = math.floor(A3 / B3)

        T1, T2, T3 = (A1 - (Q * B1)), (A2 - (Q * B2)), (A3 - (Q * B3))
        A1, A2, A3 = B1, B2, B3
        B1, B2, B3 = T1, T2, T3

def generateNonce():
    """This method returns a 16-bit random integer derived from hashing the
    current time. This is used to test for liveness"""

    hash = hashlib.sha1()

    hash.update(str(time.time()).encode("utf-8"))

    return int.from_bytes(hash.digest()[ : 2], byteorder=sys.byteorder)

def genKeys(p, q):
    """Generate n, phi(n), e, and d."""

    n = p * q

    phin = (p - 1) * (q - 1)

    e = random.randint(3, n - 1)

    while gcd_iter(e, phin) != 1:
        e = random.randint(3, n - 1)

    d = ext_Euclid(phin, e)

    print("Server's keys successfully generated.")
    print("\t" + "Value of n: " + str(n))
    print("\t" + "Value of phi(n): " + str(phin))
    print("\t" + "Value of e: " + str(e))
    print("\t" + "Value of d: " + str(d))
    print("")

    return n, e, d

def clientHelloResp(n, e):
    """Responds to client's hello message with modulus and exponent"""
    return "105 Hello "+ str(n) + " " + str(e)

def SessionKeyResp(nonce):
    """Responds to session key with nonce"""
    return "113 Nonce " + str(nonce)

def nonceVerification(nonce, decryptedNonce):
    """Verifies that the transmitted nonce matches that received
    from the client."""
    return "200 OK" if nonce == decryptedNonce else "400 Error Detected"

def isPrime(num):
    if num == 1:
        return False

    if num == 2:
        return True

    for i in range(2, int(math.sqrt(num)) + 1):
        if num % i == 0:
            return False

    return True

def isInputValid(p, q):
    """Ensure numbers are within the range and both prime"""
    
    return (p >= 907 and p <= 1013) and (q >= 53 and q <= 67) and isPrime(p) and isPrime(q)

def isPortValid(port):
    if port >= 0 and port < 65536: # unsigned 16 bit integer
        if port < 1024: # priviliged port
            if os.geteuid() == 0: # root is almost always 0 unless your distro just HAS to be different >.>
                return True
            else:
                print("")
                print("You must be root to use a priviliged port (0 - 1023).")
                return False
        else:
            return True
    else:
        print("")
        print("Port numbers are unsigned 16 bit integer numbers (0 - 65535).")
        return False

def main(argv):
    if len(argv) == 1:
        HOST = None        # Symbolic name meaning all available interfaces
        PORT = 9000        # Arbitrary non-privileged port
        print("No program arguments provided. Default values will be used.")
        print("")
    elif len(argv) == 3:
        HOST = argv[1]
        PORT = int(argv[2])

        if not isPortValid(PORT):
            print("Server cannot be started.")
            print("")
            
            return 1
    else: # most common invocation
        print("Invalid arguments.")
        print("")        
        print("Program usage:")
        print("\t" + "server.py [address, port_number]")
        print("")

        return 1

    while True: # Don't stop til you get it right, however long it takes ;)
        print("Enter prime numbers. One should be between 907 and 1013, and the other between 53 and 67.")
        p = int(input("Enter P: "))
        q = int(input("Enter Q: "))

        if(isInputValid(int(p), int(q))): 
            break
        else:
            print("")
            print("Invalid values provided. Try again.")
            print("")

    print("")
    print("Generating server's keys...")
    
    n, e, d = genKeys(p, q)

    print("Obtaining listening socket for server...")
    print("")

    listeningSocket = serverSocket(HOST, PORT) # We in business now mayn!

    print("Server is listening for new connections on port " + str(PORT))
    print("")

    while True: # Inifinite client service loop
        print("Waiting on a new connection...")
        print("")
        
        try:
            conn, addr = listeningSocket.accept()
        except KeyboardInterrupt: # gets rid of ugly console output on SIGINT
            print("")
            print("Shutdown signal received. Server will go offline now. Goodbye.")
            print("")
            
            break

        print("Connection received. Connected to remote host @ " + str(addr[0]) + " on port " + str(addr[1]) + ".")
        print("")

        handleConnection(p, q, n, e, d, conn, addr) # blast off

if __name__ == "__main__":
    main(sys.argv)
