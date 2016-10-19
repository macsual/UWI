#!/usr/bin/env python

# Author: Romario A. Maxwell
# Course Code: COMP2190
# Course Title: Netcentric Computing
# Lecturer: Dr. Fokum
# Semester I 2015
# 13-11-2015
# The University of the West Indies, Mona

# Client to implement simplified RSA algorithm.
# The client says hello to the server, and the server responds with a Hello
# and its public key. The client then sends a session key encrypted with the
# server's public key. The server responds to this message with a nonce
# encrypted with the server's public key. The client decrypts the nonce
# and sends it back to the server encrypted with the session key. Finally,
# the server sends the client a message with a status code.

import sys
import socket

import math
import random

import simplified_AES

def isPrime(num):
    if num == 1: # 1 only has one factor, itself, therfore not prime (2 factors)
        return False

    if num == 2: # the first prime number
        return True

    for i in xrange(2, int(math.sqrt(num)) + 1): # reduce sample space by not going beyond square root
        if num % i == 0: # mod function returning 0 means i is a factor
            return False

    return True # outside loop

def handleRemoteHostDisappear(conn):
    """Handler fo when remote host closes its connection impromptly"""
    
    print ""
    print "Remote host closed the connection."
    print "Shutting down connection..."

    conn.shutdown(socket.SHUT_RDWR) # not all implementations call this implicitly in the call below, better to be safe I guess
    conn.close()

    print "Closed this connection's local endpoint."
    print ""

def handleProtocolError(msg, conn):
    """Handler for when remote host doesn't follow protocol"""
    
    print ""
    print "Invalid protocol message."

    print "\t" + "Message: " + str(msg) # show caused the error
    print ""

    print "Sending error message to remote host..."
    
    try:
        conn.sendall(bytes("401 Bad Request", "utf-8"))
    except socket.error:
        print ""
        print "Error sending data to remote host"

        sys.exit(1)
    
    print "Sent."

    print "Shutting down the connection..."

    conn.shutdown(socket.SHUT_RDWR)
    conn.close()

    print("Closed this connection's local endpoint.")
    print("")

def ext_Euclid(m,n):
    """Extended Euclidean algorithm"""

    A1, A2, A3 = 1, 0, m
    B1, B2, B3 = 0, 1, n

    while True:
        if B3 == 0: 
            return A3 # No inverse

        if B3 == 1:
            while B2 < 0: # This is important apparently
                B2 += m

            return B2 # B2 = (1 / n) % m

        Q = math.floor(A3 / B3)

        T1, T2, T3 = (A1 - (Q * B1)), (A2 - (Q * B2)), (A3 - (Q * B3))
        A1, A2, A3 = B1, B2, B3
        B1, B2, B3 = T1, T2, T3

def gcd_iter(u, v):
    """Iterative Euclidean algorithm"""

    while v:
        u, v = v, u % v

    return abs(u)

def genKeys(p, q):
    """Generate n, phi(n), e, and d."""

    n = p * q

    phin = (p - 1) * (q - 1)

    e = random.randint(3, n - 1)

    while gcd_iter(e, phin) != 1:
        e = random.randint(3, n - 1)

    d = ext_Euclid(phin, e)

    print "Client's keys successfully generated."
    print "\t" + "Value of n: " + str(n)
    print "\t" + "Value of phi(n): " + str(phin)
    print "\t" + "Value of e: " + str(e)
    print "\t" + "Value of d: " + str(d)
    print ""

    return n, e, d

def expMod(b, n, m):
    """Computes the modular exponent of a number returns (b^n mod m)"""
    
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

def serverHello():
    """Sends server hello message"""

    return "100 Hello"

def sendSessionKey(s):
    """Sends server session key"""

    return "112 SessionKey " + str(s)

def sendTransformedNonce(xform):
    """Sends server nonce encrypted with session key"""

    return "130 " + str(xform)

def computeSessionKey():
    """Computes this node's session key"""

    sessionKey = random.randint(1, 32768)
    return sessionKey

def main():
    """Driver function for the project"""

    serverHost = 'localhost'        # The remote host
    serverPort = 9000               # The same port as used by the server

    print "Creating socket to communicate with remote host @ " + str(serverHost) + " over port " + str(serverPort)

    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print "Connecting to remote host..."

    try:
        serverSocket.connect((serverHost, serverPort))
    except socket.error as e:
        print ""
        print "Failed to establish connection to remote host with error:"
        print "\t" + str(e)
        print "Program will end now."

        return 1

    print "Connected."
    print ""

    print "Sending hello message to remote host..."
    try:
        serverSocket.sendall(serverHello())
    except socket.error:
        print ""
        print "Error sending data to remote host"

        return 1

    print "Hello message sent."
    print ""

    print "Waiting on server to send its public key..."
    buff = serverSocket.recv(1024)

    if not buff:
        handleRemoteHostDisappear(serverSocket)
        return 0

    strStatus = "105 Hello"
    if buff.find(strStatus) >= 0:
        print "Public key received."

        print "Parsing response..."
        
        data = buff.split(" ")

        n = int(data[2]) # Modulus for public key encryption
        e =  int(data[3]) # Exponent for public key encryption

        print "Server's public key: (" + str(n)+ ", " + str(e) + ")"
        print ""

        print "Generating this client's keys..."

        # I don't need to assume. I KNOW that these numbers will fall in the same ranges like in the server and be prime :P

        p_client = random.randint(907, 1014)
        while not isPrime(p_client): # keep going til we're prime
            p_client = random.randint(907, 1014)

        q_client = random.randint(53, 68)
        while not isPrime(q_client):
            q_client = random.randint(53, 68)

        n_client, e_client, d_client = genKeys(p_client, q_client)

        print "Client's public key: (" + str(n_client)+ ", " + str(e_client) + ")"

        print "Sending public key to server..."

        try:
            serverSocket.sendall("110 PB " + str(n_client) + " " + str(e_client))
        except socket.error:
            print ""
            print "Error sending data to server"

            return 1

        print "Public key sent."
        print ""
    else:  
        handleProtocolError(buff, serverSocket)
        return 0

    print "Waiting on server's receipt ack..."
    buff = serverSocket.recv(1024)

    if not buff:
        handleRemoteHostDisappear(serverSocket)
        return 0

    if buff == "111 ACK PB":
        print "Received receipt ack."
        print ""

        print "Generating session key..."

        symmetricKey = computeSessionKey()

        encSymmKey = RSAencrypt(symmetricKey, e, n)

        print "Session key generated."

        msg = sendSessionKey(encSymmKey)
        
        print "Pending message to server:"
        print "\t" + str(msg)

        print "Sending..."
        try:
            serverSocket.sendall(msg)
        except socket.error:
            print ""
            print "Error sending data to server"

            return 1

        print "Session key sent."
        print ""
    else:
        handleProtocolError(buff, serverSocket)
        return 0

    print "Waiting on server challenge..."
    buff = serverSocket.recv(1024)

    if not buff:
        handleRemoteHostDisappear(serverSocket)
        return 0

    strStatus = "113 Nonce"
    if buff.find(strStatus) >= 0:
        print "Challenge received."

        encNonce = int(buff.split(" ")[2])

        print "Encrypted nonce: " + str(encNonce)

        print "Decrypting nonce..."

        nonce = RSAdecrypt(encNonce, e, n)

        print "Decrypted nonce: " + str(nonce)
        print ""

        """Setting up for Simplified AES encryption"""
        plaintext = nonce

        simplified_AES.keyExp(symmetricKey) # Generating round keys for AES.

        ciphertext = simplified_AES.encrypt(plaintext) # Running simplified AES.

        msg = sendTransformedNonce(ciphertext)

        print "Pending message with challenge response:"
        print "\t" + str(msg)

        print "Sending..."
        try:
            serverSocket.sendall(msg)
        except socket.error:
            print ""
            print "Error sending data to server"

            return 1

        print "Challenge response sent."
        print ""
    else:
        handleProtocolError(buff, serverSocket)
        return 0

    print "Waiting on challenge outcome..."
    buff = serverSocket.recv(1024)

    if not buff:
        handleRemoteHostDisappear(serverSocket)
        return 0
    else:
        print "Response received from server."
        print "\t" + "Response: " + str(buff)
        print ""

    print "Shutting down connection..."

    serverSocket.close()

    print "Closed this connection's local endpoint."

if __name__ == "__main__":
    main()
