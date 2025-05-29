#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed May 21 17:02:29 2025

@author: aaron
"""

import socket
import json
from vaudenayAttack import VaudenayAttack
from oracles import LocalOracle

class CryptohackClient():
  def __init__(self, hostname, port):
    self.server_host = hostname
    self.server_port = port
    self.sock = None
        
  def connect(self):
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.sock.connect((self.server_host, self.server_port))
       
    print(f"Connected to server at {self.server_host}:{self.server_port}")
       
  def disconnect(self):
    if self.sock:
      self.sock.close()
      print("Disconnected from server.")
    
  def readline(self):
    packet = self.sock.recv(1)
    data = bytearray(packet)

    while packet and data[-1] != ord('\n'):
      packet = self.sock.recv(1)
      if not packet:
        return None
      data.extend(packet)
    
    return bytes(data)

  def json_recv(self):
    line = self.readline()
    return json.loads(line.decode())

  def json_send(self, data):
    request = json.dumps(data).encode()+b"\n"
    self.sock.sendall(request)

class CryptohackOracle():
  def __init__(self):
    hostname = "socket.cryptohack.org" # localhost to run locally
    port = 13421
    self.client = CryptohackClient(hostname, port)
    self.client.connect()
    self.client.readline()
		
  def query(self, ciphertext: bytes):
    ciphertext = bytes(ciphertext)
    ct = bytes.hex(ciphertext)
    request =  {"option": "unpad", "ct": ct}
    self.client.json_send(request)
    response = self.client.json_recv()['result']
    return response
    
  def get_ciphertext(self):
    request = {"option": "encrypt"}
    self.client.json_send(request)
    response = self.client.json_recv()['ct']
    return bytes.fromhex(response)
        

  def check_plaintext(self, pt: bytes):
    request = {"option": "check", "message": pt.decode()}
    self.client.json_send(request)
    response = self.client.json_recv()
    return response

if __name__ == "__main__":
  oracle = CryptohackOracle()
  #oracle = LocalOracle()

  attack = VaudenayAttack(oracle)

  pt = attack.decrypt_ciphertext()
  print("Recovered plaintext:", pt)

  response = oracle.check_plaintext(pt)
  print("Server response:", response)
