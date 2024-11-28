#!/usr/bin/env python3
from socketserver import BaseRequestHandler,ThreadingTCPServer
import random
import os
import string
from hashlib import sha256
import signal
import json
from flag import flag

assert len(flag) == 42 and flag.startswith(b"DubheCTF{")

with open("polys.txt","r") as f:
    polys = json.load(f)

def random_poly():
    return polys[random.randint(0,len(polys)-1)]

N = 256

BANNER = br'''
 CCCCC  RRRRRR   CCCCC       GGGG    AAA   MM    MM EEEEEEE 
CC    C RR   RR CC    C     GG  GG  AAAAA  MMM  MMM EE      
CC      RRRRRR  CC         GG      AA   AA MM MM MM EEEEE   
CC    C RR  RR  CC    C    GG   GG AAAAAAA MM    MM EE      
 CCCCC  RR   RR  CCCCC      GGGGGG AA   AA MM    MM EEEEEEE 
 '''




def crc256(msg,IN,OUT,POLY):
    crc = IN
    for b in msg:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (POLY & -(crc & 1))
    return (crc ^ OUT).to_bytes(32,'big')

def setup():
    print(BANNER)

def handle():
    # signal.alarm(120)
    # if not proof_of_work():
    #     return
    # initial
    IN = random.getrandbits(N)
    OUT = random.getrandbits(N)
    POLY = random_poly()

    for i in range(5):
        print("what do you want to do?")
        print("1.calculate crc")
        print("2.getflag")
        print("3.exit")
        try:
            choice = input()
            if choice == '1':
                msg = bytes.fromhex(input())
                crc_hex = crc256(msg,IN,OUT,POLY).hex()
                print("Here is your crc: "+crc_hex)
            elif choice == '2':
                flag_crc = crc256(flag,IN,OUT,POLY).hex()
                print("Here is your flag: "+flag_crc)
            else:
                return
        except:
            print("error")
            pass

handle()
