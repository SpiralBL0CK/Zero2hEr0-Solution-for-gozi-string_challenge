import sys
from pwn import *
from dumpulator import Dumpulator

dword_1000A348 = "0xf21ad7d0"
dword_1000A2FC = 0x106
dword_1000A310 = 0xad986467 ^ 0x81BBE65D
dword_1000A3CC = [0xB6,0x82 ,0xAA ,0x45 ,0xD0 ,0x38 ,0xE2 ,0x84 ,0xBA ,0x86 ,0xB5 ,0x50 ,0xDB ,0x43 ,0xE6 ,0x88 ,0x77 ,0x70 ,0x70 ,0x6F ,0xDB ,0x8D,0xE6 ,0x88 ,0x77 ,0xF8 ,0x6F ]
byte_1000B552 = [0x7, 0x95, 0x17, 0xA9, 0xF8, 0x29, 0xCF, 0xDC, 0xCE, 0x56,0xE6, 0x99, 0xEC, 0x5E, 0xE, 0x2A, 0x17, 0x55, 0xEB,0x95,0xDE, 0x69, 0xFF, 0xFB, 0xD4, 0x35, 0xD9, 0xA3, 0x3, 0x3D,0xE4, 0xE0, 0xBF,0x50, 0xC1, 0xCC, 0x3C, 0x70, 0x28, 0xF9,0xCD, 0x55, 0x7D, 0xAB, 0x19,0x1D, 0x2D, 0x20, 0xA8, 0x5A,0xCD, 0x5B, 0x5E, 0x21, 0xB8]
dword_1000A344  = 0x69B25F44
dword_1000A304 = open(sys.argv[1],"rb").read()

def hash(a):
    dp = Dumpulator(sys.argv[2],quiet=False)
    #piret = dp.allocate(256)
    #lpmem = dp.allocate(256)
    #dp.call(0x10007780,[piret,lpmem,0x69B25F44  ^ 0x889A0120])
    #decrypted = dp.read_str(piret)
    #print(f"decrypted: '{decrypted}'")

if __name__ == "__main__":
    hash(dword_1000A344 ^ 0x889A0120)
                                               
