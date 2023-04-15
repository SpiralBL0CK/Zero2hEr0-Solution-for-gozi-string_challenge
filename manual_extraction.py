import sys
import re
import pefile
import json
from pwn import *
from dumpulator import Dumpulator

dword_1000A348 = "0xf21ad7d0"
dword_1000A2FC = 0x106
dword_1000A310 = 0xad986467 ^ 0x81BBE65D
dword_1000A3CC = [0xB6,0x82 ,0xAA ,0x45 ,0xD0 ,0x38 ,0xE2 ,0x84 ,0xBA ,0x86 ,0xB5 ,0x50 ,0xDB ,0x43 ,0xE6 ,0x88 ,0x77 ,0x70 ,0x70 ,0x6F ,0xDB ,0x8D,0xE6 ,0x88 ,0x77 ,0xF8 ,0x6F ]
byte_1000B552 = [0x7, 0x95, 0x17, 0xA9, 0xF8, 0x29, 0xCF, 0xDC, 0xCE, 0x56,0xE6, 0x99, 0xEC, 0x5E, 0xE, 0x2A, 0x17, 0x55, 0xEB,0x95,0xDE, 0x69, 0xFF, 0xFB, 0xD4, 0x35, 0xD9, 0xA3, 0x3, 0x3D,0xE4, 0xE0, 0xBF,0x50, 0xC1, 0xCC, 0x3C, 0x70, 0x28, 0xF9,0xCD, 0x55, 0x7D, 0xAB, 0x19,0x1D, 0x2D, 0x20, 0xA8, 0x5A,0xCD, 0x5B, 0x5E, 0x21, 0xB8]
dword_1000A344  = 0x69B25F44
dword_1000A304 = open(sys.argv[1],"rb").read()

def unpack_config(data):
    print(hexdump(data))
    print("====================")
    config = '{"header":"NULL"}'
    config = json.loads(config)
    config['header'] = data[0:2]
    config['flags'] = data[2:4]
    config['xor_key'] = data[4:8]
    config['crc_hash'] = data[8:0xc]
    config['offset_blob'] = data[0xc:0x10]
    config['size_of_blob'] = data[0x10:0x14]
    print(config)



def hash(a):
    struct_list = []
    v12 = 0
    v4 =  dword_1000A344 ^ 0x150E;
    v16 = dword_1000A344 ^ 0x150E;
    pefile = open(sys.argv[1],"rb").read()
    print(pefile)
    nt_header = pefile[pefile[0x3c]:]
    print(hexdump(nt_header))
    edx = (nt_header[6]+1)*0x28
    ebx = nt_header[0x14]
    print(ebx,edx)
    print("=============================================")
    #print(hexdump(nt_header[ebx:]))
    to_check = nt_header[ebx+edx:]
    to_check = to_check[24:]
    print(hexdump(to_check))
    for string in re.finditer(bytes("JJ","utf-8"),to_check):
        struct_list.append(string.start())
    print("----------------------------------------------")
    print(to_check)
    print("**********************************************")
    print(struct_list)
    struct_list.append(struct_list[-1]+20)
    for i in range(len(struct_list)-1):
        passed_data = to_check[struct_list[i]:struct_list[i+1]]
        unpack_config(passed_data) 


if __name__ == "__main__":
    hash(dword_1000A344 ^ 0x889A0120)
