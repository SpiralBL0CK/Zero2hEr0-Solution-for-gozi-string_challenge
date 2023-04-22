import sys
import re
import pefile
import json
from aplib import *
import struct
from pwn import *
from dumpulator import Dumpulator
import ctypes
dword_1000A348 = "0xf21ad7d0"
dword_1000A2FC = 0x106
dword_1000A310 = 0xad986467 ^ 0x81BBE65D
dword_1000A3CC = [0xB6,0x82 ,0xAA ,0x45 ,0xD0 ,0x38 ,0xE2 ,0x84 ,0xBA ,0x86 ,0xB5 ,0x50 ,0xDB ,0x43 ,0xE6 ,0x88 ,0x77 ,0x70 ,0x70 ,0x6F ,0xDB ,0x8D,0xE6 ,0x88 ,0x77 ,0xF8 ,0x6F ]
byte_1000B552 = [0x7, 0x95, 0x17, 0xA9, 0xF8, 0x29, 0xCF, 0xDC, 0xCE, 0x56,0xE6, 0x99, 0xEC, 0x5E, 0xE, 0x2A, 0x17, 0x55, 0xEB,0x95,0xDE, 0x69, 0xFF, 0xFB, 0xD4, 0x35, 0xD9, 0xA3, 0x3, 0x3D,0xE4, 0xE0, 0xBF,0x50, 0xC1, 0xCC, 0x3C, 0x70, 0x28, 0xF9,0xCD, 0x55, 0x7D, 0xAB, 0x19,0x1D, 0x2D, 0x20, 0xA8, 0x5A,0xCD, 0x5B, 0x5E, 0x21, 0xB8]
dword_1000A344  = 0x69B25F44
dword_1000A304 = open(sys.argv[1],"rb").read()

def isKthBitSet(n, k):
    if n & (1 << k):
        return True
    else:
        return False



def string_decrypt_config(a2,hashz):
    result= 0
    v5 = 0
    v4 = a2[4]
    while(result == 0):
        if(v5 > a2):
            break
        if(v4-2) == hashz:
            if((v4-1) and 1) != 0:
                result = v4 + (v4-8)
            else:
                result = v4
        v5+=1
        v4+=6
    return result



def unpack_config(data):
    print(hexdump(data))
    print("====================")
    config = '{"header":"NULL"}'
    config = json.loads(config)
    config['header'] = data[0:2]
    config['flags'] = data[2:4]
    config['xor_key'] = int.from_bytes(data[4:8],"little")
    config['crc_hash'] = data[8:0xc]
    config['offset_blob'] =  int.from_bytes(data[0xc:0x10],"little")
    config['size_of_blob'] = int.from_bytes(data[0x10:0x14],"little")+1
    return config


def sub_10007A1E(j):
    pass




def hash(param1):
    struct_list = []
    v12 = 0
    v4 =  dword_1000A344 ^ 0x150E;
    v16 = dword_1000A344 ^ 0x150E;
    pefile = open(sys.argv[1],"rb").read()
    #print(pefile)
    nt_header = pefile[pefile[0x3c]:]
    #print(hexdump(nt_header))
    edx = (nt_header[6]+1)*0x28
    ebx = nt_header[0x14]
    #print(ebx,edx)
    
    #print("=============================================")
    #print(hexdump(nt_header[ebx:]))
    
    to_check = nt_header[ebx+edx:]
    to_check = to_check[24:]
    
    #print(hexdump(to_check))
    
    for string in re.finditer(bytes("JJ","utf-8"),to_check):
        struct_list.append(string.start())

    configs = []
    decrypted_packages = [] 
    binary_blob_of_data = open(sys.argv[3],"rb").read()
    struct_list.append(struct_list[-1]+20)

    for i in range(len(struct_list)-1):
        keys = []
        passed_data = to_check[struct_list[i]:struct_list[i+1]]
        #print(unpack_config(passed_data))
        configs.append(unpack_config(passed_data))
        #print("////////////////////////////////////////////:")
        start = configs[i]['offset_blob']
        end = configs[i]['offset_blob']+configs[i]['size_of_blob']
        #print(hex(start),hex(end))
        #print("+++++++++++++++++++++++++++++++++++++++++++++")
        encrypted_package = binary_blob_of_data[start:end]
        #print(hexdump(encrypted_package))
        #print("+++++++++++++++++++++++++++++++++++++++++++++")
        current_key = 0
        for j in range(0,len(encrypted_package),4):
            if j == 0:
                v9 = encrypted_package[j:j+4] 
                v9 = hex(int.from_bytes(v9))[2:]
                print(v9)
                v9 = "".join(reversed([v9[i:i+2] for i in range(0, len(v9), 2)]))
                v9 = int(v9,base=16)-configs[i]['xor_key']
                print("||||||||||||||||||||||||||||||||||||||||||||")
                print("i egal 0")
                print(hex(v9))
                current_key = v9+configs[i]['xor_key']
                keys.append(current_key)
            else:
                v9 = encrypted_package[j:j+4]
                v9 = hex(int.from_bytes(v9))[2:]
                v9 = "".join(reversed([v9[i:i+2] for i in range(0, len(v9), 2)]))
                print("||||||||||||||||||||||||||||||||||||||||||||")
                print(v9)
                print(hex(current_key))
                print("in else")
                old_key = current_key
                current_key = (int(v9,base=16)-current_key) & 0xffffffff
                print("dupa new calc new crnt key ")
                print(hex(current_key))
                current_key = (current_key + old_key)& 0xffffffff
                keys.append(current_key)
        decrypted_packages.append(keys)
        if((configs[i]['size_of_blob'] & 3) != 0):
            pass # we need to somehow enter this
            #sub_10007A1E ( (configs[i]['size_of_blob'] & 3) )
        v12 = 1

        print("]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]")
        print(type(decompress(encrypted_package)))

        print(decompress(encrypted_package))
        print(decrypted_packages)
    return(decrypted_packages,configs[0]['size_of_blob'])

def custom_hash(param1,param2):
    #0046f9a4 = couter
    res = 0 
    edi = param1[0]
    counter = 1
    ecx = param1[4]
    for i in range(edi):
        ebx = param1[(counter+1)]
        print(hex(ebx))
        print(counter)
        if(ebx == param2):
            print("in if")
            if(( param1[(counter+2)] and 1 ) != 0):
                res = 0xa8+param1[(counter+3)]+param1[2]
                print(hex(res))
        counter += 6


if __name__ == "__main__":
    #hash(dword_1000A344 ^ 0x889A0120)
    #for testing purpose only
    v0 = [0x0000000B, 0x00000000, 0xD0665BF6, 0x00000001, 0x00000108, 0x00000000, 0x00000000, 0x00000000,
    0x54432E74, 0x00000001, 0x00000124, 0x00000000, 0x00000000, 0x00000000, 0xBBB5C71D, 0x00000001,
    0x00000113, 0x00000000, 0x00000000, 0x00000000, 0x073D11EE, 0x00000001, 0x00000100, 0x00000000,
    0x00000000, 0x00000000, 0x656B798A, 0x00000001, 0x000000ED, 0x00000000, 0x00000000, 0x00000000,
    0x556AED8F, 0x00000001, 0x000000DA, 0x00000000, 0x00000000, 0x00000000, 0x4FA8693E, 0x00000001,
    0x000000C5, 0x00000000, 0x00000000, 0x00000000, 0x11271C7F, 0x00000001, 0x000000BE, 0x00000000,
    0x00000000, 0x00000000, 0x48295783, 0x00000001, 0x000000A8, 0x00000000, 0x00000000, 0x00000000,
    0x584E5925, 0x00000001, 0x00000093, 0x00000000, 0x00000000, 0x00000000, 0x41CAE66D, 0x00000001,
    0x0000007D, 0x00000000, 0x00000000, 0x00000000, 0x666E6F63, 0x652E6769, 0x2E656764, 0x70796B73,
    0x6F632E65, 0x3831206D, 0x38312E35, 0x35312E39, 0x38322E31, 0x35383120, 0x3938312E, 0x3135312E,
    0x0030372E, 0x6572642F, 0x2E002F77, 0x006B6C6A, 0x706D622E, 0x30303300, 0x30350030, 0x45473000,
    0x4B6F564F, 0x4E674F6E, 0x636A7857, 0x00310049, 0x30003032, 0x00003000, 0x7710235A, 0x0000EC32,
    0x00DC9590, 0x00A500C4 ]
    if(len(v0) > 0 ):
        custom_hash(v0,dword_1000A344 ^ 0x7895433B)
