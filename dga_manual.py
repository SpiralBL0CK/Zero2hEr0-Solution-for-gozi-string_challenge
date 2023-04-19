import sys
import time
import codecs
import re
from pwn import *
from ctypes import *
from ctypes.wintypes import *


dword_1000A348 = "0xf21ad7d0"
dword_1000A2FC = 0x106
dword_1000A310 = 0xad986467 ^ 0x81BBE65D
dword_1000A3CC = [0xB6,0x82 ,0xAA ,0x45 ,0xD0 ,0x38 ,0xE2 ,0x84 ,0xBA ,0x86 ,0xB5 ,0x50 ,0xDB ,0x43 ,0xE6 ,0x88 ,0x77 ,0x70 ,0x70 ,0x6F ,0xDB ,0x8D,0xE6 ,0x88 ,0x77 ,0xF8 ,0x6F ]
byte_1000B552 = [0x7, 0x95, 0x17, 0xA9, 0xF8, 0x29, 0xCF, 0xDC, 0xCE, 0x56,0xE6, 0x99, 0xEC, 0x5E, 0xE, 0x2A, 0x17, 0x55, 0xEB,0x95,0xDE, 0x69, 0xFF, 0xFB, 0xD4, 0x35, 0xD9, 0xA3, 0x3, 0x3D,0xE4, 0xE0, 0xBF,0x50, 0xC1, 0xCC, 0x3C, 0x70, 0x28, 0xF9,0xCD, 0x55, 0x7D, 0xAB, 0x19,0x1D, 0x2D, 0x20, 0xA8, 0x5A,0xCD, 0x5B, 0x5E, 0x21, 0xB8]
dword_1000A344  = 0x69B25F44
dword_1000A304 = open(sys.argv[1],"rb").read()

class FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime", ctypes.c_ulong),
        ("dwHighDateTime", ctypes.c_ulong)
    ]

def REV(n: int) -> int:
    return ((n >> 24) & 0xff) | ((n << 8) & 0xff0000) | ((n >> 8) & 0xff00) | ((n << 24) & 0xff000000)
    # If output of all the above expression is
    # OR'ed then it results in 0xddccbbaa

def generate_seed_or_smthig_based_on_date(param1,param2,param3,param4,param5):
    result = param1 >> 2
    print(hex(result))
    v6 = 0 
    ctr = 0
    decrypted_string = []
    if(result > 0):
        v7 = param3 # sau param 2 ca is idetice pana la urma
        while(result):
            v8 = int.from_bytes(bytes(v7[ctr:(ctr+4)]))
            v8 = REV(v8)
            if(((not param5) or (v8))):
                res = ((v6 - param4)  & 0xffffffff )
                print(hex(res))
                res += v8
                res = res & 0xffffffff
                res = REV(res)
                res = hex(res)
                v6 = v8
                decrypted_string.append(res)
                ctr += 4
            else:
                result = 1
            result-=1
    #print(decrypted_string)
    
    return decrypted_string


def sub_100047C8(param1,binar_blob):
    nt_header = binar_blob[binar_blob[0x3c]:]
    #print(hexdump(nt_header))
    edx = nt_header[0x14]
    esi = nt_header[6]
    #print(esi)
    ecx = nt_header[edx+0x18:]
    #print(hexdump(ecx))
    v8 = 0
    counter = 0
    for i in range(0,5):
        if((ecx[counter:][0:4] == b'.bss') and (not(ecx[counter:][4:8] == b'0000'))):
            print("win")
            v8 = ecx[counter:]
        else:
            print("=============================================")
            print(hexdump(ecx[counter:][0:4]))
            print("=============================================")
        pass
        counter += 40
    ecx = v8[0xd:0x0f]
    print(hexdump(ecx))
    if(ecx != b'0000'):
        v10 = v8[0x10:0x14]
        #print(hexdump(v10))
        #print("weener")
        if(v10):
            return(ecx,v10)


def dga(param1_binar_memorie,param2):
    v11 = "26 2022"
    param3,param4 = sub_100047C8(1,param1_binar_memorie)
    param4 = int.from_bytes(param4)
    param3 = int.from_bytes(param3)
    print(param3)
    print(param4)
    v5 =  (param4 >> 12) + ((param4 & 0xFFF) != 0)
    v6 =  param1_binar_memorie[param3:]
    v12 = param1_binar_memorie[param3:]
    """
    As we cannot emulate the heapalloc for this particullary case we relly on ctypes to do the job
    """
    v7 =  v12[0:0x1000]
    print("=============================================")
    print(hexdump(v7))
    print("=============================================")
    """
    in upcoming lines we emulate this 
      Size = 0; where size == param4
      v9 = a2;
      if ( v5 )
      {
        v14 = (&unk_1000B7CB + v8 - v6 + a2);
        v16 = v8;
        do
        {
          strcpy(v11, "26 2022");
          generate_seed_or_smthig_based_on_date(0x1000u, v16, v16, v15 + v11[0] + *"Apr 26 2022" - Size + a2 - 1, 1);
          v10 = v14[1] - v14[2];
          v16 += 4096;
          v9 = v14[3] + v10;
          ++Size;
        }
        while ( Size < v5 );
    """
    param4 = 0
    v9 = param2
    v8 = v7
    unk_1000B7CB = [
        0x66, 0x1D, 0xAF, 0xF0, 0x1B, 0x9A, 0xD7, 0xC2, 0x83, 0x54, 
        0xE2, 0x42, 0x3E, 0xA4, 0xE3, 0xB6, 0x88, 0x01, 0xB6, 0x4B, 
        0x3C, 0xF4, 0x0F, 0xBA, 0x77, 0x05, 0xB0, 0x48, 0x49, 0xAE, 
        0xC6, 0x8B, 0x75, 0x43, 0xB0, 0x79, 0x46, 0xA9, 0x0E, 0x8E, 
        0x7F, 0xFC, 0xB9, 0x6A, 0x46, 0xEE, 0x0E, 0x9F, 0x71, 0xFB, 
        0x75, 0xF4, 0x05, 0xFD, 0x59, 0x12, 0xC1, 0xED, 0x69, 0xF3, 
        0x00, 0x07, 0x61, 0xC5, 0xAD, 0xF1, 0x6E, 0x41, 0x19, 0xF9, 
        0x54, 0x85, 0x6B, 0xE8, 0x64, 0x6D, 0x18, 0xCF, 0x26, 0x58, 
        0x68, 0x24, 0x9C, 0xAE, 0xEA, 0xBD, 0xE4, 0x12, 0xCC, 0x34, 
        0xDE, 0x80
    ]

    v14 = unk_1000B7CB[param2]
    print(v14)
    v16 = v8
    additional_val = 0x20727041
    v11 = hex(int.from_bytes(bytes(v11[0:4],'utf-8')[::-1]))
    print(v11)
    v11 = int(v11,base=16)
    #print(hex(param3+v11+additional_val))

    ctr = 0
    ctr_new_decrypted_string = 0 
    new_str = ""
    non_wide_decrypted_string = []
    for param4 in range(0,v5):
        z =  param3+v11+additional_val-param4+param2-1
        print(hex(z))
        res = generate_seed_or_smthig_based_on_date(
            0x1000,
            v16,
            v16,
            z,
            1
        )
        print("acu incepe nebunia")
        print("=============================================")
        for i in res:
            for j in range(2,len(i),2):
                if(i[j:j+2] == "00"):
                    continue
                else:
                    new_str += i[j:j+2]
                    ctr_new_decrypted_string+=1
                if(ctr_new_decrypted_string == 4):
                    non_wide_decrypted_string.append(new_str)
                    new_str = ""
                    ctr_new_decrypted_string = 0
        x = ""
        for i in non_wide_decrypted_string:
            x += "".join(i)
        x = x.encode("utf-8")
        z = str(codecs.decode(x,'hex'))
        #print(z)
        x = (codecs.decode(x,'hex'))
    
        count = 0
        for match in re.finditer(b"(^M|\WM|^.i|\W.i|^i|\Wi).{3,8}?(ft\W|ft$)", x):
            count += 1
            #print("match", count, match.group(), "start index", match.start(), "End index", match.end())
            #print(x[match.end()])
        print(x)
        #print(non_wide_decrypted_string)
        #print(non_wide_decrypted_string)
        #mai ai ultima bcata de ilementat dua generate_-seed blah si restu dupa foru ista
        ctr += 4096 
        v16 = v16[ctr:]
        break
    
        

def utcnow_microseconds():
    system_time = FILETIME()
    ctypes.windll.kernel32.GetSystemTimeAsFileTime(ctypes.byref(system_time))
    x = (system_time.dwLowDateTime >> 5 )% 0x13 +1
    return x    

def sub_10004B89(param1):
    dwLowDateTime = 0
    dwHighDateTime = 0
    v1 = 1  
    rez = (hex(utcnow_microseconds()))
    rez = int(rez,base=16)
    rez = 0x13
    dga(param1,rez)




if __name__ == "__main__":
    data = open(sys.argv[2],"rb").read()
    sub_10004B89(data)
