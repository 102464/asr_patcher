#!/usr/bin/env python3
try:
    import r2pipe
except Exception:
    print("ERROR trying to import r2pipe.")
    print("Please install radare2 via package manager or Internet and run:")
    print("'pip install r2pipe'")
    exit(1) 
import json
import sys
import shutil
import os

if len(sys.argv) != 3:
    print("usage: " + sys.argv[0] + " [asr_in] [asr_out]")
    exit(1)
print("Welcome to ASR Patcher. This tool will patch asr signature checks using radare2.")
if not os.path.exists(sys.argv[1]):
    print("<IN_FILE>" + sys.argv[1] + " not found!")
    exit(1)
shutil.copyfile(sys.argv[1], sys.argv[2])
print("Opening " + sys.argv[2])
r = r2pipe.open(sys.argv[2], flags=['-w'])
print("Analyzing ELF executable...")
r.cmd("aaa")
print("Searching for \"Image passed signature verification\"...")
json_data = r.cmd("/j Image passed signature verification")
data = json.loads(json_data)
addr = hex(data[0]['offset'] - 10)
print("start disassembling address offset: " + addr)
r.cmd(addr)
json_data = r.cmd("pdj")
data = json.loads(json_data)
addr = None
for element in data:
    #print("Checking: " + str(element))
    if 'flags' in element:
        print("Found flags. Continuing.")
        print("flags: " + element['flags'][0])
        if element['flags'][0] == "str.Image_passed_signature_verification":
            print("Found string at offset " + hex(element['offset']))
            if not 'xrefs' in element:
                print("XREF not found! May be it is already patched?\nThis may be a temporary issue. Clear the cache and try again.")
                exit(1)
            _addr = element['xrefs'][0]['addr'] - 0xA
            addr = hex(_addr + 0xA)
            print("XREF -> " + addr)
            break
if addr == None:
    print("ERROR: str.Image_passed_signature_verification not found!")
    exit(255)
print("NOTE: Modified instruction will point to this address: " + hex(_addr))
desc_addr = hex(_addr)
print("Start disassembling address offset: " + hex(_addr))
r.cmd(hex(_addr))
json_data = r.cmd("pdj")
data = json.loads(json_data)
addr = None
for element in data:
    if element['disasm'] == "movs r4, 0x50":
        _addr = element['offset'] - 0x4
        addr = hex(_addr + 0x4)
        print("Found movs r4, 0x50 at address " + addr)
if addr == None:
    print("ERROR: instruction \"movs r4, 0x50\" not found!")
    exit(255)
print("Writing instruction \"b " + desc_addr + "\" to address " + hex(_addr))
r.cmd(hex(_addr))
r.cmd("wa b " + desc_addr)
print("DONE: Please see the decompilation result to make sure the patch is correct.")
r.cmd(desc_addr)
print(r.cmd("pd 20"))
print("Writing and listing all changes...")
r.cmd("wci")
print(r.cmd("wc"))
print("Patch complete.")
r.quit()