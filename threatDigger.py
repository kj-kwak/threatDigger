# -*- coding: utf-8 -*-

import os
import sys
import argparse
import magic
import binascii
import re
import hashlib
import pefile
import time
from tabulate import tabulate

def parseArgument():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-t', '--target', help="name of target (directory or file)", required=True)
    return parser

class threatDigger:
    def __init__(self, arg_target):
        self.target = arg_target
        self.filename = ''
        self.buildtime = ''
        self.internalName = ''
        self.companyName = ''
        self.work_file = ''
        self.displaylist = []
        self.richHeaderXorkey = ''
        self.richHeaderCleardata = ''
        self.richHeaderDansAnchor = ''
        self.richHeaderClearDataMD5 = ''
        self.imphash = ''

    def display(self):
        print (tabulate(self.displaylist, headers=['Filename', 'Buildtime', 'InternalName', 'CompanyName','RHXorkey', 'DansAnchor', 'RHCleardataMD5', 'Imphash'
        ]))
        
    def displayAppend(self):
        if len(self.filename) > 40:
            self.displaylist.append([self.filename[:40]+"..."+"|", self.buildtime+"|", self.internalName+"|", self.companyName+"|", self.richHeaderXorkey+"|", self.richHeaderDansAnchor+"|", self.richHeaderClearDataMD5+"|", self.imphash])
        else:
            self.displaylist.append([self.filename+"|", self.buildtime+"|", self.internalName+"|", self.companyName+"|", self.richHeaderXorkey+"|", self.richHeaderDansAnchor+"|", self.richHeaderClearDataMD5+"|", self.imphash])    
        

    def getBinaryContent(self):
        fh = open(self.work_file, "rb")
        content = bytearray()
        for i in fh : content += i
        fh.close()
        return content

    def xorDans(self, key):
        l = len(key)
        data = "DanS"
        bytedata = str.encode(data)

        return bytearray((
            (bytedata[i] ^ key[i % l]) for i in range(0,len(bytedata))
        ))

    def xorDec(self, rhData, xorKey):
        # Decode every four bytes with XOR key
        clearData = ""

        for i in range(0, len(rhData)):
            clearData += chr(rhData[i] ^ xorKey[i % len(xorKey)])

        return clearData

    def parseRichheader(self):
        #print (self.work_file)
        content = self.getBinaryContent()
        try:
            xorKey = re.search(b"\x52\x69\x63\x68....\x00", content).group(0)[4:8]
            dansAnchor = self.xorDans(xorKey)
            richStart = re.search(re.escape(dansAnchor), content).start(0)
            richEnd = re.search(b'\x52\x69\x63\x68'+re.escape(xorKey), content).start(0)

            if richStart < richEnd:
                rhData = content[richStart:richEnd]
            else:
                raise Exception("WTF")

            clearData = binascii.hexlify(bytearray(str.encode(self.xorDec(rhData, xorKey)))).decode("utf-8").upper()
            xorKey = binascii.hexlify(bytearray(xorKey)).decode("utf-8").upper()
            dansAnchor = binascii.hexlify(bytearray(dansAnchor)).decode("utf-8").upper()

            return "0x"+xorKey, "0x"+dansAnchor, "0x"+clearData
        
        except:
            return None, None
        
    def process(self):
        result, type = self.isPe()
        if (result): #if target file is PE
            try:
                #print (self.work_file)
                self.richHeaderXorkey, self.richHeaderDansAnchor, self.richHeaderCleardata = self.parseRichheader() #get result of Richheader Parsing
                print (self.richHeaderCleardata.encode("utf-8"))
                self.richHeaderClearDataMD5 = hashlib.md5(self.richHeaderCleardata.encode("utf-8")).hexdigest()

                pe = pefile.PE(self.work_file)
                try:
                    self.internalName = pe.FileInfo[0][0].StringTable[0].entries[b'InternalName'].decode("UTF-8")
                except:
                    self.internalName = "None"
                try:
                    self.companyName = pe.FileInfo[0][0].StringTable[0].entries[b'CompanyName'].decode("UTF-8")
                except:
                    self.companyName = "None"
                try:
                    self.buildtime = time.strftime("%Y.%m.%d %H:%M:%S", time.localtime(pe.FILE_HEADER.TimeDateStamp))
                except:
                    self.buildtime = "None"
                try:
                    self.imphash = pe.get_imphash()
                except:
                    self.imphash = "None"

                self.displayAppend()

            except:
                print ("error")
                return
        else:
            #print (self.filename+": This file is not a PE type")
            return

    def entry(self):
        if (self.isDir()):
            for root, directories, files in os.walk(self.target):
                for self.filename in files:
                    self.work_file = os.path.join(root, self.filename)
                    self.process()

        else:
            self.work_file = self.target
            self.filename = self.target[self.target.rfind("/"):]
            #print (self.work_file, self.filename)
            self.process()

    def isPe(self):
        with magic.Magic() as m:
            try:
                filetype = m.id_filename(self.work_file)
                if (filetype.find("exe") > -1):
                    if (filetype.find("Python") > -1):
                        return 0, filetype
                    else:
                        return 1, filetype
                else:
                    return 0, filetype

            except Exception as e:
                return 0, None

    def isDir(self):
        if os.path.isdir(self.target):
            return 1
        else:
            return 0

def main():
    args = parseArgument().parse_args()
    td = threatDigger(args.target)    
    td.entry()
    td.display()

if "__main__" == __name__:
    main()