# -*- coding: utf-8 -*-

import os, sys, binascii, re, hashlib, time, csv
import argparse
import magic
import pefile

try:
    from tabulate import tabulate
except:
    print ("You need to install tabulate library (pip install tabulate)")

def parseArgument():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help="name of target (directory or file)", required=True)
    parser.add_argument('-c', '--csv', help="output with CSV file", action="store_true", required=False)
    parser.add_argument('-s', '--stdout', help="output with stdout(Default)", action="store_true", required=False)
    return parser

class threatDigger:
    def __init__(self, args):
        self.args = args
        self.target = self.args.target
        self.work_file = ''
        self.displaylist = []
        self.varInit()

    def varInit(self):
        self.filename = '-'
        self.buildtime = '-'
        self.internalName = '-'
        self.companyName = '-'
        self.richHeaderXorkey = '-'
        self.richHeaderCleardata = '-'
        self.richHeaderDansAnchor = '-'
        self.richHeaderClearDataMD5 = '-'
        self.imphash = '-'
        self.exportName = ''
        
    def display(self):
        print (tabulate(self.displaylist, headers=['Filename', 'Buildtime', "Export Function" ,'InternalName', 'CompanyName','RHXorkey', 'DansAnchor', 'RHCleardataMD5', 'Imphash'
        ]))
        
    def displayAppend(self):
        if len(self.filename) > 40:
            self.displaylist.append([self.filename[:40]+"...", self.buildtime, self.exportName, self.internalName, self.companyName, self.richHeaderXorkey, self.richHeaderDansAnchor, self.richHeaderClearDataMD5, self.imphash])
        else:
            self.displaylist.append([self.filename, self.buildtime, self.exportName, self.internalName, self.companyName, self.richHeaderXorkey, self.richHeaderDansAnchor, self.richHeaderClearDataMD5, self.imphash])    

    def csvAppend(self):
        #fieldnames = ['Filename', 'Buildtime', 'Internal Name', 'Company Name', 'Richheader Xorkey', 'Richheader DansAnchor', 'RH Cleardata MD5', 'Imphash']
        self.writer.writerow({'Filename': self.filename, 'Buildtime': self.buildtime, 'Export Function': self.exportName, 'Internal Name': self.internalName, 'Company Name': self.companyName, 'Richheader Xorkey': self.richHeaderXorkey, 
                                     'Richheader DansAnchor': self.richHeaderDansAnchor, 'RH Cleardata MD5': self.richHeaderClearDataMD5, 'Imphash': self.imphash})
        return
        
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
        clearData = bytes()

        for i in range(0, len(rhData)):
            clearData += bytes([rhData[i] ^ xorKey[i % len(xorKey)]])
        
        self.richHeaderClearDataMD5 = hashlib.md5(clearData).hexdigest()
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
            raw_clearData = self.xorDec(rhData, xorKey)
            clearData = binascii.hexlify(binascii.unhexlify(binascii.hexlify(raw_clearData).decode("utf-8"))).decode("utf-8")
            xorKey = binascii.hexlify(bytearray(xorKey)).decode("utf-8").upper()
            dansAnchor = binascii.hexlify(bytearray(dansAnchor)).decode("utf-8").upper()

            return "0x"+xorKey, "0x"+dansAnchor, "0x"+clearData
            
        except:
            return "-", "-", "-"
        
    def processing(self):
        result, type = self.isPe()
        if (result): #if target file is PE
            try:
                self.richHeaderXorkey, self.richHeaderDansAnchor, self.richHeaderCleardata = self.parseRichheader() #get Richheader Parsing Result
                pe = pefile.PE(self.work_file)
                try:
                    self.internalName = pe.FileInfo[0][0].StringTable[0].entries[b'InternalName'].decode("UTF-8")
                except:
                    pass
                try:
                    self.companyName = pe.FileInfo[0][0].StringTable[0].entries[b'CompanyName'].decode("UTF-8")
                except:
                    pass
                try:
                    self.buildtime = time.strftime("%Y.%m.%d %H:%M:%S", time.localtime(pe.FILE_HEADER.TimeDateStamp))
                except:
                    pass
                try:
                    self.imphash = pe.get_imphash()
                except:
                    pass
                try:
                    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        exportName = exp.name.decode("utf-8")
                        if (len(exportName) > 1):
                            if (len(exportName) > 20):
                                self.exportName += "\n"+exportName + " "
                            else:
                                self.exportName += exportName + " "
                        else:
                            continue
                except:
                    self.exportName = "-"
                    pass

                self.displayAppend()
                if self.args.csv:
                    self.csvAppend()

            except Exception as e:
                print (self.work_file)
                print ("Error has been occured: ", e)
                return
        else:
            return

    def checkFileType(self):
        if (self.isDir()):
            for root, directories, files in os.walk(self.target):
                for self.filename in files:
                    self.work_file = os.path.join(root, self.filename)
                    self.processing()
                    self.varInit()
        else:
            self.work_file = self.target
            self.filename = self.target[self.target.rfind("/"):]
            self.processing()
            self.varInit()

    def entry(self):
        if self.args.csv:
            self.csvFilename = "threatDigger_result.csv"
            with open(self.csvFilename,"w") as self.csvfile:
                fieldnames = ['Filename', 'Buildtime', 'Export Function', 'Internal Name', 'Company Name', 'Richheader Xorkey', 'Richheader DansAnchor', 'RH Cleardata MD5', 'Imphash']
                self.writer = csv.DictWriter(self.csvfile, fieldnames=fieldnames)
                self.writer.writeheader()
                self.checkFileType()
        else:
            self.checkFileType()

    def isPe(self):
        with magic.Magic() as m:
            try:
                filetype = m.id_filename(self.work_file)
                if (filetype.find("exe") > -1):
                    if ((filetype.find("Python") > -1) or (filetype.find("Bourne-Again") > -1) or (filetype.find("PDP-11") > -1)):
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
    td = threatDigger(args)    
    td.entry()
    td.display()
    if td.args.csv:
        os.system("open "+td.csvFilename)

if "__main__" == __name__:
    main()