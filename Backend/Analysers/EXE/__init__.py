import magic
import json
import pefile
import pyexifinfo
import hashlib
import re
import time
from datetime import datetime

__author__ = "Aziz saadaoui"
__version__ = '0.1'
__license__ = 'MIT License'

class PEstatmal():

    def __init__(self, file_name):
        self.filepath = file_name
        self.pe = pefile.PE(self.filepath)
        if not self.pe:
            raise pefile.PEFormatError('__EmptyFile__')
    
    def run(self): 
        results = {}

        results = {
            'ImpHash': self.PE_imphash(),
            'Hashes': self.PE_hash(),
            'Anti_VM': self.check_antiVM(self.filepath),
            'Type': self.PE_type(),
            'os': self.PE_os(),
            'importHash': self.PE_imphash(),
            'Arch': self.PE_arch(),
            'Entry Point': self.PE_entrypoint(),
            'Compiled': self.PE_time(),
            'Image Base': self.PE_imagebase(),
            'Sections': self.PE_sections(),
            'Security': self.PE_security(),
            'Entry Imports': self.PE_enty_import(),
            'Entry Exports':  self.PE_entry_export()
        }

        return results
    
    def PE_imphash(self):
        imp_hash = self.pe.get_imphash()
        return imp_hash 
    
    def PE_type(self):
        if self.pe.is_dll(): rtype = 'DLL'
        if self.pe.is_driver(): rtype = 'DRIVER'
        if self.pe.is_exe(): rtype = 'EXE'
        return rtype

    def PE_hash(self):
        hashes = {}
        content = open(self.filepath, 'r').read()  
        hashes["Hash_md5"]  = hashlib.md5(content).hexdigest()
        hashes["Hash_sha1"]  = hashlib.sha1(content).hexdigest()
        hashes["Hash_sha251"]  = hashlib.sha256(content).hexdigest()
        hashes["Hash_sha512"]  = hashlib.sha512(content).hexdigest()
        return hashes

    def PE_arch(self):
        arch_dic = {
            "0x0200": "Itanium",
            "0x14c": "x86", 
            "0x8664": "x64"
        }
        if self.pe.FILE_HEADER.Machine:
            return arch_dic.get(str(hex(self.pe.FILE_HEADER.Machine)))
        else: 
            return "unknow architecture"

    def PE_check_antiVM(self):
        check  = []
        VM_STRINGS  = {
            "Virtual Box":"VBox",
            "VMware":"WMvare"
        }
        Anti_VM_Sign = {
            "Red Pill":"\x0f\x01\x0d\x00\x00\x00\x00\xc3",
            "VirtualPc trick":"\x0f\x3f\x07\x0b",
            "VMware trick":"VMXh",
            "VMCheck.dll":"\x45\xC7\x00\x01",
            "VMCheck.dll for VirtualPC":"\x0f\x3f\x07\x0b\xc7\x45\xfc\xff\xff\xff\xff",
            "Xen":"XenVMM",
            "Bochs & QEmu CPUID Trick":"\x44\x4d\x41\x63",
            "Torpig VMM Trick": "\xE8\xED\xFF\xFF\xFF\x25\x00\x00\x00\xFF\x33\xC9\x3D\x00\x00\x00\x80\x0F\x95\xC1\x8B\xC1\xC3",
            "Torpig (UPX) VMM Trick": "\x51\x51\x0F\x01\x27\x00\xC1\xFB\xB5\xD5\x35\x02\xE2\xC3\xD1\x66\x25\x32\xBD\x83\x7F\xB7\x4E\x3D\x06\x80\x0F\x95\xC1\x8B\xC1\xC3"
        }
        with open(self.filepath, "rb") as f:
            buf = f.read()
            for string in VM_STRINGS:
                match = re.findall(VM_STRINGS[string], buf, re.IGNORECASE | re.MULTILINE)
                if match:
                    check.append(string)
            for trick in Anti_VM_Sign:
                if buf.find(Anti_VM_Sign[trick][::-1]) > -1:
                    check.append(trick)

        if check:
            return True
        else:
            return False

    def PE_sections(self): 
        R_sections_rows = []
        for section in self.pe.sections:
            section_item = {
                'name': section.Name.strip('\x00'),
                'address': hex(section.VirtualAddress),
                'virtual_size': hex(section.Misc_VirtualSize),
                'size': section.SizeOfRawData,
                'entropy': section.get_entropy(),
            }
            R_sections_rows.append(section_item)
        return R_sections_rows

    def PE_entrypoint(self): 
        return hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)

    def PE_imagebase(self): 
        return hex(self.pe.OPTIONAL_HEADER.ImageBase)

    def PE_enty_import(self): 
        imports = []
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry_import in self.pe.DIRECTORY_ENTRY_IMPORT:
                imp = {
                    'ENTRY NAME': entry_import.dll, 
                    'SYMBOLS': []
                } 
                for symbol in entry_import.imports:
                    if symbol.name:
                        imp['SYMBOLS'].append(symbol.name)  
            imports.append(imp)
        return imports

    def PE_entry_export(self):
        exports = []
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exported_symbol in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                exports.append({
                    'address': hex(self.self.pe.OPTIONAL_HEADER.ImageBase + exported_symbol.address),
                    'name': exported_symbol.name,
                    'ordinal': exported_symbol.ordinal
                })
        return json.dumps(exports)

    def PE_os(self): 
        return "{}.{}".format(
            self.pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            self.pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,)

    def  PE_security(self): 
        features = []
        _features = {} 
        if 	self.pe.OPTIONAL_HEADER.DllCharacteristics > 0x0:
            if 	self.pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040: features.append('ASLR')
            if 	self.pe.OPTIONAL_HEADER.DllCharacteristics & 0x0100: features.append('DEP')
            if (self.pe.OPTIONAL_HEADER.DllCharacteristics & 0x0400 or
                    (hasattr(self.pe, "DIRECTORY_ENTRY_LOAD_CONFIG") and
                        self.pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SEHandlerCount > 0 and
                        self.pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SEHandlerTable != 0) or
                        self.pe.FILE_HEADER.Machine == 0x8664): 
                            features.append('SEH')
            _features = {
                "security" : ' ,'.join(features),
            }
            return features
            
    def PE_time(self): 
        r = self.pe.FILE_HEADER.TimeDateStamp
        timestamp_fmt = datetime.utcfromtimestamp(int(r)).strftime('%Y-%m-%d %H:%M:%S')
        return timestamp_fmt
