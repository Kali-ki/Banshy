import pefile
import os
import logging

# Configuration du logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def analyze_pe(pe_path):
    try:
        pe = pefile.PE(pe_path)
        
        # Afficher les informations de base sur le fichier PE
        logger.info("Nombre de sections: %d", pe.FILE_HEADER.NumberOfSections)
        logger.info("Point d'entrée: %s", hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))

        # Liste des noms de DLLs et de fonctions suspectes
        suspicious_dlls = ["malware", "trojan", "virus"]
        suspicious_functions = ["evil_function", "backdoor", "spyware"]

        # Analyse des imports
        logger.info("Imports:")
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode().lower()
            for imp in entry.imports:
                func_name = imp.name.decode().lower()
                logger.info(f"\t{dll_name}: {func_name}")

                # Vérification de la présence de noms de DLLs ou de fonctions suspects
                if any(suspicious_dll in dll_name for suspicious_dll in suspicious_dlls) or \
                   any(suspicious_function in func_name for suspicious_function in suspicious_functions):
                    logger.info("Élément suspect détecté!")
                    return False

        return True

    except Exception as e:
        logger.error(f"Erreur lors de l'analyse du fichier PE : {e}")
        return False

def main():
    pe_path = input("Entrez le chemin du fichier PE à analyser : ")
    if os.path.isfile(pe_path) and pe_path.lower().endswith(".exe"):
        # Analyser le fichier PE
        if analyze_pe(pe_path):
            logger.info("Le fichier PE semble sain.")
        else:
            logger.info("Le fichier PE est suspect.")
    else:
        logger.error("Le chemin spécifié n'est pas valide ou ne pointe pas vers un fichier PE.")

if __name__ == "__main__":
    main()



# import pefile
# import os
# import logging
# import magic
# import json
# import pefile
# import pyexifinfo
# import hashlib
# import re
# import time
# from datetime import datetime
# #from pestatmal import PEstatMal

# class PEstatmal():

#     def __init__(self, file_name):
#         self.filepath = file_name
#         self.pe = pefile.PE(self.filepath)
#         if not self.pe:
#             raise pefile.PEFormatError('__EmptyFile__')
    
#     def run(self): 
#         results = {}

#         results = {
#             'ImpHash': self.PE_imphash(),
#             #'Hashes': self.PE_hash(),
#             'Anti_VM': self.PE_check_antiVM(self.filepath),
#             'Type': self.PE_type(),
#             'os': self.PE_os(),
#             'importHash': self.PE_imphash(),
#             'Entry Point': self.PE_entrypoint(),
#             'Sections': self.PE_sections(),
#             'Security': self.PE_security(),
#             'Entry Imports': self.PE_enty_import(),
#             'Entry Exports':  self.PE_entry_export()
#         }

#         return results
    
#     def PE_imphash(self):
#         imp_hash = self.pe.get_imphash()
#         return imp_hash 
    
#     def PE_type(self):
#         if self.pe.is_dll(): rtype = 'DLL'
#         if self.pe.is_driver(): rtype = 'DRIVER'
#         if self.pe.is_exe(): rtype = 'EXE'
#         return rtype

#     def PE_hash(self):
#         hashes = {}
#         content = open(self.filepath, 'r').read()  
#         hashes["Hash_md5"]  = hashlib.md5(content).hexdigest()
#         hashes["Hash_sha1"]  = hashlib.sha1(content).hexdigest()
#         hashes["Hash_sha251"]  = hashlib.sha256(content).hexdigest()
#         hashes["Hash_sha512"]  = hashlib.sha512(content).hexdigest()
#         return hashes

#     def PE_check_antiVM(self):
#         check  = []
#         VM_STRINGS  = {
#             "Virtual Box":"VBox",
#             "VMware":"WMvare"
#         }
#         Anti_VM_Sign = {
#             "Red Pill":"\x0f\x01\x0d\x00\x00\x00\x00\xc3",
#             "VirtualPc trick":"\x0f\x3f\x07\x0b",
#             "VMware trick":"VMXh",
#             "VMCheck.dll":"\x45\xC7\x00\x01",
#             "VMCheck.dll for VirtualPC":"\x0f\x3f\x07\x0b\xc7\x45\xfc\xff\xff\xff\xff",
#             "Xen":"XenVMM",
#             "Bochs & QEmu CPUID Trick":"\x44\x4d\x41\x63",
#             "Torpig VMM Trick": "\xE8\xED\xFF\xFF\xFF\x25\x00\x00\x00\xFF\x33\xC9\x3D\x00\x00\x00\x80\x0F\x95\xC1\x8B\xC1\xC3",
#             "Torpig (UPX) VMM Trick": "\x51\x51\x0F\x01\x27\x00\xC1\xFB\xB5\xD5\x35\x02\xE2\xC3\xD1\x66\x25\x32\xBD\x83\x7F\xB7\x4E\x3D\x06\x80\x0F\x95\xC1\x8B\xC1\xC3"
#         }
#         with open(self.filepath, "rb") as f:
#             buf = f.read()
#             for string in VM_STRINGS:
#                 match = re.findall(VM_STRINGS[string], buf, re.IGNORECASE | re.MULTILINE)
#                 if match:
#                     check.append(string)
#             for trick in Anti_VM_Sign:
#                 if buf.find(Anti_VM_Sign[trick][::-1]) > -1:
#                     check.append(trick)

#         if check:
#             return True
#         else:
#             return False

#     def PE_sections(self): 
#         R_sections_rows = []
#         for section in self.pe.sections:
#             section_item = {
#                 'name': section.Name.strip('\x00'),
#                 'address': hex(section.VirtualAddress),
#                 'virtual_size': hex(section.Misc_VirtualSize),
#                 'size': section.SizeOfRawData,
#                 'entropy': section.get_entropy(),
#             }
#             R_sections_rows.append(section_item)
#         return R_sections_rows

#     def PE_entrypoint(self): 
#         return hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)

#     def PE_enty_import(self): 
#         imports = []
#         if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
#             for entry_import in self.pe.DIRECTORY_ENTRY_IMPORT:
#                 imp = {
#                     'ENTRY NAME': entry_import.dll, 
#                     'SYMBOLS': []
#                 } 
#                 for symbol in entry_import.imports:
#                     if symbol.name:
#                         imp['SYMBOLS'].append(symbol.name)  
#             imports.append(imp)
#         return imports

#     def PE_entry_export(self):
#         exports = []
#         if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
#             for exported_symbol in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
#                 exports.append({
#                     'address': hex(self.self.pe.OPTIONAL_HEADER.ImageBase + exported_symbol.address),
#                     'name': exported_symbol.name,
#                     'ordinal': exported_symbol.ordinal
#                 })
#         return json.dumps(exports)

#     def PE_os(self): 
#         return "{}.{}".format(
#             self.pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
#             self.pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,)

#     def  PE_security(self): 
#         features = []
#         _features = {} 
#         if 	self.pe.OPTIONAL_HEADER.DllCharacteristics > 0x0:
#             if 	self.pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040: features.append('ASLR')
#             if 	self.pe.OPTIONAL_HEADER.DllCharacteristics & 0x0100: features.append('DEP')
#             if (self.pe.OPTIONAL_HEADER.DllCharacteristics & 0x0400 or
#                     (hasattr(self.pe, "DIRECTORY_ENTRY_LOAD_CONFIG") and
#                         self.pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SEHandlerCount > 0 and
#                         self.pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SEHandlerTable != 0) or
#                         self.pe.FILE_HEADER.Machine == 0x8664): 
#                             features.append('SEH')
#             _features = {
#                 "security" : ' ,'.join(features),
#             }
#             return features
        


# # Configuration du logger
# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger(__name__)

# def analyze_pe(pe_path):
#     try:

#         s = PEstatmal(pe_path)

#         pe = pefile.PE(pe_path)

#         resultats = s.run()

#         if resultats['Anti_VM'] or resultats['ImpHash'] == '0000000000000000':
#             return False
#         else:
#             return True

#         # Analyse du fichier PE
#         #pestatmal = PEstatmal(pe_path)

#         # Affichage des résultats
#         # logger.info("Score de malveillance : %.2f", pestatmal.malware_score)
#         # logger.info("Classe de malveillance : %s", pestatmal.malware_class)
#         # logger.info("Famille de malwares : %s", pestatmal.malware_family)
        
#         # # Vérification du score de malveillance
#         # if pestatmal.malware_score > 0.5:
#         #     logger.info("Le fichier PE est suspect.")
#         #     return False
#         # else:
#         #     logger.info("Le fichier PE semble sain.")
#         #     return True

#     except Exception as e:
#         logger.error(f"Erreur lors de l'analyse du fichier PE : {e}")
#         return False

# def main():
#     pe_path = input("Entrez le chemin du fichier PE à analyser : ")
#     if os.path.isfile(pe_path) and pe_path.lower().endswith(".exe"):
#         # Analyser le fichier PE
#         analyze_pe(pe_path)
#     else:
#         logger.error("Le chemin spécifié n'est pas valide ou ne pointe pas vers un fichier PE.")

# if __name__ == "__main__":
#     main()
