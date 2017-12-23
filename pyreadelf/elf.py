from enum import Enum
import collections


import common

##################################
## Constants
##################################
class BIT64_DATA_TYPE(Enum):
    Elf64_Addr      = 8
    Elf64_Off       = 8
    Elf64_Half      = 2
    Elf64_Word      = 4
    Elf64_Sword     = 4
    Elf64_Xword     = 8
    Elf64_Sxword    = 8
    Elf64_Char      = 1

class BIT32_DATA_TYPE(Enum):
    Elf32_Addr      = 4
    Elf32_Half      = 2
    Elf32_Off       = 4
    Elf32_Sword     = 4
    Elf32_Word      = 4
    Elf32_Char      = 1

class E_TYPE(Enum):
    ET_NONE     = 0
    ET_REL      = 1
    ET_EXEC     = 2
    ET_DYN      = 3
    ET_CORE     = 4
    ET_LOOS     = 0xfe00
    ET_HIOS     = 0xfeff
    ET_LOPROC   = 0xff00
    ET_HIPROC   = 0xffff

class E_MACHINE(Enum):  # TODO: x86 and x86-64 for now
    EM_NONE     = 0
    EM_386      = 3
    EM_X86_64   = 62

class E_VERSION(Enum):
    EV_NONE     = 0
    EV_CURRENT  = 1


## Ident constants
class EI_CLASS(Enum):
    ELFCLASSNONE    = 0
    ELFCLASS32      = 1
    ELFCLASS64      = 2

class EI_DATA(Enum):
    ELFDATANONE = 0
    ELFDATA2LSB = 1
    ELFDATA2MSB = 2

class EI_VERSION(Enum):
    EV_NONE     = 0
    EV_CURRENT  = 1

class EI_OSABI(Enum): # TODO: check what that for?! and complete them (maybe)?!
    ELFOSABI_SYSV           = 0
    ELFOSABI_HPUX           = 1
    ELFOSABI_STANDALONE     = 255

##
##
##
class BinResource(object):
    def __init__(self):
        pass


class Ident(BinResource):
    ELFMAGIC = "\x7f\x45\x4c\x46"  # "0x7fELF"  
    def __init__(self, data):        
        data_dict = common.segment_bin(data,self.size_map(),0,'lsb')
        ## TODO: check ELF magic
        common.append_attr(self,data_dict)
    def size_map(self):
        attr_size_map = collections.OrderedDict()
        attr_size_map["EI_MAG0"]               = 1
        attr_size_map["EI_MAG1"]               = 1
        attr_size_map["EI_MAG2"]               = 1
        attr_size_map["EI_MAG3"]               = 1
        attr_size_map["EI_CLASS"]              = 1
        attr_size_map["EI_DATA"]               = 1
        attr_size_map["EI_VERSION"]            = 1
        attr_size_map["EI_OSABI"]              = 1
        attr_size_map["EI_ABIVERSION"]         = 1
        attr_size_map["EI_PAD"]                = 7
        return attr_size_map
        
class Elf32Hdr(BinResource):
    def __init__(self):
        pass
    def size_map(self):
        attr_size_map = collections.OrderedDict()
        attr_size_map["e_ident"       ] =  BIT32_DATA_TYPE.Elf32_Char.value * 16
        attr_size_map["e_type"        ] =  BIT32_DATA_TYPE.Elf32_Half.value
        attr_size_map["e_machine"     ] =  BIT32_DATA_TYPE.Elf32_Half.value
        attr_size_map["e_version"     ] =  BIT32_DATA_TYPE.Elf32_Word.value
        attr_size_map["e_entry"       ] =  BIT32_DATA_TYPE.Elf32_Addr.value
        attr_size_map["e_phoff"       ] =  BIT32_DATA_TYPE.Elf32_Off.value
        attr_size_map["e_shoff"       ] =  BIT32_DATA_TYPE.Elf32_Off.value
        attr_size_map["e_flags"       ] =  BIT32_DATA_TYPE.Elf32_Word.value
        attr_size_map["e_ehsize"      ] =  BIT32_DATA_TYPE.Elf32_Half.value
        attr_size_map["e_phentsize"   ] =  BIT32_DATA_TYPE.Elf32_Half.value
        attr_size_map["e_phnum"       ] =  BIT32_DATA_TYPE.Elf32_Half.value
        attr_size_map["e_shentsize"   ] =  BIT32_DATA_TYPE.Elf32_Half.value
        attr_size_map["e_shnum"       ] =  BIT32_DATA_TYPE.Elf32_Half.value
        attr_size_map["e_shstrndx"    ] =  BIT32_DATA_TYPE.Elf32_Half.value
        return attr_size_map

class Elf64Hdr(BinResource):
    def __init__(self):
        pass
    def size_map(self):
        attr_size_map = collections.OrderedDict()
        attr_size_map["e_ident"       ] =  BIT64_DATA_TYPE.Elf64_Char.value * 16
        attr_size_map["e_type"        ] =  BIT64_DATA_TYPE.Elf64_Half.value
        attr_size_map["e_machine"     ] =  BIT64_DATA_TYPE.Elf64_Half.value
        attr_size_map["e_version"     ] =  BIT64_DATA_TYPE.Elf64_Word.value
        attr_size_map["e_entry"       ] =  BIT64_DATA_TYPE.Elf64_Addr.value
        attr_size_map["e_phoff"       ] =  BIT64_DATA_TYPE.Elf64_Off.value
        attr_size_map["e_shoff"       ] =  BIT64_DATA_TYPE.Elf64_Off.value
        attr_size_map["e_flags"       ] =  BIT64_DATA_TYPE.Elf64_Word.value
        attr_size_map["e_ehsize"      ] =  BIT64_DATA_TYPE.Elf64_Half.value
        attr_size_map["e_phentsize"   ] =  BIT64_DATA_TYPE.Elf64_Half.value
        attr_size_map["e_phnum"       ] =  BIT64_DATA_TYPE.Elf64_Half.value
        attr_size_map["e_shentsize"   ] =  BIT64_DATA_TYPE.Elf64_Half.value
        attr_size_map["e_shnum"       ] =  BIT64_DATA_TYPE.Elf64_Half.value
        attr_size_map["e_shstrndx"    ] =  BIT64_DATA_TYPE.Elf64_Half.value
        return attr_size_map


class Elf64Shdr(BinResource):
    def __init__(self,data):
        data_dict =  common.segment_bin(data,self.size_map() ,0,'lsb')
        common.append_attr(self,data_dict)
    def size_map(self):
        attr_size_map = collections.OrderedDict()
        attr_size_map["sh_name"      ]  =  BIT64_DATA_TYPE.Elf64_Word.value
        attr_size_map["sh_type"      ]  =  BIT64_DATA_TYPE.Elf64_Word.value
        attr_size_map["sh_flags"     ]  =  BIT64_DATA_TYPE.Elf64_Xword.value
        attr_size_map["sh_addr"      ]  =  BIT64_DATA_TYPE.Elf64_Addr.value
        attr_size_map["sh_offset"    ]  =  BIT64_DATA_TYPE.Elf64_Off.value
        attr_size_map["sh_size"      ]  =  BIT64_DATA_TYPE.Elf64_Xword.value
        attr_size_map["sh_link"      ]  =  BIT64_DATA_TYPE.Elf64_Word.value
        attr_size_map["sh_info"      ]  =  BIT64_DATA_TYPE.Elf64_Word.value
        attr_size_map["sh_addalign"  ]  =  BIT64_DATA_TYPE.Elf64_Xword.value
        attr_size_map["sh_entsize"   ]  =  BIT64_DATA_TYPE.Elf64_Xword.value
        return attr_size_map

class Elf64Phdr(BinResource):
    def __init__(self,data):
        data_dict =  common.segment_bin(data,self.size_map() ,0,'lsb')
        common.append_attr(self,data_dict)
    def size_map(self):
        attr_size_map = collections.OrderedDict()
        attr_size_map["p_type"       ]  =  BIT64_DATA_TYPE.Elf64_Word.value
        attr_size_map["p_flags"      ]  =  BIT64_DATA_TYPE.Elf64_Word.value
        attr_size_map["p_offset"     ]  =  BIT64_DATA_TYPE.Elf64_Off.value
        attr_size_map["p_vaddr"      ]  =  BIT64_DATA_TYPE.Elf64_Addr.value
        attr_size_map["p_paddr"      ]  =  BIT64_DATA_TYPE.Elf64_Addr.value
        attr_size_map["p_filez"      ]  =  BIT64_DATA_TYPE.Elf64_Xword.value
        attr_size_map["p_memsz"      ]  =  BIT64_DATA_TYPE.Elf64_Xword.value
        attr_size_map["p_align"      ]  =  BIT64_DATA_TYPE.Elf64_Xword.value
        return attr_size_map

class Elf64Sym(BinResource):
    def __init__(self,data):
        data_dict =  common.segment_bin(data,self.size_map() ,0,'lsb')
        common.append_attr(self,data_dict)
    def size_map(self):
        attr_size_map = collections.OrderedDict()
        attr_size_map["st_name"       ]  =  BIT64_DATA_TYPE.Elf64_Word.value
        attr_size_map["st_info"       ]  =  BIT64_DATA_TYPE.Elf64_Char.value
        attr_size_map["st_other"      ]  =  BIT64_DATA_TYPE.Elf64_Char.value
        attr_size_map["st_shndx"      ]  =  BIT64_DATA_TYPE.Elf64_Half.value
        attr_size_map["st_value"      ]  =  BIT64_DATA_TYPE.Elf64_Addr.value
        attr_size_map["st_size"       ]  =  BIT64_DATA_TYPE.Elf64_Xword.value
        return attr_size_map
        
class ElfHdr(BinResource):
    def __init__(self,data):
        self.ident = Ident(data[0:16])
        if EI_CLASS.ELFCLASS64.value == common.bytearray_to_int(self.ident.EI_CLASS):
            tmp = Elf64Hdr()
        elif  EI_CLASS.ELFCLASS32.value == common.bytearray_to_int(self.ident.EI_CLASS):
            tmp = Elf32Hdr()
        else:
            print "Error: Undefined ident.EI_CLASS"
        data_dict =  common.segment_bin(data,tmp.size_map() ,0,'lsb')
        common.append_attr(self,data_dict)

##TODO: read lsb/msb from Ident
class ElfParser:
    def __init__(self,file_name):
        self.file_name = file_name
        with open(file_name, mode='rb') as file:
            self.file_bin = file.read()
        self.ehdr = ElfHdr(self.file_bin)
        ##  parse section table if applicable
        self.sh_tbl = []
        if(common.bytearray_to_int(self.ehdr.e_shnum) > 0):
            start = common.bytearray_to_int(self.ehdr.e_shoff)
            for x in range(0, common.bytearray_to_int(self.ehdr.e_shnum)):
                end = start + common.bytearray_to_int(self.ehdr.e_shentsize)
                sh = Elf64Shdr(self.file_bin[start:end])
                start = end
                self.sh_tbl.append(sh)

        ## parse e_shstrndx and back annotate the sh headers (sh_tbl)
        sym_sh = self.sh_tbl[common.bytearray_to_int(self.ehdr.e_shstrndx)]
        start = common.bytearray_to_int(sym_sh.sh_addr) + common.bytearray_to_int(sym_sh.sh_offset)
        end   = common.bytearray_to_int(sym_sh.sh_addr) + common.bytearray_to_int(sym_sh.sh_offset) +common.bytearray_to_int(sym_sh.sh_size) 
        strtab = common.unpack_str_table(self.file_bin[start:end])
        for sh,nm in zip(self.sh_tbl,strtab):
            sh.real_name = nm

        ## parse program table if applicable
        self.ph_tbl = []
        if(common.bytearray_to_int(self.ehdr.e_phnum) > 0):  
            start = common.bytearray_to_int(self.ehdr.e_phoff)
            for x in range(0, common.bytearray_to_int(self.ehdr.e_phnum)):
                end = start + common.bytearray_to_int(self.ehdr.e_phentsize)
                ph = Elf64Phdr(self.file_bin[start:end])
                start = end
                self.ph_tbl.append(ph)
                

