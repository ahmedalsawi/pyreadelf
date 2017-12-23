from enum import Enum

from common import *



class ShT_Types(Enum):
    SHT_NULL        = 0
    SHT_PROGBITS    = 1
    SHT_SYMTAB      = 2
    SHT_STRTAB      = 3
    SHT_RELA        = 4
    SHT_HASH        = 5
    SHT_DYNAMIC     = 6
    SHT_NOTE        = 7
    SHT_NOBITS      = 8
    SHT_REL         = 9
    SHT_SHLIB       =10
    SHT_DYNSYM      =11
    SHT_LOOS        =0x60000000
    SHT_HIOS        =0x6fffffff
    SHT_LOPROC      =0x70000000
    SHT_HIPROC      =0x7fffffff
    SHT_GNU_INCREMENTAL_INPUTS  = 0x6fff4700
    SHT_GNU_ATTRIBUTES          = 0x6ffffff5
    SHT_GNU_HASH                = 0x6ffffff6
    SHT_GNU_LIBLIST             = 0x6ffffff7
    ## i had to add those to parse gnu non-std sections.full list at readelf/include/elf/common.h
    SHT_INIT_ARRAY      = 14
    SHT_FINI_ARRAY      = 15
    SHT_PREINIT_ARRAY   = 16
    SHT_GROUP           = 17
    SHT_SYMTAB_SHNDX    = 18
    SHT_GNU_verdef      = 0x6ffffffd
    SHT_GNU_verneed     = 0x6ffffffe
    SHT_GNU_versym      = 0x6fffffff
class ShT_Attributes(Enum):
    SHF_WRITE       = 0x01
    SHF_ALLOC       = 0x02
    SHF_EXECINSTR   = 0x04
    SHF_MASKOS      = 0x0f000000
    SHF_MASKPROC    = 0xf0000000

# FIXME: is this needed?!
class SH_IDX(Enum):
    SHN_UNDEF   = 0
    SHN_LOPROC  = 0xff00
    SHN_HIPROC  = 0xff1f
    SHN_LOOS    = 0xff20
    SHN_HIOS    = 0xff3f
    SHN_ABS     = 0xfff1
    SHN_COMMON  = 0xfff2
class SYM_BIND(Enum):
    STB_LOCAL   = 0
    STB_GLOBAL  = 1
    STB_WEAK    = 2
    STB_LOOS    = 10
    STB_HIOS    = 12
    STB_LOPROC  = 13
    STB_HIPORC  = 15
class SYM_TYPES(Enum):
    STI_NOTYPE  = 0
    STI_OBJECT  = 1
    STI_FUNC    = 2
    STI_SECTION = 3
    STI_FILE    = 4
    STI_LOOS    = 10
    STI_HIOS    = 12
    STI_LOPROC  = 13
    STI_HIPROC  = 14

class SEGMENT_TYPES(Enum):
    PT_NULL         = 0
    PT_LOAD         = 1
    PT_DYNAMIC      = 2
    PT_INTERP       = 3
    PT_NOTE         = 4
    PT_SHLIB        = 5
    PT_PHDR         = 6
    PT_LOOS         = 0x60000000
    PT_HIOS         = 0x6fffffff
    PT_LOPROC       = 0x70000000
    PT_HIPORC       = 0x7fffffff
    PT_GNU_EH_FRAME  = (PT_LOOS + 0x474e550)
    PT_SUNW_EH_FRAME = PT_GNU_EH_FRAME
    PT_GNU_STACK     = (PT_LOOS + 0x474e551)
    PT_GNU_RELRO     = (PT_LOOS + 0x474e552)
class SEMENT_ATTRIBUTES(Enum):
    PF_X        = 0x1
    PF_W        = 0x2
    PF_R        = 0x4
    PF_MASKOS   = 0x00ff0000
    PF_MASKPROC = 0xff000000

class elfHdr:
    def __init__(self,FileContent):
        offset = 0
        self.e_ident    = FileContent[offset:16] # TODO parse ident
        offset = offset  + 16
        self.e_type     = HDR_TYPE(bytearray_to_int_lsb( FileContent[offset:offset+2]))
        offset = offset  + 2
        self.e_machine  = HDR_MACHINE(bytearray_to_int_lsb( FileContent[offset:offset+2]))
        offset = offset  + 2
        self.e_version  = EI_VERSION(bytearray_to_int_lsb( FileContent[offset:offset+4]))
        offset = offset  + 4
        # FIXME This is 64 width.. should know the type from EI_CLASS in e_ident
        # FIXME i assumed that i am using LSB.
        self.e_entry = bytearray_to_int_lsb( FileContent[offset:offset+8])
        offset = offset  + 8
        self.e_phoff = bytearray_to_int_lsb( FileContent[offset:offset+8])
        offset = offset  + 8
        self.e_shoff = bytearray_to_int_lsb( FileContent[offset:offset+8])
        offset = offset  + 8
        self.e_flags =  bytearray_to_int_lsb( FileContent[offset:offset+4])
        offset = offset  + 4
        self.e_ehsize =  bytearray_to_int_lsb( FileContent[offset:offset+2])
        offset = offset  + 2
        self.e_phentsize =  bytearray_to_int_lsb( FileContent[offset:offset+2])
        offset = offset  + 2
        self.e_phnum =  bytearray_to_int_lsb( FileContent[offset:offset+2])
        offset = offset  + 2
        self.e_shentsize =  bytearray_to_int_lsb( FileContent[offset:offset+2])
        offset = offset  + 2
        self.e_shnum =  bytearray_to_int_lsb( FileContent[offset:offset+2])
        offset = offset  + 2
        self.e_shstrndx =  bytearray_to_int_lsb( FileContent[offset:offset+2])
        offset = offset  + 2
    def dump(self):
        print self.e_type
        print self.e_machine
        print self.e_version
        print hex(self.e_entry)
        print hex(self.e_flags)
        print self.e_ehsize
        print self.e_phentsize
        print self.e_phnum
        print self.e_shentsize
        print self.e_shnum 
        print self.e_shstrndx 
        pass

class elfShTHdr:
    int_name    = ""
    relEnt      = []
    def __init__(self,shHdr):
        # FIXME This is 64 width.. should know the type from EI_CLASS in e_ident
        offset = 0
        self.sh_name = bytearray_to_int_lsb(shHdr[offset:offset+4])
        offset = offset  + 4
        self.sh_type = ShT_Types(bytearray_to_int_lsb(shHdr[offset:offset+4]))
        offset = offset  + 4
        self.sh_flags = bytearray_to_int_lsb(shHdr[offset:offset+8])
        offset = offset  + 8
        self.sh_addr = bytearray_to_int_lsb(shHdr[offset:offset+8])
        offset = offset  + 8
        self.sh_offset = bytearray_to_int_lsb(shHdr[offset:offset+8])
        offset = offset  + 8
        self.sh_size = bytearray_to_int_lsb(shHdr[offset:offset+8])
        offset = offset  + 8
        self.sh_link = bytearray_to_int_lsb(shHdr[offset:offset+4])
        offset = offset  + 4
        self.sh_info = bytearray_to_int_lsb(shHdr[offset:offset+4])
        offset = offset  + 4
        self.sh_addalign = bytearray_to_int_lsb(shHdr[offset:offset+8])
        offset = offset  + 8
        self.sh_entsize = bytearray_to_int_lsb(shHdr[offset:offset+8])
        offset = offset  + 8  
    def dump(self):
        print self.int_name
        print self.sh_type
        print self.sh_flags
        print hex(self.sh_addr)
        print hex(self.sh_offset)
        print hex(self.sh_size)
        print self.sh_link
        print self.sh_addalign
        print hex(self.sh_entsize)
        pass



class elf_Sym:
    int_name    = ""
    int_binding = 0
    int_type    = 0
    def __init__(self,symtab):
        offset = 0
        self.st_name = bytearray_to_int_lsb(symtab[offset:offset+4])
        offset = offset  + 4
        self.st_info = bytearray_to_int_lsb(symtab[offset:offset+1])
        offset = offset  + 1
        self.st_other = bytearray_to_int_lsb(symtab[offset:offset+1])
        offset = offset  + 1
        self.st_shndx = bytearray_to_int_lsb(symtab[offset:offset+2]) # TODO: use enum here. but i can't find the full list of possible values.
        offset = offset  + 2
        self.st_value = bytearray_to_int_lsb(symtab[offset:offset+8])
        offset = offset  + 8
        self.st_size = bytearray_to_int_lsb(symtab[offset:offset+8])
        offset = offset  + 8
        self.int_binding = SYM_BIND(hi_nibble(self.st_info))
        self.int_type    = SYM_TYPES(lo_nibble(self.st_info))
    def dump(self):
        print self.int_name
        print self.int_binding
        print self.int_type
        print self.st_other
        print self.st_shndx
        print hex(self.st_value)
        print self.st_size

class elf_Rel:
    def __init__(self,relTab):
        offset = 0
        self.r_offset   = bytearray_to_int_lsb(relTab[offset:offset+8])
        offset = offset  + 8
        self.r_info     = bytearray_to_int_lsb(relTab[offset:offset+8])
        offset = offset  + 8
    def dump(self):
        print hex(self.r_offset)
        print hex(self.r_info)

class elf_Rela:
    def __init__(self,relTab):
        offset = 0
        self.r_offset   = bytearray_to_int_lsb(relTab[offset:offset+8])
        offset = offset  + 8
        self.r_info     = bytearray_to_int_lsb(relTab[offset:offset+8])
        offset = offset  + 8
        self.r_addend   = bytearray_to_int_lsb(relTab[offset:offset+8])
        offset = offset  + 8
    def dump(self):
        print hex(self.r_offset)
        print hex(self.r_info)
        print hex(self.r_addend)


class elf_Phdr:
    def __init__(self,phdr):
        offset = 0
        self.p_type = SEGMENT_TYPES(bytearray_to_int_lsb(phdr[offset:offset+4]))
        offset = offset  + 4
        self.p_flags =  bytearray_to_int_lsb(phdr[offset:offset+4])
        offset = offset  + 4       
        self.p_offset = bytearray_to_int_lsb(phdr[offset:offset+8])
        offset = offset  + 8
        self.p_vaddr = bytearray_to_int_lsb(phdr[offset:offset+8])
        offset = offset  + 8
        self.p_paddr = bytearray_to_int_lsb(phdr[offset:offset+8])
        offset = offset  + 8
        self.p_filesz = bytearray_to_int_lsb(phdr[offset:offset+8])
        offset = offset  + 8
        self.p_memsz = bytearray_to_int_lsb(phdr[offset:offset+8])
        offset = offset  + 8
        self.p_align = bytearray_to_int_lsb(phdr[offset:offset+8])
        offset = offset  + 8
    def dump(self):
        print self.p_type
        print self.p_flags
        print hex(self.p_offset)
        print hex(self.p_vaddr)
        print hex(self.p_paddr)
        print hex(self.p_filesz)
        print hex(self.p_memsz)
        print hex(self.p_align)
class elf:
        fileName = ""
        fileContent = ""
        hdr     = 0
        sh      = []
        symTab  = []
        pHdr    = []
        def __init__(self,fileName):
            self.fileName = fileName
            with open(fileName, mode='rb') as file:
                self.fileContent = file.read()
            ## parse elf header
            self.hdr = elfHdr(self.fileContent)
            #self.hdr.dump()
            ## parse section headers
            for i in xrange(self.hdr.e_shnum):
                offset = self.hdr.e_shoff + (i*self.hdr.e_shentsize)
                self.sh.append(elfShTHdr(self.fileContent[offset:offset + self.hdr.e_shentsize]))
            for i in xrange(self.hdr.e_shnum):
                self.sh[i].int_name = get_str(self.fileContent,self.sh[self.hdr.e_shstrndx].sh_offset+self.sh[i].sh_name)
                #self.sh[i].dump()
            ## parse symbol tables
            symtab_sht      = 0
            symStrTab_sht   = 0
            for sec in self.sh:
                if sec.int_name == ".strtab": # TODO: i assumed there is only one .strtab
                    symStrTab_sht = sec
                if (sec.sh_type == ShT_Types.SHT_SYMTAB): # TODO: the specs says soo somewhere
                    symtab_sht =   sec
            if (symtab_sht != 0):
            # TODO: gcc doesn't generate SHT_SYMTAB but it did have DYNAMIC
                for i in xrange(symtab_sht.sh_size/symtab_sht.sh_entsize):
                    offset = symtab_sht.sh_offset + (i*symtab_sht.sh_entsize)
                    self.symTab.append(elf_Sym(self.fileContent[offset:offset+symtab_sht.sh_entsize]))
                    self.symTab[i].int_name=get_str(self.fileContent,symStrTab_sht.sh_offset+self.symTab[i].st_name)
                    #self.symTab[i].dump()
            ## parse program header(so and exec)
            for i in xrange(self.hdr.e_phnum):
                offset = self.hdr.e_phoff + (self.hdr.e_phentsize * i )
                self.pHdr.append(elf_Phdr(self.fileContent[offset : offset + self.hdr.e_phentsize]))
                #self.pHdr[i].dump()
            ## parse REL/RELA
            for i in xrange(self.hdr.e_shnum):
                # TODO: i added the next line because for some reason all sh's
                # in the list points to the same relEnt.
                self.sh[i].relEnt = [] 
                if (self.sh[i].sh_type == ShT_Types.SHT_RELA):
                    for e in xrange(self.sh[i].sh_size/self.sh[i].sh_entsize):
                        offset = self.sh[i].sh_offset + (e * self.sh[i].sh_entsize)
                        self.sh[i].relEnt.append(elf_Rela(self.fileContent[offset : offset + self.sh[i].sh_entsize]))
                if (self.sh[i].sh_type == ShT_Types.SHT_REL):
                     for e in xrange(self.sh[i].sh_size/self.sh[i].sh_entsize):
                         offset = self.sh[i].sh_offset + (e * self.sh[i].sh_entsize)
                         self.sh[i].relEnt.append(elf_Rel(self.fileContent[offset : offset + self.sh[i].sh_entsize]))
                         self.sh[i].relEnt[e].dump()
            ## TODO: parse .dynsym table
            dynsymtab_sht      = 0
            dynsymStrTab_sht   = 0
            for sec in self.sh:
                if sec.int_name == ".dynstr":
                    dynsymStrTab_sht = sec
                if (sec.sh_type == ShT_Types.SHT_DYNSYM):
                    dynsymtab_sht =   sec
            if (dynsymtab_sht != 0):
                for i in xrange(dynsymtab_sht.sh_size/dynsymtab_sht.sh_entsize):
                    offset = dynsymtab_sht.sh_offset + (i*dynsymtab_sht.sh_entsize)
                    self.symTab.append(elf_Sym(self.fileContent[offset:offset+dynsymtab_sht.sh_entsize]))
                    self.symTab[i].int_name=get_str(self.fileContent,dynsymStrTab_sht.sh_offset+self.symTab[i].st_name)
                    self.symTab[i].dump()
            ## TODO: parse Dynamic sections
            ## TODO: Hash table
