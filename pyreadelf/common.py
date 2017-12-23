import codecs
from enum import Enum

##
## common utilties
##
def bin_to_ascii(s):
    x =""
    for i in s:
        x += hex(ord(i))[2:4]
    return x

def bytearray_to_int(s):
    i = int(codecs.encode(s, 'hex'), 16)
    return i

def bytearray_to_str(s):
    pass # TODO

def lo_nibble(b):
    return b%16

def hi_nibble(b):
    return b/16

def get_str(buf,offset):
    end = offset
    while (buf[end] != chr(0)):
        end = end + 1
    return buf[offset:end]

##
##
##
def unpack_str_table(data):
    ret = []
    st = ""
    for i in data:
        if (i != chr(0)):
            st = st + i
        else:
            ret.append(st)
            st = ""
    return ret;

def append_attr(obj,attr_map):
    for key in attr_map:
            setattr(obj, key, attr_map[key])

def segment_bin(bin_data, size_map, offset=0, endiance='lsb'):
    ret = {}
    for key in size_map:
        start = offset
        end = offset+size_map[key]
        x = bin_data[start:end]
        if (endiance == 'lsb'): ## if lsb, reverse the bytearray
            x = x[::-1]
        offset = end
        ret[key] = x
    return ret;
