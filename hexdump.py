from idc import *
import sys
from mylib import *
import ctypes
from re import compile as re_compile
import idaapi
GET_ADDR_RE = re_compile("0x(.)*")

def makeCType(sz):
    if sz == 1:
        return ctypes.c_ubyte
    elif sz == 2:
        return ctypes.c_ushort
    elif sz == 4:
        return ctypes.c_uint
    elif sz == 8:
        return ctypes.c_uint64
    assert False
    return None

def getSwigPtr(obj):
    if hasattr(obj, "this"):
        return int(obj.this)
    elif type(obj).__name__ =='SwigPyObject':
        return int(obj)
    else:
        assert False, "Bad operand for getSwigPtr"

class mblField(object):
    def __init__(self, size, name, offset):
        self.name = name
        self.size = size
        self.offset = offset
    
    def __str__(self):
        return "mblField {}: offset {} with size {}".format(self.name, self.offset, self.size)

def isBadAddrData(data):
    return data == long(0xFFFFFFFF)


class mblArray(object):
    SIZE_OF = 684
    def __init__(self, addr):
        self.addr = addr
        self.voidp = ctypes.c_void_p(self.addr)
        self.badaddrfields = []
        self.fields = []
  
    def getAt(self, offs, sz):
        return ctypes.cast(ctypes.c_void_p(self.addr + offs), ctypes.POINTER( makeCType(sz) ))[0]
    
    def forAllAs(self, sz, func):
        for i in range(0, mblArray.SIZE_OF / sz):
            func(self, self.getAt(i*sz, sz), i)    

    
    def classifyFields(self):
        def isBadAddrField(self, data, i):
            if isBadAddrData(data):
                self.fields.append(mblField(4, "EAField{}".format(i), i*4))
        
        self.forAllAs(4, isBadAddrField)
        
        def isProbableQVectorSubstruct(self, data, i):
            xlat = i*4
            if not isBadAddrData(data) and data != 0 and xlat + 8 <= mblArray.SIZE_OF:
                after1 = self.getAt(xlat + 4, 4)
                after2 = self.getAt(xlat + 8, 4)
                if not isBadAddrData(after1) and not isBadAddrData(after2) and after1 != 0 and after1 == after2:
                    self.fields.append(mblField(12, "Qvector{}".format(i), xlat))
        
        self.forAllAs(4, isProbableQVectorSubstruct)
        for f in self.fields:
            print f
        
                
    
        

def hexcb(event, *args):
    #if event != 2:
    #    return 0
    if event != idaapi.hxe_maturity:
        return 0
    
    cfunc = args[0]
    
    mba = cfunc.mba
    
    print type(mba)
    mbaObject = mblArray(getSwigPtr(mba))
    mbaObject.classifyFields()
    return 0

#hx_cblist_callback
#install_hexrays_callback
class hexhelper(idaapi.plugin_t):

    flags = idaapi.PLUGIN_UNL
    comment = ""
    help = ""
    wanted_name = "Hexrays Inspector"
    wanted_hotkey = ""

    def init(self):  
        initDecompiler()
        idaapi.install_hexrays_callback(hexcb)
        
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        return

    def term(self):
        pass


def PLUGIN_ENTRY():
    return hexhelper()
