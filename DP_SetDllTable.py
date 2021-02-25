#Set Dino Planet DLL pointers in RAM.
#@author
#@category StarFox
#@keybinding
#@menupath
#@toolbar
from ghidra.program.model.listing import ParameterImpl
from ghidra.program.model.symbol import SourceType

TABLE_ADDR = 0x802525e8
ITEM_SIZE  = 0x14
FUNC_NAMES = {
    0x01: 'setup',
    0x02: 'control',
    0x03: 'print',
    0x04: 'update',
    0x05: 'free',
}

AF = currentProgram.getAddressFactory()
listing = currentProgram.getListing()

def removeLabels(addrStart, addrEnd):
    addressSetView = AF.getAddressSet(addrStart, addrEnd)
    clearListing(addressSetView,
        False, #code
        True,  #symbols
        False, #comments
        False, #properties
        False, #functions
        False, #registers
        False, #equates
        False, #userReferences
        False, #analysisReferences
        False, #importReferences
        False, #defaultReferences
        False) #bookmarks

def clearData(addrStart, addrEnd):
    addressSetView = AF.getAddressSet(addrStart, addrEnd)
    clearListing(addressSetView, # set
        True,  # code
        True,  # symbols
        False, # comments
        False, # properties
        True,  # functions
        False, # registers
        False, # equates
        False, # userReferences
        False, # analysisReferences
        False, # importReferences
        False, # defaultReferences
        False) # bookmarks

def _setName(fn, name, aObj):
    if fn.name == name: return
    if(fn.name.startswith("FUN_")
    or fn.name.startswith("doNothing_")):
        fn.setName(name, ghidra.program.model.symbol.SourceType.IMPORTED)
    else:
        createLabel(aObj, fn.name, False)
        fn.setName(name, ghidra.program.model.symbol.SourceType.IMPORTED)
        #print("Not changing name of %s to %s" % (fn.name, name))

def setFuncName(addr, name):
    fn = listing.getFunctionAt(addr)
    if fn is None:
        #print("making function at", addr)
        listing.clearCodeUnits(addr, addr.add(4), False)
        createFunction(addr, name)
    else: _setName(fn, name, addr)

def createFunctionWithName(addr, name):
    createFunction(addr, name)
    setFuncName(addr, name)


def addrToInt(addr):
	return int(str(addr), 16)

def intToAddr(addr):
	return AF.getAddress("0x%08X" % addr)

struct_DLL = getDataTypes('DLL')[0]
struct_ptr = getDataTypes('pointer')[0]

table = listing.getDataAt(intToAddr(TABLE_ADDR))
idx = 0
while True:
    dll     = table.getComponent(idx)
    id      = addrToInt(dll.getComponent(0).value)
    if id < 0: break
    funcTbl = addrToInt(dll.getComponent(2).value) - ITEM_SIZE
    addr    = intToAddr(funcTbl)

    # create DLL struct and label
    removeLabels(addr, addr.add(3))
    createLabel(addr, 'DLL_%04X' % id, False)
    clearData(addr, addr.add(ITEM_SIZE))
    listing.createData(addr, struct_DLL)

    # get the DLL info
    dll       = listing.getDataAt(addr)
    nFuncs    = addrToInt(dll.getComponent(2).value)
    #pFunc0    = dll.getComponent(3).value
    pOnUnload = dll.getComponent(4).value
    pOnLoad   = dll.getComponent(5).value
    print("DLL 0x%X at 0x%X, %d funcs" % (id, funcTbl, nFuncs))
    #print("pFunc0", pFunc0)
    #print("pOnLoad", pOnLoad)
    #print("pOnUnload", pOnUnload)

    #if addrToInt(pFunc0) != 0:
    #    createFunctionWithName(pFunc0, 'DLL_%04X_funcUnk' % id)
    if addrToInt(pOnLoad) != 0:
        createFunctionWithName(pOnLoad, 'DLL_%04X_onLoad' % id)
    if addrToInt(pOnUnload) != 0:
        createFunctionWithName(pOnUnload, 'DLL_%04X_onUnload' % id)

    offs = addr.add(ITEM_SIZE)
    for i in range(nFuncs+2):
        clearData(offs, offs.add(3))
        listing.createData(offs, struct_ptr)
        ptr = listing.getDataAt(offs).value
        #print("ptr", ptr)
        fName = FUNC_NAMES.get(i, 'func%02X' % i)
        createFunctionWithName(ptr, 'DLL_%04X_%s' % (id, fName))
        offs = offs.add(4)

    idx += 1
    if idx > 500: break # sanity check
