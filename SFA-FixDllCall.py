#Manually correct DLL calls.
#@author Rena
#@category StarFox
#@keybinding
#@menupath
#@toolbar

import jarray
import struct

listing  = currentProgram.getListing()
AF       = currentProgram.getAddressFactory()
mem      = currentProgram.getMemory()
R13      = 0x8039e700 # (KD) XXX don't hardcode
dllTbl   = 0x802E8B60 # address of symbol 'dlls'
NUM_DLLS = 764 # XXX get length of 'dlls'

def addrToInt(addr):
    """Convert Address to integer."""
    return int(str(addr), 16)

def intToAddr(addr):
    """Convert integer to Address."""
    return AF.getAddress("0x%08X" % addr)

def readStruct(addr, fmt):
    size = struct.calcsize(fmt)
    data = jarray.zeros(size, 'b')
    mem.getBytes(addr, data)
    r = struct.unpack(fmt, data)
    if len(r) == 1: r = r[0] # grumble
    return r

def removeEOLComment(addr):
    # hoo boy this is dumb
    addressSetView = AF.getAddressSet(addr, addr.add(1))
    plate = getPlateComment(addr)
    rep   = getRepeatableComment(addr)
    pre   = getPreComment(addr)
    post  = getPostComment(addr)
    clearListing(addressSetView,
        False, #code
        False, #symbols
        True,  #comments
        False, #properties
        False, #functions
        False, #registers
        False, #equates
        False, #userReferences
        False, #analysisReferences
        False, #importReferences
        False, #defaultReferences
        False) #bookmarks
    if plate is not None: setPlateComment     (addr, plate)
    if rep   is not None: setRepeatableComment(addr, rep)
    if pre   is not None: setPreComment       (addr, rep)
    if post  is not None: setPostComment      (addr, rep)


if currentSelection is None:
    blk       = mem.getBlock(currentAddress)
    startAddr = blk.getStart()
    endAddr   = blk.getEnd()
else:
    startAddr = currentSelection.getMinAddress()
    endAddr   = currentSelection.getMaxAddress()
data = listing.getDataContaining(startAddr)


def dllPtrToId(ptr):
    """Given a pointer to a DLL, find it in the DLL table."""
    for i in range(NUM_DLLS):
        n = readStruct(intToAddr(dllTbl + (i*4)), '>I')
        # n may point directly to the function table
        if n == ptr: return i, False
        if n == ptr - 0x10: return i, True
    print("No DLL found for ptr 0x%08X" % ptr)
    return None, None

def removeOldComment(addr):
    oldCom  = getEOLComment(addr)
    if oldCom is None: oldCom = ''
    if oldCom.startswith('{@symbol '):
        p = oldCom.find('}')
        oldCom = oldCom[p+1:].strip()

    # lol saving clears undo buffer, quality software
    p = oldCom.find('(DLL 0x')
    if p >= 0:
        q = oldCom.find(')', p)
        if q >= 0: oldCom = oldCom[0:p] + oldCom[q+1:]

    if oldCom == '': removeEOLComment(addr)
    else: setEOLComment(addr, oldCom)

def checkAddr(addr):
    """ hopefully the calls always look like:
    8018cdcc 80 6D A2 40  lwz       param_1,-0x5dc0(r13)
    8018cdd0 80 63 00 00  lwz       param_1,0x0(param_1)
    8018cdd4 81 83 00 28  lwz       r12,0x28(param_1)
    8018cdd8 7D 88 03 A6  mtspr     LR,r12
    8018cddc 4E 80 00 21  blrl
    """
    code = readStruct(addr.subtract(4), '>II')
    if code != (0x7D8803A6, 0x4E800021): return # mtlr r12; blrl
    #print("Found bl r12 at", addr)

    # seek back further and find the offset
    op, offs = readStruct(addr.subtract(8), '>Hh')
    if (op & 0xFFF0) != 0x8180: return # lwz r12, 0x??(rN) where 0 <= N < 16

    fIdx = (offs >> 2) # DLL function idx
    rIdx = op & 0xF  # register we set r12 from
    if rIdx < 3 or rIdx > 11: return # not a suitable GPR
    #print("lwz r12, 0x%04X(r%d)" % (offs, rIdx))

    # find the value of this register
    op, offs = readStruct(addr.subtract(0xC), '>Hh') # lwz rN, ?(rN)
    # this is putting the DLL* into rN
    if (op & 0xF) != rIdx: return # assume it's the same reg
    dllOffs = offs

    # get the value in rN
    op, offs = readStruct(addr.subtract(0x10), '>Hh') # lwz rN, ?(ry)
    rLoad = op & 0xF # get ry (probably r13)
    if rLoad == 13:
        pAddr = R13 + offs
    else:
        return # XXX
    #print("DLL* is at 0x%08X" % pAddr)
    if pAddr < 0x80000000 or pAddr >= 0x81800000: return # not valid

    # read the value at the address pointed to by rN
    try:
        pDll = readStruct(intToAddr(pAddr), '>I')
        #print("DLL is at 0x%08X" % pDll)
        dllId, isFuncTbl = dllPtrToId(pDll)
    except ghidra.program.model.mem.MemoryAccessException:
        # rN doesn't point to memory with known value.
        # check for a comment telling which DLL it is.
        isFuncTbl = False
        comment = getEOLComment(intToAddr(pAddr))
        if comment is None: comment = ''
        if comment.startswith('DLL:'):
            dllId = int(comment[4:], 0)
        else:
            print("Unknown DLL ID at %08X -> %08X" % (addrToInt(addr), pAddr))
            return
    if dllId is None:
        print("Invalid DLL ptr at 0x%08X" % pAddr)
        removeOldComment(addr)
        return
    #print("DLL ID is 0x%X" % dllId)

    if isFuncTbl: fIdx -= 6 # 0x18 >> 4

    # get the DLL's function table.
    pDll = readStruct(intToAddr(dllTbl + (dllId * 4)), '>I')
    if pDll == 0:
        print("DLL 0x%X has NULL pointer" % dllId)
        return
    #print("DLL is at 0x%X" % pDll)

    # get the function from the table.
    nFuncs = readStruct(intToAddr(pDll + 0xC), '>H') - 1
    if fIdx >= nFuncs or fIdx < 0:
        print(" *** Invalid func idx %d/%d at 0x%X" % (fIdx, nFuncs, addrToInt(addr)))
        removeOldComment(addr)
        return

    pFunc = readStruct(intToAddr(pDll + 0x18 + (fIdx * 4)), '>I')
    #print("Func[0x%X]: 0x%X" % (fIdx, pFunc))
    if pFunc < 0x80000000 or pFunc >= 0x81800000:
        print(" *** Invalid fptr at 0x%X" % addrToInt(addr))
        removeOldComment(addr)
        return

    # add the comment.
    comment = "{@symbol %x} (DLL 0x%X func 0x%X)" % (pFunc, dllId, fIdx)
    #comment = "{@symbol %x}" % pFunc
    removeOldComment(addr)
    oldCom  = getEOLComment(addr)
    if oldCom is None: oldCom = ''
    setEOLComment(addr, comment + ' ' + oldCom)

def run():
    iStart = addrToInt(startAddr)
    iEnd   = addrToInt(endAddr)
    monitor.initialize(iEnd-iStart)
    addressSetView = AF.getAddressSet(startAddr, endAddr)

    for i, instr in enumerate(listing.getInstructions(addressSetView, True)):
        addr = instr.address
        if (i & 0xFFF) == 0 and i > 0:
            monitor.checkCanceled()
            monitor.incrementProgress(0x1000)
            monitor.setMessage("Scanning... %08X" % addrToInt(addr))
        checkAddr(addr)


start()
run()
end(True)
