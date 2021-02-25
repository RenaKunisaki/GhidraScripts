#Import symbols from XML.
#@author Rena
#@category Symbol
#@keybinding
#@menupath
#@toolbar
import xml.etree.ElementTree as ET
from ghidra.program.model.listing import ParameterImpl
from ghidra.program.model.symbol import SourceType

AF = currentProgram.getAddressFactory()
listing = currentProgram.getListing()

def addrToInt(addr):
	return int(str(addr), 16)

def intToAddr(addr):
	return AF.getAddress("0x%08X" % addr)

# ghidra is fussy
def fixDataType(typ):
    return typ.replace(' ', '').replace('*', ' *')

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


def setParams(fn, eFunc):
    # set the params of a function.
    params = []
    for iParam, param in enumerate(eFunc.findall('./params/param')):
        reg  = param.get('reg',  None) # XXX support stack params?
        typ  = param.get('type', None)
        name = param.get('name', 'param%d' % (iParam+1))
        if typ is not None:
            dt = getDataTypes(fixDataType(typ))
            if len(dt) == 0:
                print("Not found data type", typ)
            else: dt = dt[0]
        else: dt = getDataTypes('undefined')[0]
        if reg is not None and reg != 'stack': loc = currentProgram.getRegister(reg)
        else: loc = param.get('stackOffset', None)
        if loc is None:
            # this probably means stack param
            print("No storage for param %s (reg %s) in func 0x%08X" % (
                name, reg, eFunc.get('address', 0xFFFFFFFF)))
            return
        try:
            pObj = ParameterImpl(name, dt, loc, currentProgram, SourceType.ANALYSIS)
        except:
            print("Failed creating param", name, typ, dt)
            return
        params.append(pObj)

    # apply the parameter changes
    #print("Set sig", fn, params)
    try:
        fn.replaceParameters(
            ghidra.program.model.listing.Function.FunctionUpdateType.CUSTOM_STORAGE, # updateType
            True, # force (remove conflicting local params)
            SourceType.ANALYSIS, # source
            params)
    except Exception as ex:
        print("Failed setting signature of", fn, ex)


def setReturn(fn, eFunc):
    ret = eFunc.find('./return')
    if ret is None: return

    typ = ret.get('type', None)
    if typ is not None:
        typ = fixDataType(typ)
        dt  = getDataTypes(fixDataType(typ))
        if len(dt) == 0:
            print("Not found data type", typ)
        #elif ret != 'void':
        else:
            # XXX reg? multiple returns?
            try: fn.setReturnType(dt[0], SourceType.ANALYSIS)
            except:
                print("Failed setting return of %s to type %s" % (fn, typ))


def handleFunc(eFunc):
    name   = eFunc.get('name')
    addr   = int(eFunc.get('address'), 0)
    length = int(eFunc.get('length'),  0)
    aStart = intToAddr(addr)
    aEnd   = intToAddr(addr+length - 1)
    listing.clearCodeUnits(aStart, aEnd, False)
    createFunction(aStart, name)
    func = listing.getFunctionAt(aStart)
    if func is None:
        print("Failed creating function at 0x%08X" % addr)
    else:
        comment = eFunc.find('./comment')
        if comment is not None:
            setPlateComment(aStart, comment.text)
        setParams(func, eFunc)
        setReturn(func, eFunc)


def handleSym(eSym):
    # <symbol address="0xA4800018" length="0x00000004" name="SI_STATUS" type="undefined4"/>
    name   = eSym.get('name')
    typ    = eSym.get('type')
    addr   = int(eSym.get('address'), 0)
    length = int(eSym.get('length'),  0)
    aStart = intToAddr(addr)
    aEnd   = intToAddr(addr+length-1)
    dt     = getDataTypes(fixDataType(typ))
    if len(dt) == 0:
        print("Not found data type:", typ)
    else:
        #print("Create at %08X - %08X type %s" % (addr, addr+length-1, typ))
        if length != dt[0].length:
            print("Symbol length (%s:0x%X) doesn't match data type length (%s:0x%X)" % (
                name, length, typ, dt[0].length))
            length = dt[0].length
            if length < 0: length = 1 # WTF?
            aEnd   = aStart.add(length-1)
        addressSetView = AF.getAddressSet(aStart, aEnd)
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
        listing.createData(aStart, dt[0])
    removeLabels(aStart, aEnd)
    createLabel(aStart, name, False)



path  = str(askFile("Import Symbol Map", "Import"))
xml   = ET.parse(path).getroot()
funcs = list(xml.findall('./functions/function'))
syms  = list(xml.findall('./data/symbol'))

monitor.initialize(len(funcs) + len(syms))

monitor.setMessage("Importing symbols...")
for eSym in syms:
    monitor.checkCanceled()
    handleSym(eSym)
    monitor.incrementProgress(1)

monitor.setMessage("Importing functions...")
for eFunc in funcs:
    monitor.checkCanceled()
    handleFunc(eFunc)
    monitor.incrementProgress(1)

monitor.setMessage("Ghidra is a butt...")
for eFunc in funcs:
    monitor.checkCanceled()
    addr   = int(eFunc.get('address'), 0)
    aStart = intToAddr(addr)
    disassemble(aStart) # ensure actually code here

print("Imported %d funcs, %d symbols" % (len(funcs), len(syms)))
