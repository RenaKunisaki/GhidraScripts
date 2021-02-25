#Auto name DLL functions in SFA.
#@author Rena
#@category StarFox
#@keybinding
#@menupath
#@toolbar

# use Struct/FixupStructPtrs.py before running this to make the DLL structs.

import jarray
import struct
import os.path
import xml.etree.ElementTree as ET
from ghidra.program.model.listing import ParameterImpl
from ghidra.program.model.symbol import SourceType

#xmlPath = '/mnt/guilmon/home/rena/projects/games/hax/sfa/data/K'
#xmlPath = '/mnt/guilmon/home/rena/projects/games/hax/sfa/data/U0'
xmlPath = '/mnt/guilmon/home/rena/projects/games/hax/sfa/data/KD'
dllsXml  = ET.parse(os.path.join(xmlPath, 'dlls.xml')).getroot()
interfaces = ET.parse(os.path.join(xmlPath, 'dllfuncs.xml')).getroot()

listing = currentProgram.getListing()
AF = currentProgram.getAddressFactory()
DT = currentProgram.getDataTypeManager()
mem = currentProgram.getMemory()

prgName  = currentProgram.name
data     = listing.getDataAt(currentAddress)
NUM_DLLS = data .getLength() / data.getComponent(0).getLength()
#NUM_DLLS = 0x2C2


# ghidra is fussy
def fixDataType(typ):
    return typ.replace(' ', '').replace('*', ' *')


def addrToInt(addr):
    return int(str(addr), 16)

def intToAddr(addr):
    return AF.getAddress("0x%08X" % addr)


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


def updateDllNames():
    newDLL_ID   = ghidra.program.model.data.EnumDataType('DLL_ID',   4)
    newDLL_ID16 = ghidra.program.model.data.EnumDataType('DLL_ID16', 2)

    for dll in dllsXml.findall("./dll"):
        id   = int(dll.get('id'), 0)
        name = dll.get('name', None)
        if name is not None:
            try: newDLL_ID  .add(name, id)
            except: print("Failed adding %s=0x%X to DLL_ID" % (name, id))
            try: newDLL_ID16.add(name, id)
            except: print("Failed adding %s=0x%X to DLL_ID16" % (name, id))
    newDLL_ID  .add("NUM_DLLS", NUM_DLLS)
    newDLL_ID16.add("NUM_DLLS", NUM_DLLS)
    newDLL_ID  .add("NO_DLL", 0xFFFFFFFF)
    newDLL_ID16.add("NO_DLL", 0xFFFF)

    #DT.getDataType(prgName+"/SFA/DLL/DLL_ID")  .replaceWith(newDLL_ID)
    #DT.getDataType(prgName+"/SFA/DLL/DLL_ID16").replaceWith(newDLL_ID16)
    DT.getDataType(prgName+"/DLL_ID")  .replaceWith(newDLL_ID)
    DT.getDataType(prgName+"/DLL_ID16").replaceWith(newDLL_ID16)


def setName(fn, name):
    if name is None:
        raise ValueError("function name is None")
    if fn.name == name: return
    #if(fn.name.startswith("FUN_")
    #or fn.name.startswith("doNothing_")
    #or fn.name.startswith("Fn_")
    #or 'file[' in fn.name
    #or 'obj[' in fn.name
    #or ':' in fn.name or '.' in fn.name
    #or fn.name.startswith('dll_')):
    #    fn.setName(name, SourceType.ANALYSIS)
    #else:
    #    print("Not changing name of %s to %s" % (fn.name, name))
    fn.setName(name, SourceType.ANALYSIS)


def setParams(fn, funcDef, comment, oldComment):
    # set the params and build up the comment describing them.
    if funcDef['params'] is None: return

    params = []
    for iParam, param in enumerate(funcDef['params']):
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
                name, reg, funcDef.get('address', 0xFFFFFFFF)))
            return
        try:
            pObj = ParameterImpl(name, dt, loc, currentProgram, SourceType.ANALYSIS)
        except:
            print("Failed creating param", name, typ, dt)
            return
        params.append(pObj)
        desc = param.find('./description')
        if desc is not None:
            text = ''.join(desc.itertext())
            if text != '':
                comment.append("@param %s %s" % (name, desc.text))
                oldComment.append("%s: %s" % (name, desc.text))
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


def setReturn(fn, funcDef, comment, oldComment):
    ret = funcDef.get('returns', None)
    if ret is None: return

    typ = ret[0].get('type', None)
    if typ is not None:
        typ = fixDataType(typ)
        dt = getDataTypes(typ)
        if len(dt) == 0:
            print("Not found data type", typ)
        #elif ret != 'void':
        else:
            # XXX reg? multiple returns?
            try: fn.setReturnType(dt[0], SourceType.ANALYSIS)
            except:
                print("Failed setting return of %s to type %s" % (fn, ret))

    # add return comment
    retDesc = ret[0].find('./description')
    if funcDef.get('name', None) == 'isOneOfItemsBeingUsed':
        print("retDesc=", retDesc)
    if retDesc is not None:
        comment.append('@return %s' % (''.join(retDesc.itertext())))


def setFuncSig(fn, funcDef):
    # build the plate comment.
    # also build the old-format comment so that we can check if it's there
    # and replace it with the new one.
    comment = []
    oldComment = []
    desc = funcDef.get('desc', None)
    if desc is not None and desc != '':
        comment.append('@description ' + desc)
        oldComment.append(desc)

    setParams(fn, funcDef, comment, oldComment)
    setReturn(fn, funcDef, comment, oldComment)

    # set the comment
    comment = '\n'.join(comment)
    oldComment = '\n'.join(oldComment)
    if comment != '':
        addr = fn.getEntryPoint()
        orig = getPlateComment(addr)
        if orig == comment+'\n'+comment: orig = None # oops
        if orig == oldComment: orig = None # replace old format
        if orig is not None and orig != comment: comment += '\n' + orig

        # remove duplicate lines
        comment = comment.split('\n')
        comment = [i for n, i in enumerate(comment) if i not in comment[n+1:]]

        setPlateComment(addr, '\n'.join(comment))
    if funcDef.get('name', None) == 'isOneOfItemsBeingUsed':
        print("COMMENT", comment)


def getFuncSigFromInterface(iface, funcIdx, _depth=0):
    """Given an interface and a function index, get the function's signature.

    Recurses to follow 'extends' of the interface.

    Return function signature or None.
    """
    assert _depth < 5, "Interface nesting too deep"
    func = iface.find('./function[@idx="%d"]' % funcIdx)
    if func is not None: return func
    for ext in iface.findall('./extends'):
        name = ext.get('interface')
        extIface = interfaces.find('./interface[@name="%s"]' % name)
        if extIface is None: raise ValueError("Interface '%s' not found" % name)
        r = getFuncSigFromInterface(extIface, funcIdx, _depth+1)
        if r is not None: return r
    return None


def getSig(iDll, iFunc):
    """Get signature of function #`iFunc` in DLL #`iDll`."""
    dll = dllsXml.find('./dll[@id="0x%04X"]' % iDll)
    result = {
        'iDll':    iDll,
        'iFunc':   iFunc,
        'address': None,
        'params':  None,
        'desc':    None,
    }

    fields = ('name', 'stub', 'return', 'returns')
    for f in fields: result[f] = None

    ifaceName = dll.get('interface', None)
    if ifaceName is not None:
        iface = interfaces.find('./interface[@name="%s"]' % ifaceName)
        if iface is None:
            raise ValueError("Interface '%s' not found" % ifaceName)
        sig = getFuncSigFromInterface(iface, iFunc)
        if sig is not None:
            for f in fields: result[f] = sig.get(f, result[f])

            params = sig.findall('./params/param')
            if len(params) > 0: result['params'] = []
            for param in params: result['params'].append(param)

            returns = sig.findall('./return')
            if len(returns) > 0: result['returns'] = []
            for ret in returns: result['returns'].append(ret)

            desc = sig.find('description')
            if desc is not None:
                result['desc'] = ''.join(desc.itertext())

    # func def in the DLL overrides those in the interface.
    # XXX why is idx in hex here but not in interface?
    func = dll.find('./functions/function[@idx="0x%X"]' % iFunc)
    if func is not None:
        result['address'] = int(func.get('address'), 16)
        for f in fields: result[f] = func.get(f, result[f])

        params = func.findall('./params/param')
        if len(params) > 0 and result['params'] is None: result['params'] = []
        for param in params: result['params'].append(param)

        returns = func.findall('./return')
        if len(returns) > 0 and result['returns'] is None: result['returns'] = []
        for ret in returns: result['returns'].append(ret)

        desc = func.find('description')
        if desc is not None:
            d = result['desc']
            if d is None: d = ''
            else: d += '\n'
            result['desc'] = d + ''.join(desc.itertext())

    # if both interface and function specify the same param,
    # don't try to apply them both.
    if result['params'] is not None:
        params = {}
        nextReg, nextFloat = 3, 1
        for param in result['params']:
            reg = param.get('reg', None)
            if reg == 'stack':
                reg = 's%X' % int(param.get('stackOffset'), 0)
                params[reg] = param
            else:
                if reg is None:
                    if param.get('type', None) in ('float', 'double'):
                        param.set('reg', 'f%d' % nextFloat)
                        nextFloat += 1
                    else:
                        param.set('reg', 'r%d' % nextReg)
                        nextReg += 1
                reg = param.get('reg')
                if ':' in reg: reg = reg.split(':')[0]
                params[reg] = param
        result['params'] = list(params.values())

    if result['desc'] is not None: result['desc'] = result['desc'].strip()
    if result['name'] is None: result['name'] = 'func%02X' % iFunc
    #if iDll == 0 and iFunc == 20: print(result)
    return result



def handleFunc(iDll, iFunc, fp, dllName):
    if fp is None or fp < 0x80000000 or fp > 0x81800000: return

    name = 'func%d' % iFunc
    funcDef = getSig(iDll, iFunc)
    if funcDef is not None:
        name = funcDef.get('name', name)
        if funcDef.get('stub', '0') == '1':
            ret = funcDef.get('return', None)
            if ret is None: name += '_nop'
            else: name += '_ret_' + (str(ret).replace('-', 'm'))
    name = '%s_%s' % (dllName, name)

    # wtf?
    while ('_%02X_%02X' % (iDll, iDll)) in name:
        name = name.replace('_%02X_%02X' % (iDll, iDll), '_%02X' % iDll)
    while ('_%02X%02X' % (iDll, iDll)) in name:
        name = name.replace('_%02X%02X' % (iDll, iDll), '_%02X' % iDll)

    addr = intToAddr(fp)
    fn = listing.getFunctionAt(addr)
    if fn is None:
        #print("making function at", fp)
        #listing.clearCodeUnits(addr, addr.add(4), False)
        createFunction(addr, name)
    else: setName(fn, name)
    disassemble(addr) # ensure actually code here

    if funcDef is not None:
        fn = listing.getFunctionAt(addr)
        setFuncSig(fn, funcDef)



def handleDll(idx, obj, addr):
    flags = obj.getComponent(2)
    count = obj.getComponent(3)
    if count is None or flags is None: return

    # create label for DLL
    #DLL_ID = DT.getDataType(prgName+"/SFA/DLL/DLL_ID")
    DLL_ID = DT.getDataType(prgName+"/DLL_ID")
    dllName = DLL_ID.getName(idx)
    if dllName is None: dllName = "dll_%02X" % idx
    removeLabels(addr, addr.add(3))
    createLabel(addr, dllName, False)

    # sanity check
    flags = addrToInt(flags.value)
    if flags != 0:
        print("Ignoring DLL 0x%X with flags 0x%08X" % (idx, flags))
        return
    nFuncs = addrToInt(count.value)
    if nFuncs > 64:
        print("Ignoring DLL 0x%X with %d funcs" % (idx, nFuncs))
        return

    # create label for function table
    removeLabels(addr.add(0x18), addr.add(0x1B))
    createLabel(addr.add(0x18), "%s_funcs" % dllName, False)

    # create functions and/or rename existing functions
    for i in range(1 + nFuncs):
        #fp = obj.getComponent(5+i)
        #fp = listing.getDataAt(addr.add((i * 4) + 0x10))
        data = jarray.zeros(4, "b")
        mem.getBytes(addr.add((i * 4) + 0x10), data)
        fp = struct.unpack('>I', data)[0] # grumble
        handleFunc(idx, i, fp, dllName)


def run():
    updateDllNames()

    startAddr = intToAddr(int(dllsXml.get('tableAddress'), 16))
    data  = listing.getDataAt(startAddr)
    #struc = data .getComponent(0).dataType.dataType
    #sLen  = struc.getLength()
    monitor.initialize(NUM_DLLS)
    monitor.setMessage("Update DLLs...")
    for i in range(NUM_DLLS):
        addr = data.getComponent(i).value
        obj  = listing.getCodeUnitAt(addr)
        if obj is not None:
            handleDll(i, obj, addr)
        monitor.checkCanceled()
        monitor.incrementProgress(1)

start()
run()
end(True)
