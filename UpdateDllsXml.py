#Update dlls.xml from project.
#@author Rena
#@category StarFox
#@keybinding
#@menupath
#@toolbar

import jarray
import struct
import re
import os
import os.path
import xml.etree.ElementTree as ET
from ghidra.program.model.listing import ParameterImpl
from ghidra.program.model.symbol import SourceType

#xmlPath    = '/mnt/guilmon/home/rena/projects/games/hax/sfa/data/K'
#xmlPath    = '/mnt/guilmon/home/rena/projects/games/hax/sfa/data/U0'
xmlPath    = '/mnt/guilmon/home/rena/projects/games/hax/sfa/data/KD'
dllsTree   = ET.parse(os.path.join(xmlPath, 'dlls.xml'))
dllsXml    = dllsTree.getroot()
interfaces = ET.parse(os.path.join(xmlPath, 'dllfuncs.xml')).getroot()

listing = currentProgram.getListing()
AF = currentProgram.getAddressFactory()
DT = currentProgram.getDataTypeManager()
mem = currentProgram.getMemory()

prgName  = currentProgram.name
#data     = listing.getDataAt(currentAddress)
#NUM_DLLS = data .getLength() / data.getComponent(0).getLength()
#NUM_DLLS = 0x2C2 # U0
NUM_DLLS = 0x2FC # KD

def addrToInt(addr):
    return int(str(addr), 16)

def intToAddr(addr):
    return AF.getAddress("0x%08X" % addr)


RE_STRIP_STUB_RETURN = re.compile(r'_ret_[0-9A-F]+')
RE_GENERIC_FUNC_NAME = re.compile(r'(^FUN_|^doNothing_|^return|Fn_|\[|:|\.|func[0-9A-F]+)')
def isGenericFuncName(name):
    """Check if name is a generic function name."""
    if name is None:
        raise ValueError("function name is None")
    return RE_GENERIC_FUNC_NAME.search(name) is not None


def isGenericParamName(name):
    """Check if name is a generic parameter name."""
    if name is None:
        raise ValueError("parameter name is None")
    return name.startswith('param')


def handleFunc(iDll, iFunc, fp, dll):
    if fp is None or fp < 0x80000000 or fp > 0x81800000: return
    dllName = dll.get('name', None)

    eFuncs = dll.find('./functions')
    if eFuncs is None: eFuncs = ET.SubElement(dll, 'functions')

    eFunc = dll.find('./functions/function[@idx="0x%X"]' % iFunc)
    if eFunc is None:
        #print("Not found DLL 0x%X function 0x%X" % (iDll, iFunc))
        eFunc = ET.SubElement(eFuncs, 'function', {
            'idx': '0x%X' % iFunc,
            'address': '0x%08X' % fp,
        })
    fAddr = eFunc.get('address', None)
    if fAddr is not None:
        print("fAddr is", type(fAddr).__name__, fAddr)
        if fAddr != fp:
            print("Mismatched addresses for DLL 0x%X function 0x%X: 0x%X vs 0x%X" % (
                iDll, iFunc, fAddr, fp))
    else: eFunc.set('address', '0x%08X' % fp)

    addr = intToAddr(fp)
    fn = listing.getFunctionAt(addr)
    if fn is None:
        print("No function at 0x%X (DLL 0x%X func 0x%X)" % (fp, iDll, iFunc))
        return

    # if this function has a non-generic name, and the XML doesn't,
    # then save that to the XML.
    name = fn.getName()
    if name.startswith('dll'): name = name[3:]
    if name.startswith('_'): name = name[1:]
    if dllName is not None:
        if name.lower().startswith(dllName.lower()):
            name = name[len(dllName):]
    if name.startswith('_'): name = name[1:]
    count = 0
    while ('_nop' in name or '_ret_' in name) and count < 10:
        name = RE_STRIP_STUB_RETURN.sub('', name.replace('_nop', ''))
        count += 1
    while ('%02X_' % iDll) in name:
        name = name.replace('%02X_' % iDll, '')
    if not isGenericFuncName(name):
        fName = eFunc.get('name', None)
        if fName is None: eFunc.set('name', name)
        elif fName != name:
            print("Mismatched names for DLL 0x%X func 0x%X: '%s' vs '%s'" % (
                iDll, iFunc, fName, name))
            eFunc.set('name', name)

    # if this function has some params and the XML doesn't, save them.
    params = fn.getParameters()
    if len(params) > 0:
        # fix functions that have <param> directly under <function>
        # instead of under <params>
        eParam = eFunc.findall('./param')
        if len(eParam) > 0:
            eParams = eFunc.find('./params')
            if eParams is None: eParams = ET.SubElement(eFunc, 'params')
            for param in list(eParam):
                eFunc.remove(param)
                eParams.append(param)

        eParams = eFunc.findall('./params/param')
        if len(eParams) == 0:
            eParams = eFunc.find('./params')
            if eParams is None: eParams = ET.SubElement(eFunc, 'params')
            for param in params:
                stackOffs = None
                reg = param.getRegister()
                if reg is None:
                    reg = 'stack'
                    try: stackOffs = hex(param.getStackOffset())
                    except:
                        print("No register or stack for param %r in DLL 0x%X func 0x%X" % (
                            param, iDll, iFunc))
                        reg = None
                else: reg = reg.getName()
                pName = param.getName()
                if isGenericParamName(pName): pName = None
                pType = param.getDataType().getName()
                if pType == 'undefined': pType = None
                elif pType == 'undefined8' and reg is not None and reg.startswith('f'):
                    pType = 'double'

                attrs = {
                    'type': pType,
                    'name': pName,
                    'reg':  reg,
                    'stackOffset': stackOffs,
                }
                # XXX use some fancy comprehensionm shit
                if attrs['type']        is None: del attrs['type']
                if attrs['name']        is None: del attrs['name']
                if attrs['reg']         is None: del attrs['reg']
                if attrs['stackOffset'] is None: del attrs['stackOffset']
                eParam = ET.SubElement(eParams, 'param', attrs)
        elif len(eParams) != len(params):
            print("Mismatched params for DLL 0x%X func 0x%X (addr 0x%X)" % (
                iDll, iFunc, fp))


    # if this function has some returns and the XML doesn't, save them.
    ret = fn.getReturnType()
    if ret is not None and ret.getName() != 'undefined':
        ret = ret.getName()
        eRet = eFunc.find('return')
        if eRet is not None:
            if eRet.get('type') != ret:
                print("Mismatched returns for DLL 0x%X func 0x%X: %s vs %s" % (
                    iDll, iFunc, ret, eRet.get('type')))
        else: ET.SubElement(eFunc, 'return', {'type': ret})


def handleDll(idx, obj, addr):
    flags = obj.getComponent(2)
    count = obj.getComponent(3)
    if count is None or flags is None: return

    # sanity check
    flags = addrToInt(flags.value)
    if flags != 0:
        print("Ignoring DLL 0x%X with flags 0x%08X" % (idx, flags))
        return
    nFuncs = addrToInt(count.value)
    if nFuncs > 64:
        print("Ignoring DLL 0x%X with %d funcs" % (idx, nFuncs))
        return

    dll = dllsXml.find('./dll[@id="0x%04X"]' % idx)
    if dll is None:
        dll = ET.SubElement(dllsXml, 'dll', {
            'id': '0x%04X' % idx,
        })
    for i in range(1 + nFuncs):
        #fp = obj.getComponent(5+i)
        #fp = listing.getDataAt(addr.add((i * 4) + 0x10))
        data = jarray.zeros(4, "b")
        mem.getBytes(addr.add((i * 4) + 0x10), data)
        fp = struct.unpack('>I', data)[0] # grumble
        handleFunc(idx, i, fp, dll)


def run():
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


    dllsTree.write(os.path.join(xmlPath, 'dlls2.xml.tmp'))
    os.system('xmllint --format -o %s %s' % (
        os.path.join(xmlPath, 'dlls2.xml'),
        os.path.join(xmlPath, 'dlls2.xml.tmp')))

start()
run()
end(True)
