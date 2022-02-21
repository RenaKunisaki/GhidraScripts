#Export all symbols and types to XML for SFA.
#@author Rena
#@category StarFox
#@keybinding
#@menupath
#@toolbar
GAME_VERSION = 'U0'

import xml.etree.ElementTree as ET
import os.path
import re
import time
from datetime import timedelta

# I think this won't work; there's too much information lost on import to ghidra
# such as the order of type definitions.
# but it might still be useful if we made a corresponding importer.

# XXX find a way to determine these quickly.
NUM_FUNCS = 8264
NUM_SYMS  = 4230
NUM_TYPES = 3411

# read existing file
xmlPath   = '/mnt/guilmon/home/rena/projects/games/hax/sfa/elf/'
symsPath  = os.path.join(xmlPath, 'symbols.export.xml')
typesPath = os.path.join(xmlPath, 'types.export.xml')
tSymbols  = ET.parse(symsPath)
tTypes    = ET.parse(typesPath)
eSymbols  = tSymbols.getroot()
eTypes    = tTypes  .getroot()


AF      = currentProgram.getAddressFactory()
DT      = currentProgram.getDataTypeManager()
listing = currentProgram.getListing()

def addrToInt(addr):
	return int(str(addr), 16)

def intToAddr(addr):
	return AF.getAddress("0x%08X" % addr)

def checkCanceled():
    if monitor.isCancelled(): raise "Cancelled"

filterFuncPrefixes = ("FUN_", "LAB_")
def filterFunc(func):
	if func.name.startswith(filterFuncPrefixes): return False
	return True

filterLabelPrefixes = (
	'byte_',
    'char_',
    'd_',
	'dat_',
    'double_',
	'dword_',
    'f_',
	'float_',
    'int_',
	'lab_',
    'long_',
    'minus',
    'null_',
	'padding_',
    'pointer_',
	'ptr_',
	's_',
    'short_',
    'switchdata',
    'thunk_',
    'u_',
    'ubyte_',
    'uint_',
    'ushort_',
    'word_',
	'zlb_',
)
filterLabels = (
    'eight',
    'five',
    'four',
    'half',
    'nine',
    'one',
    'pi',
    'piover180',
    'padding',
    'seven',
    'six',
    'ten',
    'three',
    'two',
    'zero',
)
typeMap = {
    'pointer': 'void*',
    'undefined': 'undefined1',
}

def filterData(sym):
    if sym.label is None or sym.label == "": return False
    lbl = sym.label.lower()
    if lbl in filterLabels: return False
    if lbl.startswith(filterLabelPrefixes): return False
    return True

def isGenericParamName(name):
    """Check if name is a generic parameter name."""
    if name is None:
        raise ValueError("parameter name is None")
    return name.startswith('param')

def paramSortFunc(param):
    """Key function for sorting function params."""
    reg = param.get('reg', '')
    if    reg.startswith('r'): reg = int(reg[1:])
    elif  reg.startswith('f'): reg = int(reg[1:]) + 32
    else: reg = 64
    return reg


def listParams(func):
    """Build list of parameters for function."""
    result = []
    nextR, nextF = 3, 1
    iter = getattr(func, 'getParameters', None)
    if iter is None: iter = getattr(func, 'getArguments') # lol
    for param in iter():
        checkCanceled()
        pType = param.getDataType().getName()
        stackOffs = None
        if hasattr(param, 'getRegister'): # lol
            reg = param.getRegister()
            if reg is None:
                reg = 'stack'
                try: stackOffs = hex(param.getStackOffset())
                except:
                    print("No register or stack for param %r in func %s" % (
                        param, func))
                    reg = None
            else: reg = reg.getName()
        else:
            if pType in ('float', 'double'):
                reg = 'f%d' % nextF
                nextF += 1
            else:
                reg = 'r%d' % nextR
                nextR += 1
        pName = param.getName()
        if isGenericParamName(pName): pName = None
        #if pType == 'undefined': pType = None
        if pType == 'undefined8' and reg is not None and reg.startswith('f'):
            pType = 'double'
        if pType in typeMap: pType = typeMap[pType]

        res = {
            'type': pType,
            'name': pName,
            'reg':  reg,
            'stackOffset': stackOffs,
        }
        # XXX use some fancy comprehension shit
        r = {}
        for k, v in res.items():
            if v is None: pass
            else: r[k] = str(v)
        result.append(r)
    return sorted(result, key=paramSortFunc)


def listFuncs():
    """Build list of functions in current program."""
    for func in filter(filterFunc, listing.getFunctions(True)):
        checkCanceled()
        ret = func.getReturnType()
        if ret is not None and ret.getName() != 'undefined':
            ret = ret.getName()
        else:
            ret = None
        yield {
            'start':  addrToInt(func.body.minAddress),
            'end':    addrToInt(func.body.maxAddress),
            #'proto':  str(func.signature.prototypeString),
            'name':   str(func.name),
            'params': list(listParams(func)),
            'comment': getPlateComment(func.body.minAddress),
            'return':  ret,
        }

def listSyms():
    """Yield list of non-function symbols in current program."""
    for sym in filter(filterData, listing.getDefinedData(True)):
        checkCanceled()
        typ = str(sym.dataType.displayName)
        if typ in typeMap: typ = typeMap[typ]
        yield {
            "name":  str(sym.label),
            "start": addrToInt(sym.minAddress),
            "end":   addrToInt(sym.maxAddress),
            "type":  typ,
        }

addrPath = "address[@version='%s']" % GAME_VERSION
def setAddress(eSym, addr):
    """Set up the 'address' child element of an element."""
    # remove duplicates
    for eAddr in list(eSym.findall(addrPath)):
        eSym.remove(eAddr)
    eAddr = ET.SubElement(eSym, 'address')
    eAddr.set('version', GAME_VERSION)
    eAddr.text = '0x%08X' % addr
    return eAddr

nextNoName = 0
re_name_badChars = re.compile(r'[^_A-Za-z0-9\*]+')
def filterName(name):
    """Ensure name is a valid identifier for C code."""
    global nextNoName
    name = name.replace(' ', '')
    name = re_name_badChars.sub('_', name)
    if name == '': # lol
        name = 'NO_NAME_%d' % nextNoName
        nextNoName += 1
    if name[0].isdigit(): name = '_'+name
    return name

def parseTypeName(typeName):
    """Extract array size from type name if present."""
    p = typeName.find('[')
    if p >= 0:
        q = typeName.find(']')
        return {
            'type':  filterName(typeName[0:p]),
            'count': typeName[p+1:q],
        }
    p = typeName.find(':')
    if p >= 0:
        return {
            'type': filterName(typeName[0:p]),
            'bits': typeName[p+1:]
        }
    return {'type':filterName(typeName)}

def removeDuplicates(elem, path):
    """Remove duplicate children of elem."""
    dupes = list(elem.findall(path))[1:]
    for d in dupes: elem.remove(d)

def exportFunctions():
    """Write functions to symbols XML."""
    nFuncs = 0
    # addr, size, vAddr, align, name
    for func in listFuncs():
        name = filterName(func['name'])
        #monitor.setMessage("Listing functions... "+func['name'])
        monitor.incrementProgress(1)
        removeDuplicates(eSymbols, ".//symbol[@name='%s']" % name)
        eSym = eSymbols.find(".//symbol[@name='%s']" % name)
        if eSym is None: eSym = ET.SubElement(eSymbols, 'symbol')
        eSym.set('type', 'function')
        eSym.set('name', name)
        setAddress(eSym, func['start'])
        #'length':  '0x%08X' % ((func['end'] - func['start'])+1),

        #if func['comment'] is not None: # XXX parse
        #    ET.SubElement(eFunc, 'comment').text = func['comment']

        # handle return
        eRet = eSym.find('return')
        if eRet is None: eRet = ET.SubElement(eSym, 'return')
        if func['return'] is not None:
            typ = parseTypeName(func['return'])
            eRet.set('type', typ['type'])
            if 'count' in typ: eRet.set('count', typ['count'])
            if 'bits'  in typ: eRet.set('bits',  typ['bits'])
        else: # return type isn't known
            eRet.set('type', 'UNKNOWN_RETURN_TYPE')

        # handle params
        eParams = eSym.find('params')
        if eParams is None: eParams = ET.SubElement(eSym, 'params')
        #eParams.clear() # to fix duplicates

        for i, param in enumerate(func['params']):
            pName = filterName(param.get('name', 'param%d' % (i+1)))
            pReg  = param.get('reg', 'unk%d' % i)
            removeDuplicates(eParams, ".//param[@name='%s']" % pName)
            removeDuplicates(eParams, ".//param[@reg='%s']" % pReg)
            eParam = eParams.find(".//param[@reg='%s']" % pReg)
            if eParam is None: eParam = eParams.find(".//param[@name='%s']" % pName)
            if eParam is None: eParam = ET.SubElement(eParams, 'param')
            eParam.set('name', pName)
            eParam.set('reg', pReg)
            if 'type' in param:
                typ = parseTypeName(param['type'])
                eParam.set('type', typ['type'])
                if 'count' in typ: eParam.set('count', typ['count'])

        nFuncs += 1
    return nFuncs


def exportData():
    """Write non-function symbols to symbols XML."""
    nSyms = 0
    for sym in listSyms():
        name = filterName(sym['name'])
        #monitor.setMessage("Listing data... "+name)
        monitor.incrementProgress(1)
        removeDuplicates(eSymbols, ".//symbol[@name='%s']" % name)
        eSym = eSymbols.find(".//symbol[@name='%s']" % name)
        if eSym is None: eSym = ET.SubElement(eSymbols, 'symbol')

        # update the element
        eSym.set('name', name)
        typ = parseTypeName(sym['type'])
        eSym.set('type', typ['type'])
        if 'count' in typ: eSym.set('count', typ['count'])

        #'length':  '0x%08X' % ((sym['end'] - sym['start'])+1),
        setAddress(eSym, sym['start'])
        nSyms += 1
    return nSyms


def getTypeElement(parent, dType, elemType):
    name = filterName(dType.name)
    eDef = parent.find(".//%s[@name='%s']" % (elemType, name))
    if eDef is None: eDef = ET.SubElement(parent, elemType)
    eDef.set('name', name)
    eDef.set('category', str(dType.categoryPath))
    return eDef


def exportStructOrUnion(dType, elemType):
    """Write struct/union definition to types XML."""
    eStruct = getTypeElement(eTypes, dType, elemType)
    for comp in dType.components:
        fName  = comp.fieldName
        #fType  = comp.dataType.name if comp.dataType else 'undefined1'
        if comp.dataType and comp.dataType.name != 'undefined':
            fType  = parseTypeName(comp.dataType.name)
            eField = eStruct.find("field[@name='%s']" % fName)
            if eField is None: eField = ET.SubElement(eStruct, 'field')
            if fName is None: fName = 'unk%02X' % comp.offset
            eField.set('name', fName)
            eField.set('type', fType['type'])
            if 'count' in fType: eField.set('count', fType['count'])
            eField.set('offset', '0x%X' % comp.offset)
            removeDuplicates(eStruct, ".//field[@name='%s']" % fName)


def exportEnum(dType):
    """Write enum definition to types XML."""
    if dType.name.startswith('define_'):
        name = dType.name[7:]
        eDef = getTypeElement(eTypes, dType, 'define')
        eDef.set('value', '0x%X' % dType.values[0])
        return

    eEnum = getTypeElement(eTypes, dType, 'enum')
    eEnum.set('type', 'u%d' % (dType.getLength() * 8))
    if eEnum.get('prefix', None) is None:
        eEnum.set('prefix', dType.name+'_')
    for mName in dType.names:
        name = filterName(mName)
        eMember = eEnum.find(".//member[@name='%s']" % name)
        if eMember is None: eMember = ET.SubElement(eEnum, 'member')
        eMember.set('name', name)
        eMember.set('value', '0x%X' % dType.getValue(mName))
        removeDuplicates(eEnum, ".//member[@name='%s']" % name)


def exportTypedef(dType):
    """Write typedef to types XML."""
    eDef = getTypeElement(eTypes, dType, 'typedef')
    eDef.text = filterName(dType.dataType.name)


def exportFuncdef(dType):
    """Write function typedef to types XML."""
    #typedef void (*SignalHandler)(int signum);
    eDef = getTypeElement(eTypes, dType, 'funcdef')
    retType = dType.returnType
    name    = filterName(dType.name)
    # I have no idea what I'm doing

    removeDuplicates(eTypes, ".//funcdef[@name='%s']" % name)

    # handle return
    eRet = eDef.find('return')
    if eRet is None: eRet = ET.SubElement(eDef, 'return')
    if retType is not None:
        typ = parseTypeName(retType.name)
        eRet.set('type', typ['type'])
        if 'count' in typ: eRet.set('count', typ['count'])
        if 'bits'  in typ: eRet.set('bits',  typ['bits'])
    else: # return type isn't known
        eRet.set('type', 'UNKNOWN_RETURN_TYPE')

    # handle params
    eParams = eDef.find('params')
    if eParams is None: eParams = ET.SubElement(eDef, 'params')
    #eParams.clear() # to fix duplicates

    params = listParams(dType)
    for i, param in enumerate(params):
        # funcdef params don't have names
        pReg  = param.get('reg', 'unk%d' % i)
        removeDuplicates(eParams, ".//param[@reg='%s']" % pReg)
        eParam = eParams.find(".//param[@reg='%s']" % pReg)
        if eParam is None: eParam = ET.SubElement(eParams, 'param')
        eParam.set('reg', pReg)
        if 'type' in param:
            typ = parseTypeName(param['type'])
            eParam.set('type', typ['type'])
            if 'count' in typ: eParam.set('count', typ['count'])


def exportTypes():
    """Write type definitions to types XML."""
    nTypes, nFailed = 0, 0
    types = DT.allDataTypes
    Data  = ghidra.program.database.data
    while True:
        try:
            dType = next(types)
            nTypes += 1
        except StopIteration: break
        except Exception as ex:
            print("ERROR", ex)
            break
        except:
            nFailed += 1
            continue
        if dType.name == 'word[8]':
            # I guess this is the only way to detect the last type, which is
            # important because after that `next()` will just hang forever,
            # because lol quality software.
            break

        #monitor.setMessage("Listing types... "  + dType.name)
        monitor.incrementProgress(1)
        dt = type(dType)
        if   dt is Data.EnumDB: exportEnum(dType)
        elif dt is Data.FunctionDefinitionDB: exportFuncdef(dType)
        elif dt is Data.StructureDB: exportStructOrUnion(dType, 'struct')
        elif dt is Data.TypedefDB: exportTypedef(dType)
        elif dt is Data.UnionDB: exportStructOrUnion(dType, 'union')
        #elif dt is Data.PointerDB: pass
        #elif dt is Data.ArrayDB: pass
        #else:
            #print("Unrecognized type", type(dType), dType)
            #break
    return nTypes


tmStart = time.time()
monitor.initialize(NUM_FUNCS+NUM_TYPES+NUM_SYMS)
monitor.setMessage("Listing types...")
nTypes = exportTypes()
monitor.setMessage("Listing data...")
nSyms  = exportData()
monitor.setMessage("Listing functions...")
nFuncs = exportFunctions()
#nSyms, nFuncs = 0, 0

monitor.setMessage("Writing symbols...")
tSymbols.write(symsPath)
monitor.setMessage("Writing types...")
tTypes  .write(typesPath)
tmTotal = time.time() - tmStart
print("Wrote %d functions, %d symbols, %d types in %s" % (nFuncs, nSyms, nTypes,
    str(timedelta(seconds=tmTotal))))
