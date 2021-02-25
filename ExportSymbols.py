#Export all symbols to XML.
#@author Rena
#@category Symbol
#@keybinding
#@menupath
#@toolbar
import xml.etree.ElementTree as ET

AF = currentProgram.getAddressFactory()
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
	"BYTE_",
	"DAT_",
	"DWORD_",
	"FLOAT_",
	#"fptr_",
	"LAB_",
	"padding_",
	"PTR_",
	"s_",
	"ZLB_",
)
def filterData(sym):
	if sym.label is None or sym.label == "": return False
	if sym.label == "padding": return False
	if sym.label.startswith(filterLabelPrefixes): return False
	return True

def isGenericParamName(name):
    """Check if name is a generic parameter name."""
    if name is None:
        raise ValueError("parameter name is None")
    return name.startswith('param')

def listParams(func):
    for param in func.getParameters():
        checkCanceled()
        reg = param.getRegister()
        stackOffs = None
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
        yield r


def listFuncs():
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
	for sym in filter(filterData, listing.getDefinedData(True)):
		checkCanceled()
		yield {
			"name":  str(sym.label),
			"start": addrToInt(sym.minAddress),
			"end":   addrToInt(sym.maxAddress),
			"type":  str(sym.dataType.displayName),
		}

nFuncs, nSyms = 0, 0
eRoot  = ET.Element('symbols')
eFuncs = ET.SubElement(eRoot, 'functions')
eData  = ET.SubElement(eRoot, 'data')
tree   = ET.ElementTree(eRoot)

outPath = str(askFile("Export Symbols", "Export"))

# Export functions
monitor.setMessage("Listing functions...")
# addr, size, vAddr, align, name
for func in listFuncs():
    eFunc = ET.SubElement(eFuncs, 'function', {
        'address': '0x%08X' % func['start'],
        'length':  '0x%08X' % ((func['end'] - func['start'])+1),
        'name':    func['name'],
    })
    if func['comment'] is not None:
        ET.SubElement(eFunc, 'comment').text = func['comment']
    if func['return'] is not None:
        ET.SubElement(eFunc, 'return', {'type':func['return']})
    eParams = ET.SubElement(eFunc, 'params')
    for param in func['params']:
        ET.SubElement(eParams, 'param', param)
    nFuncs += 1

# Export data
monitor.setMessage("Listing data...")
for sym in listSyms():
    eSym = ET.SubElement(eData, 'symbol', {
        'address': '0x%08X' % sym['start'],
        'length':  '0x%08X' % ((sym['end'] - sym['start'])+1),
        'name':    sym['name'],
        'type':    sym['type'],
    })
    nSyms += 1

tree.write(outPath)
print("Wrote %d functions, %d symbols" % (nFuncs, nSyms))
