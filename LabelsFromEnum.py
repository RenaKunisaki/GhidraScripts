#Assign labels to selection from an enum.
#@author Rena
#@category Data
#@keybinding
#@menupath
#@toolbar

DT = currentProgram.getDataTypeManager()
listing = currentProgram.getListing()
mem = currentProgram.getMemory()
SYM_USER_DEFINED = ghidra.program.model.symbol.SourceType.USER_DEFINED

def addrToInt(addr):
	return int(str(addr), 16)

def intToAddr(addr):
	return AF.getAddress("0x%08X" % addr)

if currentSelection is None:
	startAddr = currentAddress
	endAddr = currentAddress
else:
	startAddr = currentSelection.getMinAddress()
	endAddr = currentSelection.getMaxAddress()

data = listing.getDataContaining(startAddr)
if data.isArray():
	struc = data.getComponent(0)
else:
	struc = data

sLen = struc.getLength()
#print("type is", dt, "len", sLen)

enumName = askString("Assign Labels from Enum", "Enter enum name")
prefix   = askString("Assign Labels from Enum", "Enter prefix")
whichEnum = getDataTypes(enumName)[0]

def setLabel(addr, val):
    name = whichEnum.getName(val)
    if name is not None:
        createLabel(addr, prefix + name, True, SYM_USER_DEFINED)

def run():
    addr = startAddr
    if data.isArray():
        count = data.getLength() / data.getComponent(0).getLength()
        for i in range(count):
            setLabel(addr, i)
            addr = addr.add(sLen)
    else:
        for i in range(whichEnum.getCount()):
            setLabel(addr, i)
            addr = addr.add(sLen)

run()
