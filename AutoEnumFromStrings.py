#Automatically generate an enum from a string pointer table.
#@author Rena
#@category Data
#@keybinding 
#@menupath 
#@toolbar 

class SelectionError(BaseException):
	pass

DT = currentProgram.getDataTypeManager()
listing = currentProgram.getListing()
mem = currentProgram.getMemory()

def addrToInt(addr):
	return int(str(addr), 16)

def intToAddr(addr):
	return AF.getAddress("0x%08X" % addr)

def createEnum(name, values):
	if name is None: name = "autoEnum"
	size = 1
	if len(values) > 0xFFFF: size = 4
	elif len(values) > 0xFF: size = 2
	enum = ghidra.program.model.data.EnumDataType(name, size)
	for name, val in values.items():
		enum.add(name, val)
	DT.addDataType(enum, ghidra.program.model.data.DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER)
	return enum

def readString(addr, length=None):
	if type(addr) is int:
		addr = intToAddr(addr)
	resLen = 0
	if length is not None:
		data = jarray.zeros(length, "b")
		mem.getBytes(addr, data)
		resLen = length
	else:
		data = []
		while True:
			resLen += 1
			b = mem.getByte(addr)
			if b == 0: break
			data.append(b)
			addr = addr.add(1)
	return "".join(map(lambda c: chr(c) if c >= 0x20 and c <= 0x7E else '', data)), resLen
	
	
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

if struc.isPointer(): # array of char*
	dt = struc.dataType.dataType
else: # array of strings
	dt = struc.dataType

if dt.name != "string" and dt.name != "char":
	raise SelectionError("Select a string or char*")

sLen = struc.getLength()
#print("type is", dt, "len", sLen)

values = {}
def addStr(name, val):
	while name in values:
		name += "_%02X" % val
	values[name] = val

def run():
	if data.isArray():
		count = data.getLength() / data.getComponent(0).getLength()
		for i in range(count):
			addr = data.getComponent(i).value
			s, _ = readString(addr)
			addStr(s, i)
	else:
		addr = startAddr
		idx = 0
		while addr < endAddr:
			s, l = readString(addr)
			if s != "":
				addStr(s, idx)
				idx += 1
			addr = addr.add(l)

	if len(values) == 0:
		raise SelectionError("No strings here. Select a range of strings or an array of string pointers.")
	else:
		enum = createEnum(None, values)
		printf("Created enum '%s' with %d values.\n", enum.name, len(values))

try:
	run()
except SelectionError as ex:
	printerr(ex)

