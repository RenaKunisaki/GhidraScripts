#Follow GameText array and auto assign names and enums
#@author 
#@category StarFox
#@keybinding 
#@menupath 
#@toolbar 

import jarray
from array import array
import re
listing = currentProgram.getListing()
AF = currentProgram.getAddressFactory()
DT = currentProgram.getDataTypeManager()
mem = currentProgram.getMemory()

reEnumName = re.compile(r'[^a-zA-Z0-9_]+')

def addrToInt(addr):
	return int(str(addr), 16)

def intToAddr(addr):
	return AF.getAddress("0x%08X" % addr)

def createEnum(name, values, size=None):
	if name is None: name = "autoEnum"
	if size is None:
		size = 1
		if len(values) > 0xFFFF: size = 4
		elif len(values) > 0xFF: size = 2
	enum = ghidra.program.model.data.EnumDataType(name, size)
	for name, val in values.items():
		name = reEnumName.sub('', name)
		while True:
			try:
				enum.add(name, val)
				break
			except java.lang.IllegalArgumentException:
				name = "%s_%X" % (name, val)
	DT.addDataType(enum, ghidra.program.model.data.DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER)
	return enum

def readAddr(addr):
	arr = jarray.zeros(4, "b")
	mem.getBytes(addr, arr)
	v = (((arr[0] & 0xFF) << 24) |
		((arr[1] & 0xFF) << 16) |
		((arr[2] & 0xFF) << 8) |
		(arr[3] & 0xFF))
	return intToAddr(v)

def readString(addr):
	if type(addr) is int:
		addr = intToAddr(addr)
	
	data = []
	while True:
		try:
			b = mem.getByte(addr)
		except ghidra.program.model.mem.MemoryAccessException:
			printf("Error: can't read string from address 0x%X\n", addrToInt(addr))
			b = 0
		if b == 0: break
		elif b < 0x7F:
			data.append(b & 0xFF)
		addr = addr.add(1)
	a = array('B', data)
	return a.tostring()#.decode('shift-jis')

data = listing.getDataAt(currentAddress)
struc = data.getComponent(0).dataType
sLen = struc.getLength()

numTexts = data.length / sLen
texts = {}
for i in range(numTexts):
	entry      = data.getComponent(i)
	id         = entry.getComponent(0).value.value
	numPhrases = entry.getComponent(1).value.value
	#language   = entry.getComponent(5).value.value
	phrases    = entry.getComponent(6)
	strs       = []
	for j in range(numPhrases):
		res = readString(readAddr(phrases.value.add(j*4)))
		strs.append(res)

	text = '_'.join(filter(lambda s: s != "" and not s.isspace(), strs))
	label = text.replace(' ', '_')

	# add a comment
	entry.setComment(entry.EOL_COMMENT,
		"[%04X] %s" % (id, '\n'.join(strs)))

	# add a label
	try:
		createLabel(phrases.value, "GameText%04X_%s" % (id, label, False))
	except:
		pass # probably invalid characters

	texts["%04X_%s" % (id, label)] = id
	printf("%04X: %s\n", id, text)
	
createEnum("GameTextId", texts)
createEnum("GameTextId32", texts, 4)
