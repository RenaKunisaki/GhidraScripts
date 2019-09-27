#Set ObjectFileStruct's label to the object's name.
#@author Rena
#@category Struct
#@keybinding 
#@menupath 
#@toolbar 

import jarray

AF = currentProgram.getAddressFactory()
listing = currentProgram.getListing()
mem = currentProgram.getMemory()

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
if not struc.isPointer():
	raise "Select a POINTER to a struct!"
struc = struc.dataType.dataType
#struc = currentProgram.getDataTypeManager().getDataType("/auto_structs/FileStruct")
sLen = struc.getLength()
#print("Struct is", struc)


numFixed, numFailed = 0, 0
def fix(addr):
	global numFixed
	global numFailed
	if addrToInt(addr) == 0: return
	#print("Fixing", addr)
	try:
		listing.clearCodeUnits(addr, addr.add(sLen), False)
		listing.createData(addr, struc)

		# get name
		data = jarray.zeros(13, "b")
		mem.getBytes(addr.add(0x91), data)
		name = ""
		for i, b in enumerate(data):
			if b == 0: break
			if b < 0 or b > 255:
				print("WTF this name has", b, "in it at", i)
				#break
			if b >= 0x20 and b <= 0x7E:
				name += chr(b)
		
		if name != "":
			createLabel(addr, "ObjFileStruct_%s" % name, True)
		numFixed += 1
	except ghidra.program.model.util.CodeUnitInsertionException:
		#print("Failed", addr)
		numFailed += 1

print("Data is:", data)
if data.isArray():
	count = data.getLength() / data.getComponent(0).getLength()
	for i in range(count):
		fix(data.getComponent(i).value)
		
else:
	AF = currentProgram.getAddressFactory()
	incr = data.getLength()
	for addr in range(addrToInt(startAddr), addrToInt(endAddr), incr):
		fix(listing.getDataAt(AF.getAddress(hex(addr)).value))

print("Fixed %d, failed to fix %d" % (numFixed, numFailed))