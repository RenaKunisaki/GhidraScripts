#Given pointer to struct, change destination type to that struct.
#@author Rena
#@category Struct
#@keybinding 
#@menupath 
#@toolbar 

AF = currentProgram.getAddressFactory()
listing = currentProgram.getListing()

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