#Scan memory and find pointers to existing labels.
#@author Rena
#@category Data
#@keybinding 
#@menupath 
#@toolbar 

import jarray
from array import array
listing = currentProgram.getListing()
AF = currentProgram.getAddressFactory()
DT = currentProgram.getDataTypeManager()
mem = currentProgram.getMemory()
tPtr = currentProgram.getDataTypeManager().getDataType("/pointer")

def addrToInt(addr):
	return int(str(addr), 16)

def intToAddr(addr):
	return AF.getAddress("0x%08X" % addr)

def readAddr(addr):
	arr = jarray.zeros(4, "b")
	mem.getBytes(addr, arr)
	v = (((arr[0] & 0xFF) << 24) |
		((arr[1] & 0xFF) << 16) |
		((arr[2] & 0xFF) << 8) |
		(arr[3] & 0xFF))
	return intToAddr(v)


if currentSelection is None:
	blk = mem.getBlock(currentAddress)
	startAddr = blk.getStart()
	endAddr = blk.getEnd()
else:
	startAddr = currentSelection.getMinAddress()
	endAddr = currentSelection.getMaxAddress()

iStart = addrToInt(startAddr)
iEnd = addrToInt(endAddr)
monitor.initialize(iEnd-iStart)
monitor.setMessage("Scanning...")

addr = iStart
while addr < iEnd: # lol range() is broken
	if addr & 0xFFF == 0:
		monitor.checkCanceled()
		monitor.incrementProgress(0x1000)
		monitor.setMessage("Scanning... %08X" % addr)
	addrObj = intToAddr(addr)
	val = readAddr(addrObj)
	dat = listing.getCodeUnitAt(val)
	#printf("%08X %08X %s\n", addr, addrToInt(val), str(dat))
	lbl = dat.getLabel() if dat else None
	if lbl is not None:
		printf("%08X %08X -> %s: ", addr, addrToInt(val), lbl)
		try:
			listing.createData(addrObj, tPtr, 1)
			printf("OK\n")
		except ghidra.program.model.util.CodeUnitInsertionException:
			# creating a pointer here conflicts with what's already here.
			printf("Failed\n")
	addr += 4
	
