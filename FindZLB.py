#Find all ZLB archives in file.
#@author Rena
#@category StarFox
#@keybinding 
#@menupath 
#@toolbar 

numFound = 0

AF = currentProgram.getAddressFactory()
listing = currentProgram.getListing()
mem = currentProgram.getMemory()
struc = currentProgram.getDataTypeManager().getDataType("/ZlbHeader")
tByte = currentProgram.getDataTypeManager().getDataType("/byte")
sLen = struc.getLength()

def addrToInt(addr):
	return int(str(addr), 16)

def intToAddr(addr):
	return AF.getAddress("0x%08X" % addr)

def createZlb(addr):
	try:
		# create the header struct
		addrObj = intToAddr(addr)
		listing.clearCodeUnits(addrObj, addrObj.add(sLen), False)
		listing.createData(addrObj, struc)

		# read it
		version = mem.getInt(addrObj.add(4))
		decLen = mem.getInt(addrObj.add(8))
		compLen = mem.getInt(addrObj.add(12))

		# XXX handle version == "DIR\0"

		# create the data array
		# XXX why doesn't this make an actual array?
		listing.createData(addrObj.add(16), tByte, compLen)

		# add a comment
		codeUnit = listing.getDataAt(addrObj)
		codeUnit.setComment(codeUnit.PLATE_COMMENT,
			"ZLB v0x%X - raw size=0x%X compressed=0x%X" % (
			version, decLen, compLen))

		# add a label
		createLabel(addrObj, "ZLB_%08X" % addr, False)
		
	except ghidra.program.model.util.CodeUnitInsertionException:
		print("Failed to create ZlbHeader at 0x%08X" % addr)

for memRange in list(mem.getAddressRanges()):
	aStart = addrToInt(memRange.getMinAddress())
	aEnd   = addrToInt(memRange.getMaxAddress())
	monitor.initialize(aEnd-aStart)
	print("Scanning 0x%08X - 0x%08X; Found %d so far" % (aStart, aEnd, numFound))
	for addr in range(aStart, aEnd, 4):
		if addr & 0xFFF == 0:
			monitor.checkCanceled()
			monitor.incrementProgress(0x1000)
			monitor.setMessage("Checking 0x%08X; Found %d so far" % (addr, numFound))
		try:
			val = mem.getInt(intToAddr(addr))
		except (java.lang.NullPointerException, ghidra.program.model.mem.MemoryAccessException):
			break

		if val == 0x5a4c4200: #"ZLB\0"
			numFound = numFound + 1
			print("Found ZLB at 0x%08X" % addr)
			createZlb(addr)

print("Found %d archives." % numFound)
