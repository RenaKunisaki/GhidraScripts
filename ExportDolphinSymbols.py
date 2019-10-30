#Export a .map file that Dolphin can read.
#@author Rena
#@category GameCube/Wii
#@keybinding 
#@menupath 
#@toolbar 

AF = currentProgram.getAddressFactory()
listing = currentProgram.getListing()

def addrToInt(addr):
	return int(str(addr), 16)

def intToAddr(addr):
	return AF.getAddress("0x%08X" % addr)

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

def listFuncs():
	for func in filter(filterFunc, listing.getFunctions(True)):
		if monitor.isCancelled(): raise "Cancelled"
		yield {
			"start": addrToInt(func.body.minAddress),
			"end":   addrToInt(func.body.maxAddress),
			"proto": str(func.signature.prototypeString),
			"name":  str(func.name),
		}

def listSyms():
	for sym in filter(filterData, listing.getDefinedData(True)):
		if monitor.isCancelled(): raise "Cancelled"
		yield {
			"name":  str(sym.label),
			"start": addrToInt(sym.minAddress),
			"end":   addrToInt(sym.maxAddress),
			"type":  str(sym.dataType.displayName),
		}

path = str(askFile("Export Symbol Map", "Export"))
nFuncs, nSyms = 0, 0
with open(path, "wt") as file:
	monitor.setMessage("Listing functions...")
	file.write(".text\n")
	# addr, size, vAddr, align, name
	for func in listFuncs():
		# latest version seems to reject symbols > 4 bytes
		file.write("%08X %08X %08X 0 %s\n" % (
			func['start'],
			4, #func['end'] - func['start'],
			func['start'],
			func['name'],
			#func['proto'],
		))
		nFuncs += 1
	monitor.setMessage("Listing data...")
	for sym in listSyms():
		file.write("%08X %08X %08X 0 %s\n" % (
			sym['start'],
			0, #sym['end'] - sym['start'],
			sym['start'],
			sym['name'],
		))
		nSyms += 1

	
print("Wrote %d functions, %d symbols" % (nFuncs, nSyms))
