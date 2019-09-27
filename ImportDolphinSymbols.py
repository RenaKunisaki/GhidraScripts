#Import .map file from Dolphin generated symbols
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


def setName(fn, name, aObj):
	if fn.name == name: return
	if(fn.name.startswith("FUN_")
	or fn.name.startswith("doNothing_")):
		fn.setName(name, ghidra.program.model.symbol.SourceType.IMPORTED)
	else:
		createLabel(aObj, fn.name, False)
		fn.setName(name, ghidra.program.model.symbol.SourceType.IMPORTED)
		#print("Not changing name of %s to %s" % (fn.name, name))

def handleSym(addr, sym):
	aObj = intToAddr(addr)
	fn = listing.getFunctionAt(aObj)
	if fn is None:
		#print("making function at", addr)
		listing.clearCodeUnits(aObj, aObj.add(4), False)
		createFunction(aObj, sym['name'])
	else: setName(fn, sym['name'], aObj)

def parseLine(line, syms):
	addr, size, vAddr, align, name = line.strip().split(' ')
	if not name.startswith("zz_"):
		addr  = int(addr,  16)
		size  = int(size,  16)
		vAddr = int(vAddr, 16)
		align = int(align, 16)
		syms[addr] = {
			'name':name,
			'size':size,
			'vAddr':vAddr,
			'align':align,
		}


def parseMapFile(inFile):
	syms = {}
	for line in inFile:
		try: parseLine(line, syms)
		except ValueError: pass
	return syms

path = str(askFile("Import Symbol Map", "Import"))
with open(path, "rt") as file:
	syms = parseMapFile(file)

for addr, sym in syms.items():
	handleSym(addr, sym)
