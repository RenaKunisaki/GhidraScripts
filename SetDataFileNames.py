#Auto name data file buffers.
#@author Rena
#@category StarFox
#@keybinding 
#@menupath 
#@toolbar

listing = currentProgram.getListing()
AF = currentProgram.getAddressFactory()
DT = currentProgram.getDataTypeManager()
mem = currentProgram.getMemory()

def addrToInt(addr):
	return int(str(addr), 16)

def setName(fn, name):
	if fn.name == name: return
	if(fn.name.startswith("FUN_")
	or fn.name.startswith("doNothing_")):
		fn.setName(name, ghidra.program.model.symbol.SourceType.ANALYSIS)
	else:
		print("Not changing name of %s to %s" % (fn.name, name))

def handleFunc(idx, fp, name):
	if fp is None or addrToInt(fp.value) == 0: return
	fName = "file[0x%X].%s" % (idx, name)
	fn = listing.getFunctionAt(fp.value)
	if fn is None:
		#print("making function at", fp.value)
		listing.clearCodeUnits(fp.value, fp.value.add(4), False)
		createFunction(fp.value, fName)
	else: setName(fn, fName)

def handleFile(idx, obj):
	names = ["onLoad", "onUnload"]
	for i in range(2):
		fp = obj.getComponent(5+i)
		handleFunc(idx, fp, names[i])		

def fix(idx, addr):
	obj = listing.getCodeUnitAt(addr)
	if obj is None: return
	handleFile(idx, obj)
	
data = listing.getDataAt(currentAddress)
struc = data.getComponent(0).dataType.dataType
sLen = struc.getLength()

names = DT.getDataType("/DataFileEnum")
count = data.getLength() / data.getComponent(0).getLength()
for i in range(count):
	dAddr = currentAddress.add(i * 4)
	name = names.getName(i)
	if name is not None:
		# we can't label individual items in the array.
		#createLabel(dAddr, "ObjFileBuffers[%s]" % name, True)
		addr = data.getComponent(i).value
		if addrToInt(addr) != 0:
			print(addr, name)
			createLabel(addr, name, True)

