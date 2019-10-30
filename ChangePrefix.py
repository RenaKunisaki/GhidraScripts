#Rename a symbol while keeping the address suffix.
#@author Rena
#@category Symbol
#@keybinding 
#@menupath 
#@toolbar 

AF = currentProgram.getAddressFactory()
listing = currentProgram.getListing()
mem = currentProgram.getMemory()

def addrToInt(addr):
	return int(str(addr), 16)

def intToAddr(addr):
	return AF.getAddress("0x%08X" % addr)

def run():
	addr = currentAddress
	name = askString("Change Prefix", "Enter label for %x:" % addrToInt(addr))
	if name is None: return
	createLabel(addr, "%s_%08x" % (name, addrToInt(addr)), True, ghidra.program.model.symbol.SourceType.USER_DEFINED)

run()