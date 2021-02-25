#Find functions that consist only of a return. Only supports PowerPC.
#@author Rena
#@category Functions
#@keybinding
#@menupath
#@toolbar

import jarray
import struct
mem = currentProgram.getMemory()
listing = currentProgram.getListing()

def addrToInt(addr):
	return int(str(addr), 16)


nFuncs = 0
for func in listing.getFunctions(True):
	body = func.body
	name = None
	if body.numAddresses in (1, 4):
		data = jarray.zeros(4, "b")
		mem.getBytes(body.minAddress, data)
		op = struct.unpack('>I', data)[0] # grumble
		if op == 0x4E800020: # blr
			name = "nop_%08X" % addrToInt(body.minAddress)
	elif body.numAddresses in (2, 8):
		data = jarray.zeros(8, "b")
		mem.getBytes(body.minAddress, data)
		ops = struct.unpack('>2I', data)
		if (ops[0] & 0xFFFF0000 == 0x38600000 # li r3, xxxx
		and ops[1] == 0x4E800020): # blr
			val = ops[0] & 0xFFFF
			if val > 9: name = "ret0x%X" % val
			else: name = "ret%d" % val
			name += "_%08X" % addrToInt(body.minAddress)
	if name is not None:
		#print("%08X %s" % (addrToInt(body.minAddress), name))
		func.setName(name, ghidra.program.model.symbol.SourceType.ANALYSIS)
	nFuncs += 1
print("Checked %d functions" % nFuncs)
