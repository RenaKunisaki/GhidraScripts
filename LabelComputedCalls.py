#Add comment showing destination of computed jumps.
#@author Rena
#@category GameCube/Wii
#@keybinding
#@menupath
#@toolbar

listing = currentProgram.getListing()
AF      = currentProgram.getAddressFactory()
mem     = currentProgram.getMemory()

def addrToInt(addr):
    """Convert Address to integer."""
    return int(str(addr), 16)

def intToAddr(addr):
    """Convert integer to Address."""
    return AF.getAddress("0x%08X" % addr)

def run():
    if currentSelection is None:
    	blk = mem.getBlock(currentAddress)
    	startAddr = blk.getStart()
    	endAddr   = blk.getEnd()
    else:
    	startAddr = currentSelection.getMinAddress()
    	endAddr   = currentSelection.getMaxAddress()

    iStart = addrToInt(startAddr)
    iEnd   = addrToInt(endAddr)
    monitor.initialize(iEnd-iStart)
    addressSetView = AF.getAddressSet(startAddr, endAddr)

    for i, instr in enumerate(listing.getInstructions(addressSetView, True)):
        addr = instr.address
        if (i & 0xFFF) == 0 and i > 0:
            monitor.checkCanceled()
            monitor.incrementProgress(0x1000)
            monitor.setMessage("Scanning... %08X" % addrToInt(addr))
        if instr.getFlowType().isComputed():
            flows = instr.getFlows()
            if len(flows) > 0:
                comment = "{@symbol %x}" % addrToInt(flows[0])
                if getEOLComment(addr) is None: setEOLComment(addr, comment)
                if getPreComment(addr) == comment: setPreComment(addr, None)

start()
run()
end(True)
