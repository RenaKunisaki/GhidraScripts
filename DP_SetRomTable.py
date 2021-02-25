#Set Dino Planet ROM table pointers.
#@author
#@category StarFox
#@keybinding
#@menupath
#@toolbar
from ghidra.program.model.listing import ParameterImpl
from ghidra.program.model.symbol import SourceType

TABLE_ADDR = 0xb00a4970
TABLE_SIZE = 76
FILE_BASE  = TABLE_ADDR + (TABLE_SIZE * 4)

FILE_IDS = {
    0x24: 'TEX1_BIN',
    0x27: 'TEX0_BIN',
    0x33: 'ANIM_TAB',
    0x34: 'ANIM_BIN',
    0x46: 'DLLS_BIN',
}

AF = currentProgram.getAddressFactory()
listing = currentProgram.getListing()

def removeLabels(addrStart, addrEnd):
    addressSetView = AF.getAddressSet(addrStart, addrEnd)
    clearListing(addressSetView,
        False, #code
        True,  #symbols
        False, #comments
        False, #properties
        False, #functions
        False, #registers
        False, #equates
        False, #userReferences
        False, #analysisReferences
        False, #importReferences
        False, #defaultReferences
        False) #bookmarks

def addrToInt(addr):
	return int(str(addr), 16)

def intToAddr(addr):
	return AF.getAddress("0x%08X" % addr)

table = listing.getDataAt(intToAddr(TABLE_ADDR))
for i in range(1, TABLE_SIZE):
    offs = addrToInt(table.getComponent(i).value) + FILE_BASE
    name = FILE_IDS.get(i-1, 'FILE_%02X' % (i-1))
    addr = intToAddr(offs)
    removeLabels(addr, addr.add(3))
    createLabel(addr, 'ROM_'+name, False)
