#Restore labels to the ones before FID conflict bullshit
#@author Rena
#@category Functions
#@keybinding
#@menupath
#@toolbar

import jarray
import struct
AF      = currentProgram.getAddressFactory()
mem     = currentProgram.getMemory()
SymTab  = currentProgram.symbolTable
listing = currentProgram.getListing()

def addrToInt(addr):
	return int(str(addr), 16)

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

funcs = list(listing.getFunctions(True))
monitor.initialize(len(funcs))
monitor.setMessage("Fixing...")
nFuncs = 0
for func in funcs:
    history = SymTab.getLabelHistory(func.body.minAddress)
    for i, item in enumerate(history):
        if item.labelString.startswith('FID_conflict:'):
            lol = history[i-1].labelString.split(' ')[0]
            print(func, lol)
            removeLabels(func.body.minAddress, func.body.minAddress.add(3))
            func.setName(lol, ghidra.program.model.symbol.SourceType.USER_DEFINED)
            break
        elif 'FID_conflict:' in item.labelString:
            fuckMakingSense = item.labelString.split(' to ')[0]
            print(func, fuckMakingSense)
            removeLabels(func.body.minAddress, func.body.minAddress.add(3))
            func.setName(fuckMakingSense, ghidra.program.model.symbol.SourceType.USER_DEFINED)
            break
	nFuncs += 1
    monitor.checkCanceled()
    monitor.incrementProgress(1)
print("Checked %d functions" % nFuncs)
