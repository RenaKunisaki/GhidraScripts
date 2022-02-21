#Convert selection to floats and label them with their values.
#@author Rena
#@category Data
#@keybinding
#@menupath
#@toolbar

import math
AF      = currentProgram.getAddressFactory()
DT      = currentProgram.getDataTypeManager()
listing = currentProgram.getListing()
mem     = currentProgram.getMemory()
dt_float = DT.getDataType('/float')
SYM_USER_DEFINED = ghidra.program.model.symbol.SourceType.USER_DEFINED

def addrToInt(addr):
	return int(str(addr), 16)

def intToAddr(addr):
	return AF.getAddress("0x%08X" % addr)


if currentSelection is None:
	startAddr = currentAddress
	endAddr = currentAddress.add(3)
else:
	startAddr = currentSelection.getMinAddress()
	endAddr = currentSelection.getMaxAddress()
data = listing.getDataContaining(startAddr)


def processAddr(addr):
    A = intToAddr(addr)
    #printf("%08X: check\n", addr)

    # check if already a higher-priority label here
    unit = listing.getCodeUnitAt(A)
    if unit:
        syms = unit.getSymbols()
        for sym in syms:
            #print("found sym", sym)
            if not sym.source.isLowerPriorityThan(SYM_USER_DEFINED):
                printf("%08X: already have label %s\n", addr, sym)
                return

        if unit.baseDataType.name not in (
            'undefined', 'undefined4', 'float'):
            printf("%08X: already have type %s\n", addr, unit.baseDataType.name)
            return # already another type

        # make it a float
        listing.clearCodeUnits(A, A.add(3), False)
        listing.createData(A, dt_float)

    val = listing.getDataAt(A)
    if val is not None: val = val.value
    if type(val) is not float:
        printf("%08X: value type %s: %s\n", addr, type(val).__name__, val)
        return # some non-float here

    if   math.isnan(val):
        printf("%08X: value is NaN\n", addr)
        # XXX undo converting it
        return # probably not a float
    elif math.isinf(val): sVal = 'infinity'
    elif val >= 340282346638528859811704183484516925440: sVal = 'infinity'
    elif val <= -340282346638528859811704183484516925440: sVal = 'mInfinity'
    elif ((abs(val) < 0.000000001 and abs(val) > 0)
    or     abs(val) > 562949953421312):
        printf("%08X: value is %s, probably not float\n", addr, val)
        # XXX undo converting it
        return # probably not a float
    elif val >=  3.14  and val <= 3.15:  sVal = 'pi'
    elif val >=  6.28  and val <= 6.29:  sVal = 'twoPi'
    elif val >=  0.017 and val <= 0.018: sVal = 'piOver180'
    elif val ==  0.5: sVal = 'half'
    elif val ==  1:   sVal = 'one'
    elif val ==  0:   sVal = 'zero'
    #elif val == -1:   sVal = 'minusOne'
    else:
        # format nicely, eg -12000.345 => m12kp345
        intr, frac = ('%1.4f' % val).split('.')
        #print(val, intr, frac)
        iVal = abs(int(intr))
        #if   iVal >= 1000000: intr = str(iVal // 1000000)+'m'
        #elif iVal >=    1000: intr = str(iVal // 1000)+'k'
        intr = intr.replace('-', 'm')
        while frac.endswith('0'): frac = frac[:-1]
        if    frac in ('0', ''): frac = ''
        else: frac = 'p' + frac
        sVal = 'f_' + intr + frac

    printf("%08X: value = %s => %s\n", addr, val, sVal)
    createLabel(A, sVal, True, SYM_USER_DEFINED)


def run():
    incr = data.getLength()
    for addr in range(addrToInt(startAddr), addrToInt(endAddr), incr):
        processAddr(addr)


run()
