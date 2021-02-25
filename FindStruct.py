#Find structs by field type.
#@author Rena
#@category Struct
#@keybinding
#@menupath
#@toolbar

StringColumnDisplay  = ghidra.app.tablechooser.StringColumnDisplay
AddressableRowObject = ghidra.app.tablechooser.AddressableRowObject
TableChooserExecutor = ghidra.app.tablechooser.TableChooserExecutor
DTM = state.tool.getService(ghidra.app.services.DataTypeManagerService)
AF      = currentProgram.getAddressFactory()
DT      = currentProgram.getDataTypeManager()
listing = currentProgram.getListing()
mem     = currentProgram.getMemory()

def addrToInt(addr):
	return int(str(addr), 16)

def intToAddr(addr):
	return AF.getAddress("0x%08X" % addr)


class Executor(TableChooserExecutor):
    def getButtonName(self):
        return "Edit Structure"

    def execute(self, row):
        DTM.edit(row.struc) # show the structure editor
        return False # do not remove row


class StructNameColumn(StringColumnDisplay):
    def getColumnName(self):
        return "Struct Name"

    def getColumnValue(self, row):
        return row.struc.displayName

class StructLengthColumn(StringColumnDisplay):
    def getColumnName(self):
        return "Struct Size"

    def getColumnValue(self, row):
        return row.struc.length


class StructListResult(AddressableRowObject):
    def __init__(self, struc):
        self.struc = struc

    def getAddress(self):
        return intToAddr(self.struc.length)


def run():
    # XXX find a way to make this UI better.
    # criteria is eg:
    # B8=*int   (a struct with an int* at 0xB8)
    # B8=*      (a struct with any pointer at 0xB8)
    # B8=2      (a struct with any field at 0xB8 with length 2)
    # B8=*2     (a struct with a pointer at 0xB8 to something with length 2)
    # B8        (a struct with any field starting at 0xB8)
    params = askString("Find Struct", "Enter search criteria")
    params = params.split(';')

    monitor.initialize(len(params))
    candidates = list(DT.allStructures)


    def showResults():
        executor = Executor()
        tbl = createTableChooserDialog("Matching Structs", executor)
        tbl.addCustomColumn(StructNameColumn())
        tbl.addCustomColumn(StructLengthColumn())
        #printf("show %d results\n", len(candidates))
        for res in candidates:
            #printf("%s\n", res.displayName)
            tbl.add(StructListResult(res))
        tbl.show()
        tbl.setMessage("%d results" % len(candidates))


    def removeResult(struc):
        candidates.remove(struc)
        #print("remove", struc.name, "#res", len(candidates))


    def checkComponent(struc, comp, offset, typ):
        # return True if match, False if not.

        # does component match given offset/type?
        if comp.offset != offset: return False
        if typ is None: return True # match any type at this offset

        # if this is a pointer, walk the dataType chain
        # to reach the base type
        tp = typ
        dt = comp.dataType
        while tp.startswith('*'):
            if (not hasattr(dt, 'dataType')) or dt.dataType is None:
                #printf("[X] %s.%s @%X type is %s\n", struc.name,
                #    comp.fieldName, offset, str(getattr(dt, 'dataType')))
                return False
            dt = dt.dataType
            tp = tp[1:]

        # check the name
        # remove spaces for simplicity
        tp = tp.replace(' ', '')
        nm = dt.name.replace(' ', '')
        if tp.isnumeric():
            #printf("[%s] %s.%s @%X size is %d\n",
            #    "O" if dt.length == int(tp) else "X",
            #    struc.name, comp.fieldName, offset, dt.length)
            if dt.length == int(tp):
                return True
        else:
            #printf("[%s] %s.%s @%X type is %d\n",
            #    "O" if nm == tp else "X",
            #    struc.name, comp.fieldName, offset, dt.length)
            if nm == tp:
                return True

        #comp.dataType.name, numElements, elementLength, length, dataType
        #comp.fieldName, comment, endOffset, bitFieldComponent, dataType, length, offset, ordinal

        return False


    def evaluateParam(param):
        param  = param.split('=')
        offset = int(param[0], 16)
        if len(param) < 2:
            # no type given - find any struct which has a field
            # beginning at this offset.
            typ = None
        else:
            # user specified a type for the field
            typ = param[1]

        #printf("Evaluate '%s', #res=%d\n", param, len(candidates))
        remove = []
        for struc in candidates:
            monitor.checkCanceled()
            #monitor.incrementProgress(1)
            #monitor.setMessage("Checking %s" % struc.displayName)
            #print("check", struc.displayName)

            match = False
            for comp in struc.components:
                if checkComponent(struc, comp, offset, typ):
                    match = True
                    break
            if not match: remove.append(struc)
        for struc in remove: removeResult(struc)
        #printf("Evaluated '%s', #res=%d\n", param, len(candidates))


    for param in params:
        monitor.checkCanceled()
        monitor.incrementProgress(1)
        monitor.setMessage("Checking %s" % param)
        evaluateParam(param)
        if len(candidates) == 0: break

    #popup("Found %d matches (see console)" % len(candidates))
    showResults()

run()
