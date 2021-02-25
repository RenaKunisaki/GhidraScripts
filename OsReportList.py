#Create a list of OSReport calls.
#@author
#@category GameCube/Wii
#@keybinding
#@menupath
#@toolbar

import jarray
from array import array
#from ghidra.app.decompiler import DecompInterface
#from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.plugin.core.analysis import AutoAnalysisManager
from ghidra.app.plugin.core.analysis import ConstantPropagationAnalyzer
from ghidra.util.classfinder import ClassSearcher
from ghidra.program.util import SymbolicPropogator
listing = currentProgram.getListing()
AF      = currentProgram.getAddressFactory()
DT      = currentProgram.getDataTypeManager()
FM      = currentProgram.getFunctionManager()
mem     = currentProgram.getMemory()
tPtr    = currentProgram.getDataTypeManager().getDataType("/pointer")
StringColumnDisplay  = ghidra.app.tablechooser.StringColumnDisplay
AddressableRowObject = ghidra.app.tablechooser.AddressableRowObject
TableChooserExecutor = ghidra.app.tablechooser.TableChooserExecutor

#ifc = DecompInterface()
#ifc.openProgram(currentProgram)

targetNames = {}
def regTarget(name, rMsg=None, rFile=None, rLine=None, rFunc=None):
    """Register a target function.

    name:  function name.
    rMsg:  register containing format string or message.
    rFile: register containing file name.
    rLine: register containing line number.
    rFunc: register containing function name.
    """
    targetNames[name.lower()] = {
        'rMsg':  rMsg,
        'rFile': rFile,
        'rLine': rLine,
        'rFunc': rFunc,
    }

regTarget('debugprint',    rMsg=3)
regTarget('debugprintf',   rMsg=3)
regTarget('debugprintfxy', rMsg=5)
regTarget('debugprintxy',  rMsg=5)
regTarget('diprintf',      rMsg=3)
regTarget('logprintf',     rMsg=3)
regTarget('ospanic',       rFile=3, rLine=4, rMsg=5)
regTarget('osreport',      rMsg=3)
regTarget('panic')
regTarget('printf',        rMsg=3)
regTarget('reportexception')


class Executor(TableChooserExecutor):
    def getButtonName(self):
        return "Do a Thing"

    def execute(self, row):
        return False # do not remove row


class FuncNameColumn(StringColumnDisplay):
    def getColumnName(self):
        return "Func Name"

    def getColumnValue(self, row):
        return row.result['funcname']

class FunctionColumn(StringColumnDisplay):
    def getColumnName(self):
        return "Function"

    def getColumnValue(self, row):
        return row.result['function']

class FileColumn(StringColumnDisplay):
    def getColumnName(self):
        return "File"

    def getColumnValue(self, row):
        return row.result['file']

class LineColumn(StringColumnDisplay):
    def getColumnName(self):
        return "Line"

    def getColumnValue(self, row):
        return row.result['line']

class CallColumn(StringColumnDisplay):
    def getColumnName(self):
        return "Call"

    def getColumnValue(self, row):
        return row.result['call']

class MessageColumn(StringColumnDisplay):
    def getColumnName(self):
        return "Message"

    def getColumnValue(self, row):
        return row.result['message']


class PrintListResult(AddressableRowObject):
    def __init__(self, result):
        self.result = result

    def getAddress(self):
        return intToAddr(self.result['address'])

def makeDialog():
    executor = Executor()
    tbl = createTableChooserDialog("Print calls", executor)
    tbl.addCustomColumn(FileColumn())
    tbl.addCustomColumn(LineColumn())
    tbl.addCustomColumn(FuncNameColumn())
    tbl.addCustomColumn(FunctionColumn())
    tbl.addCustomColumn(CallColumn())
    tbl.addCustomColumn(MessageColumn())
    tbl.show()
    tbl.setMessage("Running...")
    return tbl


def addrToInt(addr):
    """Convert Address to integer."""
    return int(str(addr), 16)

def intToAddr(addr):
    """Convert integer to Address."""
    return AF.getAddress("0x%08X" % addr)

def readAddr(addr):
    """Read 4 bytes from address."""
    arr = jarray.zeros(4, "b")
    mem.getBytes(addr, arr)
    v = (((arr[0] & 0xFF) << 24) |
        ((arr[1] & 0xFF) << 16) |
        ((arr[2] & 0xFF) << 8) |
        (arr[3] & 0xFF))
    return intToAddr(v)

def readString(addr, length=None, maxLength=1000):
    """Read null-terminated or fixed-length string from address.

    Return string and length.
    """
    if type(addr) is int:
        addr = intToAddr(addr)
    resLen = 0
    if length is not None:
        data = jarray.zeros(length, "b")
        mem.getBytes(addr, data)
        resLen = length
    else:
        data = []
        while len(data) < maxLength:
            resLen += 1
            try: b = mem.getByte(addr)
            except ghidra.program.model.mem.MemoryAccessException: break
            if b == 0: break
            data.append(b)
            addr = addr.add(1)
    return "".join(map(lambda c: chr(c) if c >= 0x20 and c <= 0x7E else '', data)), resLen

def getConstantAnalyzer(program):
    mgr = AutoAnalysisManager.getAnalysisManager(program)
    analyzers = ClassSearcher.getInstances(ConstantPropagationAnalyzer)
    for analyzer in analyzers:
        if analyzer.canAnalyze(program):
            return mgr.getAnalyzer(analyzer.getName())
    return None

def analyzeFunction(function, monitor):
    program = function.getProgram()
    analyzer = getConstantAnalyzer(program)
    symEval = SymbolicPropogator(program)
    symEval.setParamRefCheck (True)
    symEval.setReturnRefCheck(True)
    symEval.setStoredRefCheck(True)
    analyzer.flowConstants(program, function.getEntryPoint(), function.getBody(),
        symEval, monitor)
    return symEval

def movePastDelaySlot(addr):
    inst = getInstructionAt(addr)
    if inst.getDelaySlotDepth() > 0:
        while True:
            inst = inst.getNext()
            if not inst.isInDelaySlot(): break
    return inst.getAddress()


def getMsg(prop, nextAddr, instr, reg=3):
    while reg < 12:
        val = prop.getRegisterValue(nextAddr, instr.getRegister('r%d' % reg))
        if val is not None:
            val = val.getValue()
            s, l = readString(intToAddr(val), maxLength=256)
            if l > 2: return s
        reg += 1
    return '<unknown>'



def logFunc(instr, addr, name, monitor, tbl):
    #results = ifc.decompileFunction(instr, 0, ConsoleTaskMonitor())
    #print(results.getDecompiledFunction().getC())

    func = FM.getFunctionContaining(addr)
    if func is None:
        tbl.add(PrintListResult({
            'address':  addrToInt(addr),
            'file':     '',
            'line':     '',
            'funcname': '',
            'function': '(none)',
            'call':     name,
            'message':  '',
        }))
        return
    prop = analyzeFunction(func, monitor)
    nextAddr = movePastDelaySlot(addr)

    targetFunc = targetNames[name.lower()]
    rMsg  = targetFunc['rMsg']
    rFile = targetFunc['rFile']
    rLine = targetFunc['rLine']
    rFunc = targetFunc['rFunc']

    msg = getMsg(prop, nextAddr, instr, rMsg)

    if rFile is not None: fileName = getMsg(prop, nextAddr, instr, rFile)
    else: fileName = ''
    if rFunc is not None: funcName = getMsg(prop, nextAddr, instr, rFunc)
    else: funcName = ''
    lineNo = ''
    if rLine is not None:
        val = prop.getRegisterValue(nextAddr, instr.getRegister('r%d' % rLine))
        if val is not None: lineNo = str(val.getValue())

    tbl.add(PrintListResult({
        'address':  addrToInt(addr),
        'file':     fileName,
        'line':     str(lineNo),
        'funcname': funcName,
        'function': func.getName(),
        'call':     name,
        'message':  msg,
    }))


def run():
    if currentSelection is None:
    	blk = mem.getBlock(currentAddress)
    	startAddr = blk.getStart()
    	endAddr = blk.getEnd()
    else:
    	startAddr = currentSelection.getMinAddress()
    	endAddr = currentSelection.getMaxAddress()

    iStart = addrToInt(startAddr)
    iEnd   = addrToInt(endAddr)
    monitor.initialize(iEnd-iStart)

    monitor.setMessage("Getting functions...")
    funcIter = FM.getFunctions(True)
    targetAddrs = {}
    while True:
        try: func = funcIter.next()
        except java.lang.NullPointerException: break
        if func is None: break
        name = func.getName()
        if name.lower() in targetNames:
            targetAddrs[func.getEntryPoint()] = name

    monitor.setMessage("Finding printf calls...")
    tbl = makeDialog()
    nResults = 0
    addr = iStart
    while addr < iEnd: # lol range() is broken
        if addr & 0xFFF == 0:
            monitor.checkCanceled()
            monitor.incrementProgress(0x1000)
            monitor.setMessage("Scanning... %08X" % addr)
        addrObj = intToAddr(addr)
        instr   = listing.getCodeUnitAt(addrObj)
        if instr and instr.getMnemonicString() in ('b', 'bl'):
            target = instr.getOpObjects(0)[0]
            if target in targetAddrs:
                logFunc(instr, addrObj, targetAddrs[target], monitor, tbl)
                nResults += 1
                tbl.setMessage("%d results" % nResults)
        addr += 4

run()
