//@category Functions

import java.util.LinkedList;
import java.util.List;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.SymbolicPropogator;

public class PrintfSigOverrider extends GhidraScript {

    private static final String PRINT_F = "printf";
    private static final String UNSUPPORTED_MESSAGE =
        "Currently only processors passing parameters via registers are supported.";

    private static final Pattern FORMAT_PATTERN =
        Pattern.compile("%\\S*([lLh]?[cdieEfgGosuxXpn%])");

    private static final String DEC = "int printf(char* format%s)";
    
    private static final String FLOAT = "float";
    private static final String DOUBLE = "double";
    private static final String CHAR_PTR = "char *";
    private static final String WCHAR = "wchar_t";
    private static final String WCHAR_PTR = WCHAR+" *";
    private static final String LONG_DOUBLE = "long double";
    private static final String POINTER = "pointer";

    private static final String UNEXPECTED_FORMAT = "Unexpected specifier in format\n";
    private static final String SEPARATOR = ", ";

    @Override
    public void run() throws Exception {
        List<Function> functions = getGlobalFunctions(PRINT_F);
        for (Function function : functions) {
            monitor.checkCanceled();
            Parameter format = function.getParameter(0);
            if (format == null) {
                continue;
            }
            if (!format.isRegisterVariable()) {
                popup(UNSUPPORTED_MESSAGE);
                return;
            }
            Reference[] references = getReferencesTo(function.getEntryPoint());
            monitor.setMessage("Overriding Signatures for "+function.getName());
            monitor.initialize(references.length);
            for (Reference ref : references) {
                monitor.checkCanceled();
                if (!ref.getReferenceType().isCall()) {
                    monitor.incrementProgress(1);
                    continue;
                }
                Address callAddr = ref.getFromAddress();
                Function callee = getFunctionContaining(callAddr);
                if (callee == null) {
                    monitor.incrementProgress(1);
                    continue;
                }
                SymbolicPropogator prop = analyzeFunction(callee, monitor);
                Address nextAddr = movePastDelaySlot(callAddr);
                SymbolicPropogator.Value value = prop.getRegisterValue(nextAddr, format.getRegister());
                if (value == null) {
                    monitor.incrementProgress(1);
                    continue;
                }
                Address stringAddress = toAddr(value.getValue());
                Data data = getDataAt(stringAddress);
                if (data == null || !data.hasStringValue()) {
                    data = DataUtilities.createData(currentProgram, stringAddress,
                        StringDataType.dataType, -1, false, ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
                }
                String msg = (String) data.getValue();
                overrideFunction(function, callAddr, msg);
                monitor.incrementProgress(1);
            }
        }
    }

    private Address movePastDelaySlot(Address addr) {
        Instruction inst = getInstructionAt(addr);
        if (inst.getDelaySlotDepth() > 0) {
            do {
                inst = inst.getNext();
            } while (inst.isInDelaySlot());
        }
        return inst.getAddress();
    }

    private void overrideFunction(Function function, Address address, String format)
        throws Exception {
            int transaction = -1; 
            if (currentProgram.getCurrentTransaction() == null) {
                transaction = currentProgram.startTransaction("Override Signature");
            }
            boolean commit = false;
            try {
                HighFunctionDBUtil.writeOverride(function, address, getFunctionSignature(format));
                commit = true;
            }
            catch (Exception e) {
                printerr("Error overriding signature: " + e.getMessage());
            }
            finally {
                if (transaction != -1) {
                    currentProgram.endTransaction(transaction, commit);
                }
            }
    }

    private FunctionSignature getFunctionSignature(String format) throws Exception {
        FunctionSignatureParser parser = new FunctionSignatureParser(
        currentProgram.getDataTypeManager(),
        getState().getTool().getService(DataTypeManagerService.class));
        Matcher matcher = FORMAT_PATTERN.matcher(format);
        List<String> types = new LinkedList<>();
        String[] matches = matcher.results().map(MatchResult::group).toArray(String[]::new);
        for (String match : matches) {
            if (match.charAt(0) == 'h') {
                switch(match.charAt(1)) {
                    case 'i':
                    case 'd':
                    case 'o':
                        types.add(ShortDataType.dataType.getCDeclaration());
                        break;
                    case 'u':
                    case 'x':
                    case 'X':
                        types.add(UnsignedShortDataType.dataType.getCDeclaration());
                        break;
                    default:
                        throw new Exception(UNEXPECTED_FORMAT+format);
                }
            } else if (match.charAt(0) == 'l') {
                switch(match.charAt(1)) {
                    case 'c':
                        types.add(WCHAR);
                        break;
                    case 's':
                        types.add(WCHAR_PTR);
                        break;
                    case 'i':
                    case 'd':
                    case 'o':
                        types.add(LongDataType.dataType.getCDeclaration());
                        break;
                    case 'u':
                    case 'x':
                    case 'X':
                        types.add(UnsignedLongDataType.dataType.getCDeclaration());
                        break;
                    case 'e':
                    case 'E':
                    case 'f':
                    case 'g':
                    case 'G':
                        types.add(DOUBLE);
                        break;
                    default:
                        throw new Exception(UNEXPECTED_FORMAT+format);
                }
            } else if (match.charAt(0) == 'L') {
                switch(match.charAt(1)) {
                    case 'e':
                    case 'E':
                    case 'f':
                    case 'g':
                    case 'G':
                        types.add(LONG_DOUBLE);
                        break;
                    default:
                        throw new Exception(UNEXPECTED_FORMAT+format);
                }
            } else {
                switch(match.charAt(1)) {
                    case 'c':
                        types.add(CharDataType.dataType.getCDeclaration());
                        break;
                    case 's':
                        types.add(CHAR_PTR);
                        break;
                    case 'i':
                    case 'd':
                    case 'o':
                        types.add(IntegerDataType.dataType.getCDeclaration());
                        break;
                    case 'u':
                    case 'x':
                    case 'X':
                        types.add(UnsignedIntegerDataType.dataType.getCDeclaration());
                        break;
                    case 'e':
                    case 'E':
                    case 'f':
                    case 'g':
                    case 'G':
                        types.add(FLOAT);
                        break;
                    case 'p':
                        types.add(POINTER);
                        break;
                    default:
                        throw new Exception(UNEXPECTED_FORMAT+format);
                }
            }
        }
        if (types.isEmpty()) {
            return null;
        }
        StringBuilder builder = new StringBuilder();
        for (String type : types) {
            builder.append(SEPARATOR)
                    .append(type);
        }
        return parser.parse(null, String.format(DEC, builder.toString()));
    }

    // These should be in a Util class somewhere!

    public static ConstantPropagationAnalyzer getConstantAnalyzer(Program program) {
        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
        List<ConstantPropagationAnalyzer> analyzers = 
            ClassSearcher.getInstances(ConstantPropagationAnalyzer.class);
        for (ConstantPropagationAnalyzer analyzer : analyzers) {
            if (analyzer.canAnalyze(program)) {
                return (ConstantPropagationAnalyzer) mgr.getAnalyzer(analyzer.getName());
            }
        }
        return null;
    }

    public static SymbolicPropogator analyzeFunction(Function function, TaskMonitor monitor)
        throws CancelledException {
            Program program = function.getProgram();
            ConstantPropagationAnalyzer analyzer = getConstantAnalyzer(program);
            SymbolicPropogator symEval = new SymbolicPropogator(program);
            symEval.setParamRefCheck(true);
            symEval.setReturnRefCheck(true);
            symEval.setStoredRefCheck(true);
            analyzer.flowConstants(program, function.getEntryPoint(), function.getBody(),
                                   symEval, monitor);
            return symEval;
    }
}
