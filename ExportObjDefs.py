#Export ObjDef structs to XML.
#@author
#@category StarFox
#@keybinding
#@menupath
#@toolbar
# OBSOLETE, added to UpdateDllsXml
import xml.etree.ElementTree as ET
AF = currentProgram.getAddressFactory()
DT = currentProgram.getDataTypeManager()

def addrToInt(addr):
	return int(str(addr), 16)

def intToAddr(addr):
	return AF.getAddress("0x%08X" % addr)

def run():
    outPath = str(askFile("Export ObjDefs", "Export"))

    objDefs = []
    structs = list(DT.allStructures)
    for struct in structs:
        if struct.displayName.startswith('ObjDef_'):
            objDefs.append(struct)

    monitor.initialize(len(objDefs))

    eRoot = ET.Element('objdefs')
    tree  = ET.ElementTree(eRoot)

    for objDef in objDefs:
        monitor.checkCanceled()
        monitor.incrementProgress(1)

        eDef = ET.SubElement(eRoot, 'objdef', {
            'name': str(objDef.name)[7:], # cut off "ObjDef_"
            'size': '0x%X' % objDef.length
        })

        for comp in filter(lambda c: c.offset >= 0x18, objDef.components):
            eField = ET.SubElement(eDef, 'field', {
                'offset': '0x%X' % comp.offset,
                'type': str(comp.dataType.displayName),
                'name': str(comp.fieldName),
            })
            if comp.comment:
                ET.SubElement(eField, 'description').text = str(comp.comment)

    tree.write(outPath)

run()
