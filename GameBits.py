#Import GameBit enum from XML.
#@author Rena
#@category StarFox
#@keybinding
#@menupath
#@toolbar

import jarray
import struct
import os.path
import xml.etree.ElementTree as ET
from ghidra.program.model.listing import ParameterImpl
from ghidra.program.model.symbol import SourceType

#xmlPath = '/mnt/guilmon/home/rena/projects/games/hax/sfa/data/kiosk'
xmlPath = '/mnt/guilmon/home/rena/projects/games/hax/sfa/data/U0'
gameBitsXml = ET.parse(os.path.join(xmlPath, 'gamebits.xml')).getroot()

DT = currentProgram.getDataTypeManager()
prgName = currentProgram.name

def run():
    newBits   = ghidra.program.model.data.EnumDataType('GameBit',   4)
    newBits16 = ghidra.program.model.data.EnumDataType('GameBit16', 2)

    for bit in gameBitsXml.findall("./bit"):
        id   = int(bit.get('id'), 0)
        name = bit.get('name', None)
        if name is not None:
            try: newBits  .add(name, id)
            except: print("Failed adding %s=0x%X to GameBit" % (name, id))
            try: newBits16.add(name, id)
            except: print("Failed adding %s=0x%X to GameBit16" % (name, id))
    try: newBits  .add("NO_BIT", 0xFFFFFFFF)
    except: pass
    try: newBits16.add("NO_Bit", 0xFFFF)
    except: pass

    DT.getDataType(prgName+"/SFA/GameBits/GameBit")  .replaceWith(newBits)
    DT.getDataType(prgName+"/SFA/GameBits/GameBit16").replaceWith(newBits16)

start()
run()
end(True)
