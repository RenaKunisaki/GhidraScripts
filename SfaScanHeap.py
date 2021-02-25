#Scan heaps and automatically mark memory regions.
#@author Rena
#@category StarFox
#@keybinding
#@menupath
#@toolbar

import jarray
import struct
listing = currentProgram.getListing()
AF = currentProgram.getAddressFactory()
DT = currentProgram.getDataTypeManager()
mem = currentProgram.getMemory()
tByte = DT.getDataType("/byte")
tVec3f = DT.getDataType("main.dol/Dolphin/Math/vec3f")
tAnimDataStruct = DT.getDataType("main.dol/SFA/Animation/AnimDataStruct")

def addrToInt(addr):
	return int(str(addr), 16)

def intToAddr(addr):
	return AF.getAddress("0x%08X" % addr)

class Struct:
    def __init__(self, addr):
	data = jarray.zeros(self.SIZE, "b")
        mem.getBytes(intToAddr(addr), data)
	data = data.tostring()
        self._raw = data
        for name, field in self._fields.items():
            fmt, offs = field
            if type(fmt) is str:
                r = struct.unpack_from(fmt, data, offs)
                if len(r) == 1: r = r[0] # grumble
                if type(r) is bytes:
                    r = r.decode('ascii')
                    lol = r.find("\x00")
                    if lol > 0: r = r[0:lol]
            else: # should be a Struct
                p = struct.unpack_from('>I', data, offs)
                r = fmt(client, p[0])
            setattr(self, name, r)

class HeapStruct(Struct):
    SIZE = 0x14
    _fields = {
        "size":     ('>I', 0x00),
        "avail":    ('>I', 0x04),
        "used":     ('>I', 0x08),
        "data":     ('>I', 0x0C),
        "dataSize": ('>I', 0x10),
    }

class HeapEntry(Struct):
    SIZE = 0x1C
    _fields = {
        "loc":   ('>I',  0x00),
        "size":  ('>I',  0x04),
        "unk08": ('>H',  0x08),
        "idx":   ('>H',  0x0A),
        "stack": ('>2H', 0x0C),
        "tag":   ('>I',  0x10),
        "unk14": ('>I',  0x14),
        "unk18": ('>I',  0x18),
    }

    _tags = {
        0x00000005: "MapBlocks",
        0x00000006: "Texture",
        0x00000009: "ModelData",
        0x0000000A: "Models",
        0x0000000B: "MaybeAudio",
        0x0000000E: "Objects",
        0x00000010: "VOX",
        0x00000011: "Stack",
        0x00000015: "TextureData",
        0x00000017: "TexturePtrs",
        0x00000018: "Vec3fArray",
        0x0000001A: "ModelStruct",
        0x000000FF: "Unknown32ByteBuffer",
        0x7D7D7D7D: "DataFile",
        0x7F7F7FFF: "CompressedFile",
        0xA0A0A0A0: "Texture",
        0xFACEFEED: "FACEFEED",
        0xFFFF00FF: "IntersectPoint",
        0xFFFFFFFF: "Savegame",
    }

def setHeapEntry(heapIdx, entryIdx, entry):
	addr = intToAddr(entry.loc)
	try:
		if entry.tag == 0x00000018:
			listing.clearCodeUnits(addr, addr.add(12), False)
			listing.createData(addr, tVec3f, entry.size / 12)
		elif entry.tag == 0x00000009:
			listing.clearCodeUnits(addr, addr.add(250), False)
			listing.createData(addr, tAnimDataStruct, entry.size / 250)
		else:
			listing.createData(addr, tByte, entry.size)
	except ghidra.program.model.util.CodeUnitInsertionException:
		pass

	if entry.tag in HeapEntry._tags:
		name = HeapEntry._tags[entry.tag].split()
		name = '_'.join(filter(lambda s: s != "" and not s.isspace(), name))
		createLabel(addr, "%s_%08X" % (
			name,
			addrToInt(addr)),
		False)

	codeUnit = listing.getDataAt(addr)
	if codeUnit is not None:
		codeUnit.setComment(codeUnit.PLATE_COMMENT,
			"Heap %d entry %d Size 0x%08X\ntag 0x%08X: %s" % (
				heapIdx, entryIdx, entry.size,
				entry.tag, HeapEntry._tags.get(entry.tag, "<unknown>")))

def showHeap():
	#printf("#|Size    |Avail   |Used    |Data    |DataSize\n")
        heaps = []
        for i in range(5):
            hs = HeapStruct(0x8034069C + (i*HeapStruct.SIZE))
            heaps.append(hs)
            #printf("\%d|%08X|%08X|%08X|%08X|%08X\n", i,
            #    hs.size, hs.avail, hs.used, hs.data, hs.dataSize)

        for i, heap in enumerate(heaps):
            if heap.data != 0:
                #printf("\nHeap %d:\n", i)
                #printf("Idx |Address |Size    |Unk8|Idx |Stack   |Unk14   |Unk18   |Tag\n")
                for j in range(heap.used):
                    entry = HeapEntry(heap.data + (j * HeapEntry.SIZE))
		    setHeapEntry(i, j, entry)
                    #printf("%4d|%08X|%08X|%04X|%04X|%04X%04X|%08X|%08X|%08X %s\n", j,
                    	#entry.loc, entry.size, entry.unk08, entry.idx,
                    	#entry.stack[0], entry.stack[1], entry.unk14, entry.unk18,
                    	#entry.tag, HeapEntry._tags.get(entry.tag, "<unknown>"))

            #else:
                #printf("Heap %d: null\n", i)

showHeap()
