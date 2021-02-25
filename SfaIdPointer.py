#Given a pointer, find it on the heap and add a comment of its size and tag.
#@author RenaKunisaki
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

NUM_HEAPS = 4
HEAP_TABLE = 0x80340698
TAGS = {
    0x00000005: "Map Blocks",
    0x00000006: "Texture",
    0x00000009: "Model Data",
    0x0000000A: "Models",
    0x0000000B: "MaybeAudio",
    0x0000000E: "Objects",
    0x00000010: "VOX",
    0x00000011: "Stack", # data type, not call stack
    0x00000017: "Texture Ptrs",
    0x00000018: "Vec3f Array",
    0x0000001A: "ModelStruct",
    0x000000FF: "Unknown 32-byte buffer",
    0x7D7D7D7D: "Data File",
    0x7F7F7FFF: "Compressed File",
    0xFFFF00FF: "IntersectPoint/Savegame",
    0xFFFFFFFF: "Savegame",
}

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

def readStruct(fmt, addr):
    size = struct.calcsize(fmt)
    arr  = jarray.zeros(size, "b")
    mem.getBytes(addr, arr)
    r = struct.unpack(fmt, arr)
    if len(r) == 1: return r[0] # grumble
    return r


def scanHeap(idx, addr):
    """Search specified heap for specified address."""
    addrInt = addrToInt(addr)
    totalSize, usedSize, totalBlocks, usedBlocks, data = \
        readStruct('>5I', intToAddr(HEAP_TABLE + (idx * 0x14)))
    for i in range(usedBlocks):
        entry = readStruct('>IIHHHHIII', intToAddr(data + (i * 0x1C)))
        loc, size = entry[0], entry[1]
        tag, uniqueId = entry[6], entry[8]
        #printf("Heap %d entry 0x%04X addr 0x%08X - 0x%08X size 0x%08X tag 0x%08X ID 0x%08X\n",
        #    idx, i, loc, loc+size, size, tag, uniqueId)
        if loc <= addrInt and (loc + size) > addrInt:
            return entry, i
    return None, None


def checkAddr(addr):
    #addr = int(addr, 16)
    addrInt = addrToInt(addr)
    if addrInt < 0x80000000 or addrInt >= 0x81800000:
        #print("0x%08X: invalid" % addrInt)
        return
    for i in range(NUM_HEAPS):
        entry, entryIdx = scanHeap(i, addr)
        if entry:
            tag = TAGS.get(entry[6], '<unknown>')
            #printf("0x%08X: heap %d entry 0x%04X (0x%08X - 0x%08X size 0x%06X tag 0x%08X %s ID 0x%08X)\n",
            #    addr, i, entryIdx, entry[0], entry[0]+entry[1], entry[1],
            #    entry[6], tag, entry[8])
            comment = getPlateComment(addr)
            if comment is None: comment = ''
            comment = comment.split('\n')
            newCmt = []
            for line in comment:
                if not (line.startswith('@heap ') or line.startswith('Heap ')
                or line.startswith('tag ') or line.startswith('@size ') or line.startswith('@tag ')
                or line.startswith('@ID ')):
                    newCmt.append(line)
            newCmt.append("@heap %d entry 0x%04X (0x%08X - 0x%08X)\n@size 0x%06X\n@tag 0x%08X %s\n@ID 0x%08X" % (
                i, entryIdx, entry[0], entry[0]+entry[1], entry[1],
                entry[6], tag, entry[8]))
            print(addr, '\n'.join(newCmt))
            setPlateComment(addr, '\n'.join(newCmt))
            return
    #print("0x%08X: not found in heap" % addrInt)


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

    monitor.setMessage("Examining...")
    addr = iStart
    while addr < iEnd: # lol range() is broken
        if addr & 0xFFF == 0:
            monitor.checkCanceled()
            monitor.incrementProgress(0x1000)
            monitor.setMessage("Examining... %08X" % addr)
        addrObj = intToAddr(addr)
        val = readAddr(addrObj)
        checkAddr(val)
        addr += 4

run()
