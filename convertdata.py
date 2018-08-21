#!/usr/bin/env python3
"""
Module Docstring
"""

__author__ = ""
__version__ = ""
__license__ = "MIT"

import base64
import math
import functools
import hashlib
import sys

#------------------------------------------------------------------------------
# hex

def hexEncode(s):
    r = ""
    for c in s:
        r = r + ("\\x%x" % ord(c))
    return r

def hexDecode(s):
    r = ""
    chars = s.split("\\x")
    for c in chars:
        r = r + c + " "
    return str(bytes.fromhex(r), 'ascii')

#------------------------------------------------------------------------------
# DES

# testBit() returns a nonzero result, 2**offset, if the bit at 'offset' is one.
def testBit(int_type, offset):
    mask = 1 << offset
    return(int_type & mask)

# setBit() returns an integer with the bit at 'offset' set to 1.
def setBit(int_type, offset):
    mask = 1 << offset
    return(int_type | mask)

# clearBit() returns an integer with the bit at 'offset' cleared.
def clearBit(int_type, offset):
    mask = ~(1 << offset)
    return(int_type & mask)

def toggleBit(int_type, offset, val):
    if val:
        return setBit(int_type, offset)
    else:
        return clearBit(int_type, offset)

def chunkFn(chunk, offset, fn):
    assert offset <= len(chunk) * 4
    byteIdx = offset // 4
    bitIdx  = offset % 4
    return fn(chunk[byteIdx], bitIdx)

def modifyChunkFn(chunk, offset, fn):
    assert offset <= len(chunk) * 4
    byteIdx = offset // 4
    bitIdx  = offset % 4
    chunk[byteIdx] = fn(chunk[byteIdx], bitIdx)

testdata = [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
            0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf]

desInitialPermValues        = [58, 50, 42, 34, 26, 18, 10, 2,
                               60, 52, 44, 36, 28, 20, 12, 4,
                               62, 54, 46, 38, 30, 22, 14, 6,
                               64, 56, 48, 40, 32, 24, 16, 8,
                               57, 49, 41, 33, 25, 17, 9, 1,
                               59, 51, 43, 35, 27, 19, 11, 3,
                               61, 53, 45, 37, 29, 21, 13, 5,
                               63, 55, 47, 39, 31, 23, 15, 7]

desFinalPermValues          = [40, 8, 48, 16, 56, 24, 64, 32,
                               39, 7, 47, 15, 55, 23, 63, 31,
                               38, 6, 46, 14, 54, 22, 62, 30,
                               37, 5, 45, 13, 53, 21, 61, 29,
                               36, 4, 44, 12, 52, 20, 60, 28,
                               35, 3, 43, 11, 51, 19, 59, 27,
                               34, 2, 42, 10, 50, 18, 58, 26,
                               33, 1, 41, 9, 49, 17, 57, 25]

desKeyPermValues            = [57, 49, 41, 33, 25, 17, 9, 1,
                               58, 50, 42, 34, 26, 18, 10, 2,
                               59, 51, 43, 35, 27, 19, 11, 3,
                               60, 52, 44, 36, 63, 55, 47, 39,
                               31, 23, 15, 7, 62, 54, 46, 38,
                               30, 22, 14, 6, 61, 53, 45, 37,
                               29, 21, 13, 5, 28, 20, 12, 4]

desKeyCompressionPermValues = [14, 17, 11, 24, 1, 5, 3, 28,
                               15, 6, 21, 10, 23, 19, 12, 4,
                               26, 8, 16, 7, 27, 20, 13, 2,
                               41, 52, 31, 37, 47, 55, 30, 40,
                               51, 45, 33, 48, 44, 49, 39, 56,
                               34, 53, 46, 42, 50, 36, 29, 32]

desExpansionPermValues      = [32, 1, 2, 3, 4, 5, 4, 5,
                               6, 7, 8, 9, 8, 9, 10, 11,
                               12, 13, 12, 13, 14, 15, 16, 17,
                               16, 17, 18, 19, 20, 21, 20, 21,
                               22, 23, 24, 25, 24, 25, 26, 27,
                               28, 29, 28, 29, 30, 31, 32, 1]

desKeyEncodeShiftCount = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
desKeyDecodeShiftCount = [0, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

desSBoxValues = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
                  [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
                  [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
                  [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
                 [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
                  [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
                  [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
                  [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
                 [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
                  [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
                  [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
                  [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
                 [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
                  [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
                  [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
                  [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
                 [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
                  [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
                  [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
                  [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
                 [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
                  [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
                  [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
                  [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
                 [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
                  [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
                  [1 , 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
                  [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
                 [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
                  [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
                  [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
                  [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

desPBoxValues = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
                 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

def chunksToStr(chunks):
    return "%s" % list(map(hex, chunks))

def desPerm(permValues, chunk):
    assert len(chunk) == 16, "[desPerm] Invalid chunk length, got %d  but expecting 16." % len(chunk)
    newChunk = chunk.copy();
    for i in range(63):
        index = i + 1
        byteIndex = index // 4
        bitIndex = index % 4
        swapToIndex = permValues[index] - 1 # 1-64
        swapToByteIndex = swapToIndex // 4
        swapToBitIndex = swapToIndex % 4
        bitValue = testBit(chunk[swapToByteIndex], swapToBitIndex)
        newChunk[byteIndex] = setBit(newChunk[byteIndex], bitIndex) if bitValue else clearBit(newChunk[byteIndex], bitIndex)
        # print(("byteIndex: %d, bitIndex: %d, swapToIndex: %d, swapToByteIndex: %d, swapToBitIndex: %d, bitValue: %d, byte: %s -> %s"
        #        % (byteIndex, bitIndex, swapToIndex, swapToByteIndex, swapToBitIndex, bitValue, bin(chunk[byteIndex]), bin(newChunk[byteIndex]))))
    return newChunk

def desKeyPerm(keyChunks):
    newKey = bytearray(14) # 56 bits resulting key
    for i in range(len(desKeyPermValues)):
        offset = desKeyPermValues[i] - 1 # 1-64
        bitValue = chunkFn(keyChunks, offset, testBit)
        modifyChunkFn(newKey, i, lambda b, o: toggleBit(b, o, bitValue))
    return newKey

def desShiftSubKey(k, dir):
    bitrange = len(k) * 4
    shiftedKey = bytearray(len(k))
    if dir > 0:
        lastbit = chunkFn(k, bitrange-1, testBit)
        for i in range(bitrange-1):
            bitValue = chunkFn(k, i, testBit)
            modifyChunkFn(shiftedKey, i+1, lambda b,o: toggleBit(b, o, bitValue))
        modifyChunkFn(shiftedKey, 0, lambda b,o: toggleBit(b, o, lastbit))
    else:
        firstbit = chunkFn(k, 0, testBit)
        for i in range(bitrange-1):
            bitValue = chunkFn(k, i+1, testBit)
            modifyChunkFn(shiftedKey, i, lambda b,o: toggleBit(b, o, bitValue))
        modifyChunkFn(shiftedKey, bitrange-1, lambda b,o: toggleBit(b, o, firstbit))
    return shiftedKey

def desKeyShift(shift, keyChunks):
    assert len(keyChunks) == 14, "expecting 56 bits key..."
    lkey = keyChunks[0:7]
    rkey = keyChunks[7:14]
    dir = int(math.copysign(1, shift))
    for i in range(abs(shift)):
        lkey = desShiftSubKey(lkey, dir)
        rkey = desShiftSubKey(rkey, dir)
    lkey.extend(rkey)
    return lkey

def desKeyCompressionPerm(key):
    assert len(key) == 14, "expecting 56 bits key..."
    compressedKey = bytearray(12) # 48 bits permutated compressed key
    for bit in range(48):
        offset  = desKeyCompressionPermValues[bit] - 1 # 1-56
        bitValue= chunkFn(key, offset, testBit)
        modifyChunkFn(key, bit, lambda b,o: toggleBit(b, o, bitValue))
    return compressedKey

def desExpansionPerm(rdata):
    assert len(rdata) == 8, "half of the chunk should be 32 bits"
    expandedData = bytearray(12) # expansion to 48 bits
    for bit in range(32):
        offset  = desExpansionPermValues[bit] - 1 # 1-32
        bitValue= chunkFn(rdata, offset, testBit)
        modifyChunkFn(expandedData, bit, lambda b,o: toggleBit(b, o, bitValue))
    return expandedData

def desXOR(expandedRdata, compressedKey):
    assert len(expandedRdata) == len(compressedKey)
    length = len(expandedRdata)
    result = bytearray(length)
    for byte in range(length):
        result[byte] = expandedRdata[byte] ^ compressedKey[byte]
    return result

def desSBox(data):
    assert len(data) == 12
    result = bytearray(8) # input 48 bits => 32 bits
    bits = bytearray(6)
    # print("sbox data: %s" % data)
    for box in range(8):
        for bit in range(6):
            baseBit = box * 6
            bits[bit] = 1 if chunkFn(data, baseBit+bit, testBit) else 0
        # print("bits: %s" % bits)
        row = bits[0] << 1 | bits[5]
        col = bits[1] << 0 | bits[2] << 1 | bits[3] << 2 | bits[4] << 3
        # print("box: %d, row: %d, col: %d" % (box, row, col))
        result[box] = desSBoxValues[box][row][col]
    return result

def desPBox(data):
    assert len(data) == 8
    result = bytearray(8)
    for bit in range(32):
        offset = desPBoxValues[bit] - 1 # 1-32
        bitValue = chunkFn(data, offset, testBit)
        modifyChunkFn(result, bit, lambda b,o: toggleBit(b, o, bitValue))
    return result

# def desF(rightChunk, key):
#     return 0x0

def desGetKeys(shiftCountValues, shiftDirection):
    pwdstr = input("enter DES key: ")
    key = hashlib.md5(bytearray(pwdstr, 'ascii')).digest()
    keys = []
    permKey = desKeyPerm(key)
    shiftedPermKey = permKey.copy()
    for round in range(16):
        shift = shiftDirection * shiftCountValues[round]
        shiftedPermKey  = desKeyShift(shift, shiftedPermKey)
        compressedKey   = desKeyCompressionPerm(shiftedPermKey)
        keys += [compressedKey]
    return keys

def desEncode(data):
    keys = desGetKeys(desKeyEncodeShiftCount, 1)
    return desProcessData(keys, data)

def desDecode(data):
    keys = desGetKeys(desKeyDecodeShiftCount, -1)
    keys.reverse()
    return desProcessData(keys, data)

def desProcessData(keys, data):
    bytecount   = len(data)
    chunkcount  = (bytecount // 64) + 1
    res = bytearray(0)

    for chunckit in range(chunkcount):
        fromIdx     = chunckit * 16
        toIdx       = chunckit + 16
        assert (fromIdx < bytecount) and (toIdx <= bytecount), "Invalid index: fromIdx: %d, toIdx: %d, bytecount: %d" %(fromIdx, toIdx, bytecount)
        chunk       = data[fromIdx:toIdx]
        print("encrypting chunk %d: %s" % (chunckit, chunk))
        permChunk   = desPerm(desInitialPermValues, chunk)

        ldata           = chunk[0:8]
        rdata           = chunk[8:16]

        for round in range(16):
            compressedKey   = keys[round]
            expandedRdata   = desExpansionPerm(rdata)
            xorResult       = desXOR(expandedRdata, compressedKey)
            sboxResult      = desSBox(xorResult)
            pboxResult      = desPBox(sboxResult)
            newRdata        = desXOR(ldata, pboxResult)
            ldata           = rdata
            rdata           = newRdata
        
        encryptedChunk = ldata.copy()
        encryptedChunk.extend(rdata)
        finalChunk  = desPerm(desFinalPermValues, encryptedChunk)
        print("encrypted chunk %d:  %s" % (chunckit, finalChunk))
        res.extend(finalChunk)
    return res    

#------------------------------------------------------------------------------
# main

def printUsage():
    optionsStr = "["
    for k in options:
        optionsStr += k+"|"
    optionsStr += "\b]"

    progName = sys.argv[0] if sys.argv[0] != "" else "program"
    print("usage: %s %s <str>" % (progName, optionsStr))

options = {"encode64" : lambda s: str(base64.b64encode(bytearray(s, 'ascii')), 'ascii'),
           "decode64" : lambda s: str(base64.b64decode(bytearray(s, 'ascii')), 'ascii'),
           "encodeX" : hexEncode,
           "decodeX" : hexDecode,
           "encodeDES" : desEncode,
           "decodeDES" : desDecode,
}
     
def main():
    """ encode/decode string in base64 """

    if (len(sys.argv) != 3):
        printUsage()
        return

    option = sys.argv[1]
    if (option not in options):
        printUsage()
        return

    msg = sys.argv[2]
    print(options[option](msg))
    
if __name__ == "__main__":
    """ This is executed when run from the command line """
    main()
    
