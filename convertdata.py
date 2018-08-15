#!/usr/bin/env python3
"""
Module Docstring
"""

__author__ = ""
__version__ = ""
__license__ = "MIT"

import sys
import base64
import functools

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

def swapBits(int_type, offset1, offset2):
    b1 = testBit(int_type, offset1)
    b2 = testBit(int_type, offset2)
    int_type = setBit(int_type, offset2) if b1 else clearBit(int_type, offset2)
    int_type = setBit(int_type, offset1) if b2 else clearBit(int_type, offset1)
    return int_type

desInitialPermValues    = [58, 50, 42, 34, 26, 18, 10, 2,
                           60, 52, 44, 36, 28, 20, 12, 4,
                           62, 54, 46, 38, 30, 22, 14, 6,
                           64, 56, 48, 40, 32, 24, 16, 8,
                           57, 49, 41, 33, 25, 17, 9, 1,
                           59, 51, 43, 35, 27, 19, 11, 3,
                           61, 53, 45, 37, 29, 21, 13, 5,
                           63, 55, 47, 39, 31, 23, 15, 7]

desFinalPermValues      = [40, 8, 48, 16, 56, 24, 64, 32,
                           39, 7, 47, 15, 55, 23, 63, 31,
                           38, 6, 46, 14, 54, 22, 62, 30,
                           37, 5, 45, 13, 53, 21, 61, 29,
                           36, 4, 44, 12, 52, 20, 60, 28,
                           35, 3, 43, 11, 51, 19, 59, 27,
                           34, 2, 42, 10, 50, 18, 58, 26,
                           33, 1, 41, 9, 49, 17, 57, 25]

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

def desEncode(b):
    bytecount   = len(b)
    chunkcount  = (bytecount // 64) + 1
    res = []
    for chunckit in range(chunkcount):
        fromIdx     = chunckit * 16
        toIdx       = chunckit + 16
        assert (fromIdx < bytecount) and (toIdx <= bytecount), "Invalid index: fromIdx: %d, toIdx: %d, bytecount: %d" %(fromIdx, toIdx, bytecount)
        chunk       = b[fromIdx:toIdx]
        print("encrypting chunk %d: %s" % (chunckit, chunk))
        permChunk   = desPerm(desInitialPermValues, chunk)
        finalChunk  = desPerm(desFinalPermValues, permChunk)
        print("encrypted chunk %d:  %s" % (chunckit, finalChunk))
        res = res + finalChunk
    return res

def desDecode(s):
    return s

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
    
