#!/usr/bin/python

import sys
import struct
import argparse

def swap32(i):
  return struct.unpack("<I", struct.pack(">I", i))[0]

filename = None
buffername = None
blocksize  = 30000 # ~3MB

parser = argparse.ArgumentParser()
parser.add_argument("file", type=str, help="specify binary file")
parser.add_argument("buffer", type=str, help="name of buffer to write shellcode to")
parser.add_argument("-b", "--blocksize", type=int, help="specify block size")
args = parser.parse_args()

if args.blocksize:
  blocksize = args.blocksize

filename = args.file
buffername = args.buffer

with open(filename, "rb") as f:
  block = f.read(blocksize)

  hexStr = ""
  blockOffset = 0

  for ch in block:
    hexStr += format((ord(ch)), 'x').zfill(2)

    blockOffset += 1

    if blockOffset % 4 == 0:
      hexStr += "|"

  byteSets = hexStr.split('|')
  byteOffset = 0

  del byteSets[-1]
  data = []
  for byteSet in byteSets:
    byte = int(byteSet, 16)

    byte = format(swap32(byte), 'x').zfill(8) # Little Endian Pls

    #print "p.write4(" + str(buffername) + ".add32(0x" + str(format((byteOffset), 'x').zfill(8)) + "), 0x" + str(byte) + ");"
    data.append(eval('0x%s' % str(byte)))
    #print str(buffername) + "[" + str(byteOffset) + "] = 0x" + str(byte) + ";"

    byteOffset += 4
    #byteOffset += 1
  print(data)