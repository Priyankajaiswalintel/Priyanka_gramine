#
# Copyright (C) 2021 Intel Corporation
#
# This software and the related documents are Intel copyrighted materials, and your use of them
# is governed by the express license under which they were provided to you ("License"). Unless
# the License provides otherwise, you may not use, modify, copy, publish, distribute, disclose
# or transmit this software or the related documents without Intel's prior written permission.
#
# This software and the related documents are provided as is, with no express or implied
# warranties, other than those that are expressly stated in the License.
#

# pylint: disable=invalid-name,missing-function-docstring,missing-module-docstring,missing-class-docstring,too-many-branches,too-many-lines,too-many-locals,too-many-instance-attributes,too-many-arguments,too-many-statements

import argparse
import os
import sys
import subprocess
import struct
import traceback
import array
import multiprocessing
import datetime
import gzip
import shutil
from functools import partial
import time
import re
import json

from printer import info_p, warning_p, error_p, exception_p
from elf import getMappingFromFile
import maaReport

RANDOM_STRIDE_LEVEL = 0.05
RIGHT_STRIDE_LEVEL = 0.9
RANDOM_STRIDE = 'random'

MAAVersion = '2.2'
# DEBUG = True
DEBUG = False
MAA_RESULTS_DIR_PATTERN = 'MEMORY_TRACE_ANALYSIS'
GTPIN_MEMORY_TRACE_DIR_PATTERN = 'GTPIN_PROFILE_MEMORYTRACE'
GTPIN_STRIDE_DIR_PATTERN = 'GTPIN_PROFILE_STRIDE'
GTPIN_DIR_PATTERN = 'GTPIN_PROFILE_'
ASM_DIR = 'ASM'
MEMORY_TRACE_FILE = 'memorytrace_compressed.bin'
STRIDE_FILE = 'stride.txt'
MEMORY_TRACE_FILE_ZIP = 'memorytrace_compressed.bin.gz'
PRE_PROC_FILE_NAME = 'memorytrace_pre_process.txt'
SW_THREADS_FILE_NAME = 'memorytrace_pre_process_dispatch.txt'
TXT_REPORT_NAME = 'report.txt'
CSV_REPORT_NAME = 'report.csv'
HTML_REPORT_NAME = 'memory_access_analysis_report.html'
JSON_REPORT_NAME = 'app.report.json'
MAX_FILE_NAME_LENGTH = 250
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
RUN_DIR = os.getcwd()
CACHE_LINE_SIZE = 64
BYTE_SIZE = 8
MAX_SIMDW = 32
GTPIN_MEMTRACE_MB = 4096 # 4096 max
COLLECT_ALL_DIRECTION = 'X' # 'Y' or 'Z' # only one direction
COMPRESS_TRACE = False
READ_GTPIN_VERSION_FROM_FILE=True
READ_GTPIN_VERSION_FROM_GTPIN_EXE=True
PARALLEL_ANALYSIS = True
ENCODING='utf-8'
WA= {
    'OLD_UNIQUE_NAME_FORMAT': False,
    'TILE_ID_SUPPORTED': True,
    'DISABLE_MULTIPROCESSING': False,
}
if os.name == 'nt':
    PARALLEL_ANALYSIS = False
    WA['DISABLE_MULTIPROCESSING'] = True
    statStrList = ['']
    exe = '.exe'
else:
    manager = multiprocessing.Manager()
    statStrList = manager.list()
    statStrList.append('')
    exe = ''
STATUS_FILE_MAX_ROWS_NUM = 25
STATUS_FILE_NAME = 'status.gma.txt'
statusArray = []
dirTypes = {'maa': 0, 'gtpin':1, 'trace': 2, 'error': 255}
ERROR_CODE = {
    'Success': 0,
    'Cannot read file': 1,
    'Directory not found': 2,
    'Arguments not recognized': 3,
    'Cannot create directory': 4,
    'File not found': 5,
    'GTPin phase 1 fail': 6,
    'GTPin phase 2 fail': 7,
    'Application not found' : 8,
    'GTPin not found': 9,
    'GTPin result not found': 10,
    'Cannot read ASM file': 11,
    'Debug data not found': 12,
    'Cannot read source file': 13,
    'Link file found': 14,
    'GTPin incorrect phase': 15,

    'Unknown': 255
}
def getErrorMsg(code: int) -> str:
    return list(ERROR_CODE.keys())[list(ERROR_CODE.values()).index(code)]
distributionCodes = {'regular': 0, 'stride': 1, 'random': 2}

class Send:
    def getListAttributes() -> list:
        return ['execSize', 'channelOffset', 'accessSize', 'intensity', 'isWrite', 'isScatter',
                'isSlm', 'isAtomic', 'isEot', 'isMedia', 'addrWidth', 'simdWidth', 'bti',
                'dataPort']

    def __init__(self, fIn):
        self.read_from_file(fIn)
        self.accessSize = self.operandWidthInBytes * self.numOfElements
        self.intensity = self.execSize * self.accessSize

    def parseAttr(self): # ABI of memory trace GTPin tool
        self.isWrite = 1 if self.attr & 0x01 else 0
        self.isScatter = 1 if self.attr & 0x02 else 0
        self.isBts = 1 if self.attr & 0x04 else 0
        self.isSlm = 1 if self.attr & 0x08 else 0
        self.isScratch = 1 if self.attr & 0x10 else 0
        self.isAtomic = 1 if self.attr & 0x20 else 0
        self.isEot = 1 if ((self.attr >> 23) & 0x1) else 0
        self.isMedia = 1 if ((self.attr >> 24) & 0x1) else 0
        self.addrWidth = 64 if self.attr & 0x40 else 32
        self.simdWidth = 16 if self.attr & 0x80 else 8
        self.bti = (self.attr & 0xFF00) >> 8
        self.payloadLen = (self.attr >> 16) & 0x1F
        self.dataPort = ((self.attr >> 21) & 0x3)
        self.operandWidthInBytes = ((self.attr >> 32) & 0xFFFF)
        self.numOfElements = ((self.attr >> 48) & 0xFFFF)
    def encodeAttr(self):
        self.attr = 0
        self.attr |= 0x01 if self.isWrite else 0
        self.attr |= 0x02 if self.isScatter else 0
        self.attr |= 0x04 if self.isBts else 0
        self.attr |= 0x08 if self.isSlm else 0
        self.attr |= 0x10 if self.isScratch else 0
        self.attr |= 0x20 if self.isAtomic else 0
        self.attr |= (1<<23) if self.isEot else 0
        self.attr |= (1<<24) if self.isMedia else 0
        self.attr |= 0x40 if self.addrWidth == 64 else 0
        self.attr |= 0x80 if self.simdWidth == 16 else 0
        self.attr |= (self.bti<<8)
        self.attr |= (self.payloadLen & 0x1F ) << 16
        self.attr |= (self.dataPort & 0x3 ) << 21
        self.attr |= (self.operandWidthInBytes & 0xFFFF ) << 32
        self.attr |= (self.payloadLen & 0xFFFF) << 48
    def read_from_file(self, fIn):
        if isinstance(fIn, list):
            self.operandWidthInBytes    = 0
            self.numOfElements     = 0
            self.offset            = 0
            self.isWrite           = 0
            self.isScatter         = 0
            self.isBts             = 0
            self.isSlm             = 0 #
            self.isScratch         = 0
            self.isAtomic          = 0
            self.addrWidth         = 0 #
            self.simdWidth         = 0
            self.bti               = 0
            self.payloadLen        = 0 #
            self.dataPort          = 0
            self.isEot             = 0 #
            self.isMedia           = 0
            self.operandWidthInBytes    = 0
            self.numOfElements     = 0
            self.execSize          = 0
            self.channelOffset     = 0
            self.offset = fIn[0]
            self.attr = fIn[1]
            self.execSize = fIn[2]
            self.channelOffset = fIn[3]
            self.parseAttr()
        else:
            self.offset            = int(struct.unpack('I', fIn.read(4))[0])
            self.isWrite           = int(struct.unpack('I', fIn.read(4))[0])
            self.isScatter         = int(struct.unpack('I', fIn.read(4))[0])
            self.isBts             = int(struct.unpack('I', fIn.read(4))[0])
            self.isSlm             = int(struct.unpack('I', fIn.read(4))[0])
            self.isScratch         = int(struct.unpack('I', fIn.read(4))[0])
            self.isAtomic          = int(struct.unpack('I', fIn.read(4))[0])
            self.isFence           = int(struct.unpack('I', fIn.read(4))[0])
            self.addrWidth         = int(struct.unpack('I', fIn.read(4))[0])
            self.simdWidth         = int(struct.unpack('I', fIn.read(4))[0])
            self.bti               = int(struct.unpack('I', fIn.read(4))[0])
            self.payloadLen        = int(struct.unpack('I', fIn.read(4))[0])
            self.dataPort          = int(struct.unpack('I', fIn.read(4))[0])
            self.isEot             = int(struct.unpack('I', fIn.read(4))[0])
            self.isMedia           = int(struct.unpack('I', fIn.read(4))[0])
            self.operandWidthInBytes    = int(struct.unpack('I', fIn.read(4))[0])
            self.numOfElements     = int(struct.unpack('I', fIn.read(4))[0])
            self.execSize          = int(struct.unpack('I', fIn.read(4))[0])
            self.channelOffset     = int(struct.unpack('I', fIn.read(4))[0])
            self.encodeAttr()
        return self
    def getDefault() -> 'Send':
        return Send([-1, 0, 0, 0])
    def maxTheorCacheLineNumber(self) -> int:
        return self.simdWidth
    def minTheorCacheLineNumber(self) -> int:
        return -(-self.simdWidth*self.accessSize//CACHE_LINE_SIZE)
    def __str__(self):
        string = '0x{:04x} {:8} SIMD{simdWidth} {addrWidth}{isSlm}{isAtomic}{isScatter}'.format(
            self.offset,
            '({}|M{})'.format(self.execSize, self.channelOffset),
            simdWidth=self.simdWidth,
            addrWidth=' {}'.format(self.addrWidth),
            isSlm=' L' if self.isSlm else ' G',
            isAtomic=' A' if self.isAtomic else '',
            isScatter=' SC' if self.isScatter else ' US') + \
        '{isWrite}{accessSize}{eot} PL{payloadLen} {media}'.format(
            isWrite=' W' if self.isWrite else ' R',
            accessSize=' {}'.format(self.accessSize),
            eot=' EOT' if self.isEot else '',
            payloadLen=self.payloadLen,
            media='Media' if self.isMedia else ''
        )
        return string
    def typeStr(self):
        if self.isEot:
            return ['EOT', '', '']
        return [
            'SIMD{:<2}'.format(self.simdWidth),
            '({}|M{})'.format(self.execSize, self.channelOffset),
            '{}{}{}{}_{}'.format(
                'Media' if self.isMedia else '',
                'A' if self.isAtomic else '',
                'L' if self.isSlm else 'G',
                'W' if self.isWrite else 'R',
                self.accessSize
                )
            ]
    def typeStrLong(self):
        typeStr = []
        typeStr.append('Execution Masks: {:8},'.format(
            '({}|M{})'.format(self.execSize, self.channelOffset)))
        typeStr.append('SIMD{},'.format(self.simdWidth))
        typeStr.append('Address Width: {} bit,'.format(self.addrWidth))
        typeStr.append('payload Len: {} GRF,'.format(self.payloadLen))
        typeStr.append('{},'.format('SLM' if self.isSlm else 'Global'))
        typeStr.append('{},'.format('Write' if self.isWrite else 'Read',))
        typeStr.append('{},'.format('Scatter' if self.isScatter else 'Unscatter',))
        typeStr.append('{}'.format('Media,' if self.isMedia else ''))
        typeStr.append('{}'.format('Atomic' if self.isAtomic else ''))
        typeStr.append('{}'.format('EOT' if self.isEot else ''))
        return typeStr
    def __eq__(self, other: 'Send') -> bool:
        for attr in ['offset', 'attr', 'execSize', 'channelOffset']:
            if getattr(self, attr) != getattr(other, attr):
                return False
        return True
    def eqByAttr(self, other: 'Send') -> bool:
        for attr in ['attr', 'execSize']:
            if getattr(self, attr) != getattr(other, attr):
                return False
        return True

class AggregatedData:
    mems = ['Local', 'Global']
    rws = ['Read', 'Write']
    tus = ['Used', 'Transferred', 'CacheLineNumber', 'Calls']
    def getListAttributes() -> list:
        ls = list()
        for mem in AggregatedData.mems:
            for rw in AggregatedData.rws:
                for tu in AggregatedData.tus:
                    ls.append('ad{}{}{}'.format(mem, rw, tu))
        return ls
    def __init__(self):
        for att in AggregatedData.getListAttributes():
            setattr(self, att, int(0))
    def addSendData(self, sendData: 'SendData'):
        send = sendData.send
        attr = 'ad'
        attr += 'Local' if send.isSlm else 'Global'
        attr += 'Write' if send.isWrite else 'Read'
        att = attr+'Used'
        setattr(self, att, getattr(self, att)+sendData.used)
        att = attr+'Transferred'
        setattr(self, att, getattr(self, att)+sendData.transferred)
        att = attr+'CacheLineNumber'
        setattr(self, att, getattr(self, att)+sendData.CacheLineNumber)
        att = attr+'Calls'
        setattr(self, att, getattr(self, att)+sendData.calls)
    def addAggrData(self, other: 'AggregatedData'):
        for att in AggregatedData.getListAttributes():
            setattr(self, att, getattr(self, att)+getattr(other, att))
    def mul(self, val: float, memory: list = None):
        if memory is None:
            memory = AggregatedData.mems
        for mem in memory:
            for rw in AggregatedData.rws:
                for tu in AggregatedData.tus:
                    att = 'ad{}{}{}'.format(mem, rw, tu)
                    setattr(self, att, getattr(self, att)*val)
    def __str__(self):
        resu = ''
        for att in AggregatedData.getListAttributes():
            resu += att+':'+str(getattr(self, att))+'\n'
        return resu

class SendData:
    listAttributes = ['calls', 'amount', 'CacheLineNumber', 'mediaBytes', 'CacheLineUtil', 'used', 'transferred',
              'pattern', 'aligned']
    def getListAttributes() -> list:
        return SendData.listAttributes
    def __init__(self):
        self.stride = dict()
        self.mediaBlockSizes = set()
        self.calls = 0 # software instruction counter (lane)
        self.amount = 0 # hardware instruction counter, SIMD instructions number
        self.CacheLineNumber = 0 # total number of cachelines
        self.CacheLineMax = 0
        self.CacheLineMin = sys.maxsize
        self.mediaBytes = 0
        self.notClAligned = 0
        self.bankDistribution = list()
        # postprocess
        self.CacheLineUtil = 100
        self.used = 0
        self.transferred = 0
        self.strideSumm = 0
        self.pattern = 'Unknown'
        self.send = Send.getDefault()
        self.strideDistribution = [0, 0, 0] # regular, stride, random
        self.trace = list()
        self.aligned = True
    def postProcess(self, send: Send) -> None:
        self.send = send
        self.used = self.send.accessSize * self.calls
        if self.send.isSlm:
            self.transferred = self.used
        elif self.send.isMedia:
            self.transferred = self.mediaBytes
        else:
            self.transferred = self.CacheLineNumber * CACHE_LINE_SIZE
        self.CacheLineUtil = 100 if (self.send.isEot or self.send.isSlm or
                              self.transferred == 0) else(self.used / self.transferred * 100)
        self.strideSumm = sum(self.stride.values())
        return
    def __str__(self) -> str:
        return 'calls:{}, amount:{}, CacheLineNumber:{}, MediaBytes: {}, used: {}, transferred: {}'.format(
            self.calls,
            self.amount,
            self.CacheLineNumber,
            self.mediaBytes,
            self.used,
            self.transferred)
    def merge(self, other: 'SendData', allowDifferent: bool = False) -> None:
        if self.send == Send.getDefault() and other.send != Send.getDefault():
            self.send = other.send
        # it is possible to merge sendData from different sends but equal by attributes
        if not allowDifferent and not self.send.eqByAttr(other.send):
            warning_p('Tried to merge send data from different sends, failed. '
                      '0x{:04x} and 0x{:04x}'.format(self.send.offset, other.send.offset))
            return
        for s in other.stride.keys():
            if s in self.stride:
                self.stride[s] += other.stride[s]
            else:
                self.stride[s] = other.stride[s]
        self.mediaBlockSizes = self.mediaBlockSizes.union(other.mediaBlockSizes)
        self.calls += other.calls
        self.amount += other.amount
        self.notClAligned += other.notClAligned
        self.CacheLineNumber += other.CacheLineNumber
        self.CacheLineMax = max(self.CacheLineMax, other.CacheLineMax)
        self.CacheLineMin = min(self.CacheLineMin, other.CacheLineMin)
        self.mediaBytes += other.mediaBytes
        self.used += other.used
        self.transferred += other.transferred
        self.CacheLineUtil = (self.used/self.transferred*100) if self.transferred > 0 else 100
        self.strideSumm += other.strideSumm
        self.trace += other.trace
        self.detectPattern()
    def mul(self, m: float, attrlist: list = None):
        if attrlist is None:
            attrlist = ['calls', 'amount', 'notClAligned', 'CacheLineNumber',
                        'mediaBytes', 'transferred', 'used']
        for att in attrlist:
            setattr(self, att, int(float(getattr(self, att))*m))
    def detectPattern(self) -> None:
        if self.send.payloadLen > 0:
            sortedStride = sorted(self.stride.items(), key=lambda kv: kv[1], reverse=True)
            if len(sortedStride) > 0:
                # The major pattern is not recognizable pattern
                if sortedStride[0][0] == RANDOM_STRIDE:
                    self.pattern = 'Random'
                # majority of most popular pattern is low
                elif sortedStride[0][1] < RIGHT_STRIDE_LEVEL*self.strideSumm:
                    self.pattern = 'Random'
                # uniform pattern, same address
                elif isInt(sortedStride[0][0]) and int(sortedStride[0][0]) == 0:
                    self.pattern = 'Same Address'
                # stride is equal to access size
                elif isInt(sortedStride[0][0]) and int(sortedStride[0][0]) == self.send.accessSize:
                    self.pattern = 'Regular'
                # major stride is multiple by access size
                elif isInt(sortedStride[0][0]) and self.send.accessSize and (sortedStride[0][0]%self.send.accessSize == 0):
                    self.pattern = 'Stride ' + str(sortedStride[0][0]//self.send.accessSize)
                # not integer stride
                elif isInt(sortedStride[0][0]) and self.send.accessSize:
                    self.pattern = 'Stride {:<3.2f}'.format(
                        float(sortedStride[0][0])/self.send.accessSize)
                # everything else
                else:
                    self.pattern = 'Unknown'
                if self.notClAligned > RANDOM_STRIDE_LEVEL*self.amount:
                    self.aligned = False
            else:
                self.pattern = 'Unknown'
        else:
            self.pattern = 'NA'
        if self.strideSumm:
            self.strideDistribution[distributionCodes['regular']] = self.stride.get(
                self.send.accessSize, 0) / self.strideSumm
            strided = sum([self.stride[x] for x in self.stride if (
                self.stride[x] > RANDOM_STRIDE_LEVEL*self.strideSumm) and
                           (x != self.send.accessSize)])
            self.strideDistribution[distributionCodes['stride']] = strided / self.strideSumm
            random = sum([self.stride[x] for x in self.stride if (
                self.stride[x] < RANDOM_STRIDE_LEVEL*self.strideSumm
            )])
            self.strideDistribution[distributionCodes['random']] = random / self.strideSumm

class SourceFile:
    defaultFileName = 'fileName'
    defaultFilePath = 'filePath'
    def __init__(self, filePath: str, fileName: str, readSource: bool = True):
        self.fileName = fileName
        self.filePath = filePath
        if readSource:
            _ = self.readSourceCode()
        else:
            self.sourceCode = []
        self.index = -1
    def readSourceCode(self) -> int:
        if (self.filePath == SourceFile.defaultFilePath and
                self.fileName == SourceFile.defaultFileName):
            return ERROR_CODE['Success']
        self.sourceCode = []
        fullFileName = os.path.join(self.filePath, self.fileName)
        if not os.path.isfile(fullFileName):
            # warning_p('Source file not found: {}'.format(fullFileName))
            return ERROR_CODE['Cannot read source file']
        if os.path.islink(fullFileName):
            return ERROR_CODE['Link file found']
        try:
            with open(fullFileName, 'r', encoding=ENCODING) as f:
                for row in f.readlines():
                    if row.endswith('\n'):
                        row = row[:-1]
                    self.sourceCode += [row]
        except Exception as e:
            error_p('Can\'t read the source file: \"{}\"'.format(fullFileName))
            exception_p('{}'.format(e))
            return ERROR_CODE['Cannot read source file']
    def getDefault() -> 'SourceFile':
        return SourceFile(SourceFile.defaultFilePath, SourceFile.defaultFileName, False)
    def isDefault(self) -> bool:
        return self == SourceFile.getDefault()
    def __eq__(self, other: 'SourceFile'):
        return self.fileName == other.fileName and self.filePath == other.filePath
    def __str__(self):
        return '{}'.format(os.path.join(self.filePath, self.fileName))

class SourceMap:
    defaultRow = 0
    defaultCol = 0
    def __init__(self, sourceFile: SourceFile, row: int, column: int):
        self.file = sourceFile
        self.row = row
        self.column = column
    def getDefault() -> 'SourceMap':
        return SourceMap(SourceFile.getDefault(), SourceMap.defaultRow, SourceMap.defaultCol)
    def isDefault(self) -> bool:
        return (self.file.isDefault() and self.row == SourceMap.defaultRow and
                self.column == SourceMap.defaultCol)
    def __str__(self):
        return '{}:{}:{}'.format(self.file, self.row, self.column)
    def __eq__(self, other: 'SourceMap'):
        return self.file == other.file and self.row == other.row and self.column == other.column

class Access:
    def __init__(self, sourceMap: SourceMap):
        self.sendOffsets = list()
        self.sourceMap = sourceMap
        self.sendData = None
    def addSend(self, sendOffset: int) -> 'Access':
        self.sendOffsets.append(sendOffset)
        return self
    def __str__(self):
        return 'access. Sends:{}, source:{}, data:{}'.format(
            self.sendOffsets,
            self.sourceMap,
            self.sendData)
    def __eq__(self, other: 'Access'):
        for sendOffset in self.sendOffsets:
            if sendOffset in other.sendOffsets:
                break
        else:
            return False
        return self.sourceMap == other.sourceMap

class WorkGroup:
    def __init__(self, x: int, y: int, z: int):
        self.x = x
        self.y = y
        self.z = z
        self.sendData = dict() # send instruction offset -> SendData
        self.aggregatedDataTotal = AggregatedData()
        self.accesses = list()
        self.sends = dict()
    def getSendData(self, sendOffset: int) -> SendData:
        if sendOffset not in self.sendData:
            self.sendData[sendOffset] = SendData()
        if sendOffset in self.sends:
            self.sendData[sendOffset].send = self.sends[sendOffset]
        return self.sendData[sendOffset]
    def postProcess(self, sends: dict) -> None:
        self.sends = sends
        for sendOffset in self.sends:
            sendData = self.getSendData(sendOffset)
            sendData.postProcess(self.sends[sendOffset])
            # workgroup postprocess
            if self.sends[sendOffset].payloadLen:
                self.aggregatedDataTotal.addSendData(sendData)
    def addAccess(self, access: Access) -> None:
        acc = Access(access.sourceMap)
        acc.sendOffsets = access.sendOffsets
        sd = SendData()
        if len(acc.sendOffsets) > 0:
            sd.send = self.getSendData(acc.sendOffsets[0]).send
            for sendOffset in acc.sendOffsets:
                if sendOffset not in self.sendData:
                    continue
                sd.merge(self.sendData[sendOffset], allowDifferent=True)
        acc.sendData = sd
        self.accesses.append(acc)
    def merge(self, other: 'WorkGroup'):
        for sendOffset in other.sendData:
            if sendOffset in self.sendData:
                self.sendData[sendOffset].merge(other.sendData[sendOffset])
            else:
                self.sendData[sendOffset] = other.sendData[sendOffset]
    def __eq__(self, other):
        return self.x == other.x and self.y == other.y and self.z == other.z

class Enqueue():
    def __init__(self, enqueueId: int):
        self.id = str(enqueueId)
        self.workGroups = dict()
        self.totalThreadsExecuted = 0
        self.aggregatedDataTotal = AggregatedData()
        self.aggregatedDataAvg = AggregatedData()
        self.sendDataTotal = dict()
        self.sendDataAvg = dict()
        self.accesses = list()
        self.sends = dict()
    def getWorkGroup(self, workGroupList) -> WorkGroup:
        workGroupId = '{}_{}_{}'.format(workGroupList[0], workGroupList[1], workGroupList[2])
        self.workGroups[workGroupId] = self.workGroups.get(
            workGroupId,
            WorkGroup(workGroupList[0], workGroupList[1], workGroupList[2]))
        return self.workGroups[workGroupId]
    def getSendDataTotal(self, sendOffset: int) -> SendData:
        if sendOffset not in self.sendDataTotal:
            self.sendDataTotal[sendOffset] = SendData()
        if sendOffset in self.sends:
            self.sendDataTotal[sendOffset].send = self.sends[sendOffset]
        return self.sendDataTotal[sendOffset]
    def getSendDataAvg(self, sendOffset: int) -> SendData:
        if sendOffset not in self.sendDataAvg:
            self.sendDataAvg[sendOffset] = SendData()
        if sendOffset in self.sends:
            self.sendDataAvg[sendOffset].send = self.sends[sendOffset]
        return self.sendDataAvg[sendOffset]
    def postProcess(self, sends) -> None:
        self.sends = sends
        for wg in self.workGroups:
            workGroup = self.workGroups[wg]
            workGroup.postProcess(sends)
            # enqueue postprocess
            self.aggregatedDataTotal.addAggrData(workGroup.aggregatedDataTotal)
            self.aggregatedDataAvg.addAggrData(workGroup.aggregatedDataTotal)
            for sendOffset in workGroup.sendData:
                sendData = workGroup.sendData[sendOffset]
                self.getSendDataTotal(sendOffset).merge(sendData)
                self.getSendDataAvg(sendOffset).merge(sendData)
        if len(self.workGroups) > 1:
            self.aggregatedDataAvg.mul(float(1)/len(self.workGroups))
            for sendOffset in self.sendDataAvg:
                self.sendDataAvg[sendOffset].mul(float(1)/len(self.workGroups))
        ### callibrate filtering
        # find eot offset, amount, correction
        eotOffset = 0
        if len(self.sends) > 0:
            eotOffset = list(self.sends.keys())[-1]
            for so in self.sends:
                if self.sends[so].isEot:
                    eotOffset = so
                    break
        if eotOffset in self.sendDataTotal:
            threadsNumEnq = self.sendDataTotal[eotOffset].amount
            # if DEBUG:
            #     info_p('Total threads analyzed: {}, total number of executed threads: {}'.format(
            #         threadsNumEnq, self.totalThreadsExecuted))
            if threadsNumEnq and self.totalThreadsExecuted:
                mulConst = float(self.totalThreadsExecuted)/threadsNumEnq
                if DEBUG:
                    info_p('multiplication constant: {:f}'.format(mulConst))
                self.aggregatedDataTotal.mul(mulConst)
                self.aggregatedDataAvg.mul(mulConst)
                for sendOffset in self.sendDataTotal:
                    self.sendDataTotal[sendOffset].mul(mulConst)
                for sendOffset in self.sendDataAvg:
                    self.sendDataAvg[sendOffset].mul(mulConst)
            else:
                self.totalThreadsExecuted = threadsNumEnq
        else:
            error_p('Unable to extrapolate filtered data, EOT message not found in Enqueue ID: {}'.format(
                self.id))
        ### Pattern detection
        for sendOffset in self.sendDataAvg:
            self.sendDataAvg[sendOffset].detectPattern()
        for sendOffset in self.sendDataTotal:
            self.sendDataTotal[sendOffset].detectPattern()
    def addAccess(self, access: Access) -> None:
        acc = Access(access.sourceMap)
        acc.sendOffsets = access.sendOffsets
        sd = SendData()
        if len(acc.sendOffsets) > 0:
            if acc.sendOffsets[0] in self.sends:
                sd.send = self.sends[acc.sendOffsets[0]]
                for sendOffset in acc.sendOffsets:
                    if sendOffset not in self.sendDataTotal:
                        continue
                    sd.merge(self.getSendDataTotal(sendOffset), allowDifferent=True)
        acc.sendData = sd
        self.accesses.append(acc)
        for wg in self.workGroups:
            self.workGroups[wg].addAccess(access)
        return acc
    def merge(self, other: 'Enqueue'):
        for attr in ['id']:
            if getattr(self, attr) != getattr(other, attr):
                error_p('{}: \"{}\" and \"{}\"'.format(
                    attr,
                    getattr(self, attr),
                    getattr(other, attr)))
                raise ValueError('Wrong enqueue id')
        self.totalThreadsExecuted += other.totalThreadsExecuted
        for wg in other.workGroups:
            if wg in self.workGroups:
                self.workGroups[wg].merge(other.workGroups[wg])
            else:
                self.workGroups[wg] = other.workGroups[wg]
    def __str__(self):
        return 'Enqueue #: {}, work groups: {}'.format(self.id, len(self.workGroups))

class Kernel:
    def __init__(self, id: int):
        self.name = 'kernel'
        self.traceFiles = list()
        self.enqueues = dict()
        self.sends = dict()
        self.sourceMapping = dict() # offset -> source
        self.accesses = list()
        self.eotOffset = 0
        self.sendDataTotal = dict()
        self.sendDataAvg = dict()
        self.asm = list()
        self.sourceFiles = list()
        self.enqueuesToProfile = list()
        self.id = id
        self.simdw = 0
        self.kernelDriverHash = ''

        self.aggregatedDataTotal = AggregatedData()
        self.aggregatedDataAvg = AggregatedData()
    def getSourceMapBySendOffset(self, sendOffset: int) -> SourceMap:
        self.sourceMapping[sendOffset] = self.sourceMapping.get(sendOffset, SourceMap.getDefault())
        return self.sourceMapping[sendOffset]
    def getAccessBySendOffset(self, sendOffset: int) -> Access:
        for access in self.accesses:
            if sendOffset in access.sendOffsets:
                return access
        error_p('Strange error, unexpected send offset: 0x{:x}. Please report it. Trace may be brocken, results corrupted'.format(sendOffset))
        acc =  Access(SourceMap.getDefault())
        acc.sendOffsets.append(sendOffset)
        self.accesses.append(acc)
        return acc
    def isSendInAccesses(self, sendOffset: int) -> bool:
        for access in self.accesses:
            if sendOffset in access.sendOffsets:
                return True
        return False
    # compare different sends with send data to group them without source mapping.
    def getSameAccess(self, sendOffset) -> Access:
        # check equality of send and send data
        return None
    def getEnqueue(self, enqueueNum: int) -> Enqueue:
        self.enqueues[enqueueNum] = self.enqueues.get(enqueueNum, Enqueue(enqueueNum))
        return self.enqueues[enqueueNum]
    def getSendDataTotal(self, sendOffset: int) -> SendData:
        if sendOffset not in self.sendDataTotal:
            self.sendDataTotal[sendOffset] = SendData()
        if sendOffset in self.sends:
            self.sendDataTotal[sendOffset].send = self.sends[sendOffset]
        return self.sendDataTotal[sendOffset]
    def getSendDataAvg(self, sendOffset: int) -> SendData:
        if sendOffset not in self.sendDataAvg:
            self.sendDataAvg[sendOffset] = SendData()
        self.sendDataAvg[sendOffset] = self.sendDataAvg.get(sendOffset, SendData())
        if sendOffset in self.sends:
            self.sendDataAvg[sendOffset].send = self.sends[sendOffset]
        return self.sendDataAvg[sendOffset]
    def mergeAnalyzed(self, other: 'Kernel'):
        for attr in ['eotOffset', 'id']:
            if getattr(self, attr) != getattr(other, attr):
                error_p('{}: \"{}\" and \"{}\"'.format(
                    attr,
                    getattr(self, attr),
                    getattr(other, attr)))
                raise ValueError('Wrong Kernel Name')
        for enq in other.enqueues:
            if enq in self.enqueues:
                self.enqueues[enq].merge(other.enqueues[enq])
                # error_p('{} in {}'.format(enq, str([x for x in self.enqueues])))
                # raise ValueError('Wrong Enqueue names for kernel: {}'.format(getattr(self, 'name')))
            else:
                self.enqueues[enq] = other.enqueues[enq]
        for send in other.sends:
            if send in self.sends and self.sends[send] != other.sends[send]:
                raise ValueError('Different enqueues to profile for one kernel name')
            self.sends[send] = other.sends[send]
    def addSendOffsetToAccess(self, sendOffset: int) -> None:
        if sendOffset not in self.sends:
            error_p('Strange error, please report it. Trace may be brocken, results corrupted')
            return
        if self.isSendInAccesses(sendOffset):
            return
        send : Send = self.sends[sendOffset]
        sendData = self.getSendDataTotal(sendOffset)
        sourceMap = self.getSourceMapBySendOffset(sendOffset)
        for access in self.accesses:
            if len(access.sendOffsets) == 0:
                error_p('Strange error, please report it. Trace may be brocken, results corrupted')
                continue
            aSendOffset = access.sendOffsets[0]
            if aSendOffset not in self.sends:
                error_p('Strange error, please report it. Trace may be brocken, results corrupted')
                continue
            aSend : Send = self.sends[aSendOffset]
            aSendData = self.getSendDataTotal(aSendOffset)
            aSourceMap = self.getSourceMapBySendOffset(sendOffset)
            if not send.eqByAttr(aSend) or sendData.amount != aSendData.amount or sourceMap != aSourceMap:
                continue
            access.sendOffsets.append(sendOffset)
            return
        # create new access
        newAccess = Access(sourceMap)
        newAccess.sendOffsets.append(sendOffset)
        self.accesses.append(newAccess)
        # if DEBUG: info_p('Created new access with send offset: 0x{:x}'.format(sendOffset))
        return
    def postProcess(self) -> None:
        enqueuesToRemove = list()
        for enq in self.enqueues:
            if len(self.enqueuesToProfile) > 0 and enq not in self.enqueuesToProfile:
                enqueuesToRemove.append(enq)
                continue
            enqueue = self.enqueues[enq]
            enqueue.postProcess(self.sends)
            # kernel postprocess stuff
            self.aggregatedDataTotal.addAggrData(enqueue.aggregatedDataTotal)
            self.aggregatedDataAvg.addAggrData(enqueue.aggregatedDataTotal)
            for sendOffset in enqueue.sendDataTotal:
                sendData = enqueue.sendDataTotal[sendOffset]
                self.getSendDataTotal(sendOffset).merge(sendData)
                self.getSendDataAvg(sendOffset).merge(sendData)
        for enq in enqueuesToRemove:
            self.enqueues.pop(enq)
        enqueuesNum = len(self.enqueues)
        if enqueuesNum > 1:
            self.aggregatedDataAvg.mul(float(1)/enqueuesNum)
            for sendOffset in self.sendDataAvg:
                self.sendDataAvg[sendOffset].mul(float(1)/enqueuesNum)

        ### Pattern detection
        for sendOffset in self.sendDataAvg:
            self.sendDataAvg[sendOffset].detectPattern()
        for sendOffset in self.sendDataTotal:
            self.sendDataTotal[sendOffset].detectPattern()

        ### Group sends into accesses by source line mapping or by similiarity after filtering correction
        # Behaviour:
        #   In caseof source map of send: add it to source mapp access
        #   in case of no source map: group sends by merging alghorithm
        for sendOffset in self.sends:
            self.addSendOffsetToAccess(sendOffset)

        # Copy accesses scel into all enqueues, wgs
        for access in self.accesses:
            access.sendData = SendData()
            for enqueue in self.enqueues:
                acc = self.enqueues[enqueue].addAccess(access)
                # summ sendData from all enqueues into access sendData
                access.sendData.merge(acc.sendData)
    def __str__(self):
        return 'Kernel    "{}" , GTPin ID: {}'.format(
            self.name,
            self.id)

class Application:
    def __init__(self, applicationBin: str, parameters: list):
        self.name = ''
        if applicationBin == '':
            self.name = 'application'
        else:
            self.name = os.path.split(applicationBin)[1]
            if self.name == '' and os.path.split(applicationBin)[0] != '':
                self.name = os.path.split(applicationBin)[0]
        self.applicationBin = applicationBin
        self.parameters = parameters
        self.GTPinVersion = {'major': 0, 'minor': 0, 'patch': '', 'date': 0}
        self.envi = dict()
        self.date = ''
        self.kernelsToProfile = list()
        self.kernelsToProfileRegEx = list()
        self.enqueuesToProfile = list()
        self.kernelRuns = list()
        self.offsetsToProfile = list()
        self.kernels = dict()
        self.executedKernels = dict() # kernelID -> enqueues num
        self.app_loader = list()
        self.resultsDir = ''
        self.scriptDir = ''
        self.existingResults = False
        self.collectMemTrace = False
        self.collectAll = False
        self.maxTraceSize = -1
        self.filterDirection = 'XYZ'
        self.existingResultsDirectory = ''
        self.dirType = dirTypes['error']
        self.collectPercentage = 0
        self.workDirectory = ''
        self.envVars = list()
        self.sourceFiles = list()
        self.analysisVersion = ''
        self.updateStatusEnabled = False
        self.memtracelib = ''
        self.stdOutputPhase1 = ''
        self.stdOutputPhase2 = ''
        self.errOutputPhase1 = ''
        self.errOutputPhase2 = ''

        self.aggregatedDataTotal = AggregatedData()
        self.aggregatedDataAvg = AggregatedData()

    def readPhase1Func(self, kernelName, enqueue, threads, bufferSize, kernelID):
        self.kernels[kernelID] = self.kernels.get(kernelID, Kernel(kernelID))
        self.kernels[kernelID].name = kernelName
        self.executedKernels[kernelID] = self.executedKernels.get(kernelID, 0) + 1
        return True
    def getKernelById(self, kernelID: int) -> Kernel:
        if kernelID not in self.kernels:
            self.kernels[kernelID] = Kernel(kernelID)
        return self.kernels[kernelID]
    def getSourceFile(self, filePath, fileName) -> SourceFile:
        nf = SourceFile(filePath, fileName)
        for fi in self.sourceFiles:
            if nf == fi:
                return fi
        self.sourceFiles.append(nf)
        return nf
    def postProcess(self) -> int:
        for ind, sourceFile in enumerate(self.sourceFiles):
            sourceFile.index = ind
        kernelsToRemove = list()
        ### Aggregated data
        for kernelID in self.kernels:
            kernelName = self.kernels[kernelID].name
            if len(self.kernelsToProfile) > 0 and kernelName not in self.kernelsToProfile:
                kernelsToRemove.append(kernelID)
                continue
            kernel = self.kernels[kernelID]
            kernel.enqueuesToProfile = self.enqueuesToProfile
            kernel.postProcess()
            kernel.sourceFiles = self.sourceFiles
            self.aggregatedDataTotal.addAggrData(kernel.aggregatedDataTotal)
            self.aggregatedDataAvg.addAggrData(kernel.aggregatedDataTotal)
        for kernelID in kernelsToRemove:
            self.kernels.pop(kernelID, None)
        if len(self.kernels) > 1:
            self.aggregatedDataAvg.mul(float(1)/len(self.kernels))
        return ERROR_CODE['Success']

def isInt(num, base = None) -> bool:
    try:
        if base == None:
            int(num)
        else:
            int(num, base)
    except ValueError:
        return False
    return True

def updateStatus(app: Application, stateId: int, message: str = ''):
    global statStrList
    if not app.updateStatusEnabled:
        return
    statStrList.append(message.replace('\n', ''))
    if len(statStrList) > STATUS_FILE_MAX_ROWS_NUM:
        statStrList = statStrList[-STATUS_FILE_MAX_ROWS_NUM:]
    fileName = os.path.join(os.path.split(app.resultsDir)[0], STATUS_FILE_NAME)
    if os.path.islink(fileName):
        sys.exit(ERROR_CODE['Link file found'])
    try:
        with open(fileName, 'w') as f:
            f.write('{}\n{}'.format(stateId, '\n'.join(statStrList)))
    except Exception as e:
        error_p('Unable to write to status file: \"{}\"'.format(fileName))
        exception_p('{}'.format(e))

def processKernelRuns(app: Application, kernel_runs: list):
    for kernelRunEntry in kernel_runs:
        if isInt(kernelRunEntry):
            app.kernelRuns.append(int(kernelRunEntry))
        elif isinstance(kernelRunEntry, str) and kernelRunEntry.count(':') in [1, 2]:
            nums = kernelRunEntry.split(':')
            for num in nums:
                if not isInt(num):
                    warning_p('Unable to recognize kernel_run command line argument: \"{}\"'.format(kernelRunEntry))
                    break
            else:
                if len(nums) == 1:
                    app.kernelRuns.append(int(nums[0]))
                if len(nums) == 2:
                    for x in range(int(nums[0]), int(nums[1])+1):
                        app.kernelRuns.append(int(x))
                if len(nums) == 3:
                    for x in range(int(nums[0]), int(nums[1])+1, int(nums[2])):
                        app.kernelRuns.append(int(x))
        else:
            warning_p('Unable to recognize kernel_run command line argument: \"{}\"'.format(kernelRunEntry))

def processKernelNames(app: Application, kernels: list):
    for kernelName in kernels:
        if kernelName.startswith('regex:'):
            app.kernelsToProfileRegEx.append(kernelName[len('regex:'):])
        else:
            app.kernelsToProfile.append(kernelName)

def setupResultsDir(app: Application) -> int:
    resultsDir = os.path.normpath(app.resultsDir)
    existingResults = app.existingResults
    workDirectory = os.path.normpath(app.workDirectory)

    if workDirectory == '':
        if DEBUG:
            info_p('No working directory specified. Set to \"{}\"'.format(RUN_DIR))
        workDirectory = RUN_DIR
    if not os.path.isdir(workDirectory):
        error_p('Wrong working directory: \"{}\". Terminated'.format(workDirectory))
        return ERROR_CODE['Directory not found']
    if app.resultsDir == '':
        if DEBUG:
            info_p('Report directory not specified.'
                   'Using the working directory: \"{}\"'.format(workDirectory))
        resultsDir = workDirectory
    if not os.path.exists(resultsDir):
        error_p('Report directory not found: \"{}\".'.format(resultsDir))
        return ERROR_CODE['Directory not found']
    currentResultDir = ''
    dirType = dirTypes['error']
    # New result. Check all results in directory, create directory with next number
    if not existingResults:
        if os.path.isdir(resultsDir):
            resNum = -1
            mtaResults = [x for x in os.listdir(resultsDir) if MAA_RESULTS_DIR_PATTERN in x]
            mtaResultsIndexesStr = [x.split(MAA_RESULTS_DIR_PATTERN)[-1] for x in mtaResults]
            mtaResultsIndexes = [int(x) for x in mtaResultsIndexesStr if x.isdigit()]+[resNum]
            resNum = max(mtaResultsIndexes)+1
            currentResultDir = os.path.join(resultsDir, MAA_RESULTS_DIR_PATTERN+str(resNum))
            try:
                os.mkdir(currentResultDir)
                dirType = dirTypes['maa']
            except Exception as e:
                error_p('Unable to create directory: \"{}\"'.format(currentResultDir))
                exception_p('{}'.format(e))
                return ERROR_CODE['Cannot create directory']
        else:
            error_p('Not a directory: \"{}\"'.format(resultsDir))
            return ERROR_CODE['Directory not found']
    else: # check the directory
        # GTPin directory specified
        if (GTPIN_DIR_PATTERN in resultsDir and
                (resultsDir.split(GTPIN_MEMORY_TRACE_DIR_PATTERN)[-1].isdigit()) or 
                (resultsDir.split(GTPIN_STRIDE_DIR_PATTERN)[-1].isdigit())
                ):
            currentResultDir = resultsDir
            dirType = dirTypes['gtpin']
        # Specified memory analysis results directory
        elif (MAA_RESULTS_DIR_PATTERN in resultsDir and
              resultsDir.split(MAA_RESULTS_DIR_PATTERN)[-1].isdigit() and 
              (os.path.isdir(os.path.join(resultsDir, GTPIN_MEMORY_TRACE_DIR_PATTERN+str(1))) or
              os.path.isdir(os.path.join(resultsDir, GTPIN_STRIDE_DIR_PATTERN+str(0))))):
            currentResultDir = resultsDir
            dirType = dirTypes['maa']
        # memorytrace_compressed.bin file
        elif resultsDir.endswith(MEMORY_TRACE_FILE) or resultsDir.endswith(MEMORY_TRACE_FILE_ZIP):
            currentResultDir = resultsDir
            dirType = dirTypes['trace']
        else:
            error_p('Directory not recognized: \"{}\", '.format(resultsDir))
            return ERROR_CODE['Directory not found']
        if DEBUG:
            info_p('Results directory: \"{}\", type: \"{}\"'.format(currentResultDir, list(dirTypes.keys())[list(dirTypes.values()).index(dirType)]))
    app.resultsDir = currentResultDir
    app.dirType = dirType
    app.workDirectory = workDirectory
    return ERROR_CODE['Success']

def setupFiltering(collectPercentage: float, direction: str = 'XYZ', shift: int = 0) -> list:
    result = []
    if 0 > collectPercentage and 100 < collectPercentage:
        warning_p('Filtering value not recognized: {}. Filtering disabled. Specify the filtration value as a percentage'.format(
            collectPercentage))
    else:
        val = '1'
        if collectPercentage == 0:
            val = '"one work group (0;0;0)"'
            result = ['--thread_group_scope',
                      'X:0,Y:0,Z:0']
        elif collectPercentage == 100:
            val = '1'
        elif 0 < collectPercentage < 100:
            val = 100/collectPercentage
            val = 1<<(int(val)-1).bit_length()
            val = str(int(val))
            result = ['--thread_group_scope',
                ','.join(['{D}:min:{S}:step:{V}'.format(D=x, S=shift, V=val) for x in direction])]
        if DEBUG:
            info_p('{}Workgroup stride: {}'.format(
                ('Filtering active. ' if val != '1' else 'Filtering disabled. '),
                val))
    return result

def parseGTPinUniqueName(uniqueName: str):
    rr = uniqueName.split('_')
    if (len(rr) < 4 and WA['OLD_UNIQUE_NAME_FORMAT']) or (len(rr) < 5 and not WA['OLD_UNIQUE_NAME_FORMAT']):
        error_p('Cannot parse GTPin unique name: \"{}\"'.format(uniqueName))
        raise TypeError

    kernelDriverHash = rr[1]

    simdWString = rr[2].replace('simd', '')
    if isInt(simdWString):
        simdw = int(simdWString)
    else:
        error_p('Cannot read SIMD width: \"{}\" in GTPin unique name: \"{}\"'.format(simdWString, uniqueName))
        raise TypeError

    kernelGTPinID = int(rr[3],16)
    if not WA['OLD_UNIQUE_NAME_FORMAT']:
        kernelGTPinID = int(rr[4])

    return (kernelDriverHash, simdw, kernelGTPinID)

def getGTPinVersion(app: Application, gtpinKit):
    def parseGTpinVersion(versionRawString) -> bool:
        versionRaw = versionRawString.split('.')
        if len(versionRaw) > 1 and isInt(versionRaw[0]) and isInt(versionRaw[1]):
            app.GTPinVersion['major'] = int(versionRaw[0])
            app.GTPinVersion['minor'] = int(versionRaw[1])
            if len(versionRaw) >= 3:
                app.GTPinVersion['patch'] = '.'.join(versionRaw[2:])
        else:
            return False
        return True

    if app.existingResults: # read version from json file
        infoJsonFile = os.path.join(app.resultsDir, 'app.report.json')
        if os.path.isfile(infoJsonFile):
            success = True
            with open(infoJsonFile, 'r') as f:
                infoData = dict(json.load(f))
                if 'GTPinVersion' in infoData:
                    versionData = dict(infoData['GTPinVersion'])
                    if 'date' in versionData or set(['major', 'minor']).issubset(versionData):
                        app.GTPinVersion['date'] = versionData.get('date', 0)
                        app.GTPinVersion['major'] = versionData.get('major', 0)
                        app.GTPinVersion['minor'] = versionData.get('minor', 0)
                        app.GTPinVersion['patch'] = versionData.get('patch', '')
                        return True
        else:
            warning_p('Cannot get GTPin version, file not found: "{}"'.format(infoJsonFile))
            return False
        warning_p('Cannot get GTPin version from file: "{}"'.format(infoJsonFile))
        return False
    if READ_GTPIN_VERSION_FROM_FILE:
        infoJsonFile = os.path.join(gtpinKit, 'info.json')
        if os.path.isfile(infoJsonFile): # otherwise try next approach: read it from exe
            success = True
            with open(infoJsonFile, 'r', encoding=ENCODING) as f:
                infoData = dict(json.loads(''.join(f.readlines())))
                if not parseGTpinVersion(infoData.get('version', '0.0')):
                    success = False
                dateGlued = ''.join(['{:>02}'.format(x) for x in infoData.get('date','0-0-0').split('-')])
                if dateGlued == '000':
                    success = False
                if isInt(dateGlued):
                    app.GTPinVersion['date'] = int(dateGlued)
                else:
                    app.GTPinVersion['date'] = 0
                    success = False
            if success:
                return True
        return False
    if READ_GTPIN_VERSION_FROM_GTPIN_EXE:
        gtpinBin = os.path.join(gtpinKit, 'Bin', 'gtpin'+exe)
        if os.path.isfile(gtpinBin):
            success = True
            command = [gtpinBin, '--version']
            process = subprocess.Popen(command, stdout=subprocess.PIPE)
            pipe = process.communicate()
            if process.returncode == 0:
                GTPinOutput = pipe[0].decode('utf-8') # \ngtpin version: GTPin version 2.23 (abe43684)\n
                versionString = 'GTPin version '
                index = GTPinOutput.find(versionString) + len(versionString)
                if not parseGTpinVersion(GTPinOutput[index:].split(' ')[0]):
                    success = False
            else:
                success = False
            if success:
                return True
        else: 
            error_p('GTPin executable not found: {}'.format(gtpinBin))
            return False
    warning_p('Cannot get GTPin version')
    return False

def executeGTPinCommand(app, command, phase: int = 1, subProcess=subprocess) -> int:
    def addOutput(outputType: str, phase: int, string: str):
        setattr(
            app,
            '{}OutputPhase{}'.format(outputType, phase),
            getattr(
                app,
                '{}OutputPhase{}'.format(outputType, phase)
            ) + string)
    if phase not in [1, 2]:
        return ERROR_CODE['GTPin incorrect phase']
    updateStatusEnum = {1: 1, 2: 2}
    try:
        with subProcess.Popen(command, cwd=app.workDirectory, env=app.envi, stdout=subProcess.PIPE,
                            stderr=subProcess.PIPE) as process:
            for line in iter(process.stdout.readline, ''):
                if not line:
                    break
                print(line.decode('utf-8'), end='')
                addOutput('std', phase, str(line.decode('utf-8')))
                updateStatus(app, updateStatusEnum[phase], line.decode('utf-8'))
            for line in iter(process.stderr.readline, ''):
                if not line:
                    break
                print(line.decode('utf-8'), end='')
                addOutput('err', phase, str(line.decode('utf-8')))
            retCode = process.wait()
            addOutput('err', phase, '\nreturn code: {}\n'.format(retCode))
            if retCode:
                error_p('Analysis complete with code: \"{}\"'.format(retCode))
                return ERROR_CODE['GTPin phase 1 fail']
    except Exception as e:
        error_p('Cannot run GTPin phase {}: \"{}\"'.format(
            phase,
            app.workDirectory))
        exception_p('{}\\nl\\{}'.format(e, traceback.format_exc()))
        return ERROR_CODE['GTPin phase {} fail'.format(phase)]
    return ERROR_CODE['Success']

def runGTPinStride(gtpinKit, gtpinArgs: list, app: Application, subProcess=subprocess) -> int:
    if not os.path.isfile(os.path.join(app.workDirectory, app.applicationBin)):
        updateStatus(app, 1, 'Application not found: {}'.format(app.applicationBin))
        error_p('Application not found: {}'.format(app.applicationBin))
        return ERROR_CODE['Application not found']
    app.envi = os.environ.copy()

    for envVar in app.envVars:
        envVarData = envVar.split('=')
        if len(envVarData) == 2:
            app.envi[envVarData[0]] = envVarData[1]
        else:
            warning_p('Unable to recogize env var: {}'.format(envVar))

    gtpinBin = os.path.join(gtpinKit, 'Bin', 'gtpin'+exe)
    if not os.path.isfile(gtpinBin):
        updateStatus(app, 1, 'GTPin executable not found: {}'.format(gtpinBin))
        error_p('GTPin executable not found: {}'.format(gtpinBin))
        return ERROR_CODE['GTPin not found']

    gtpinParameters = list()

    # move stride lib if needed
    strideLibGTPin = os.path.join(gtpinKit, 'Examples', 'intel64', 'stride.so')
    strideLibMAAT = os.path.join(SCRIPT_DIR, 'stride.so')
    if not os.path.isfile(strideLibGTPin) and os.path.isfile(strideLibMAAT):
        shutil.copy2(strideLibMAAT, strideLibGTPin)
    strideLib = 'stride'

    if len(app.memtracelib):
        if os.path.isfile(app.memtracelib):
            strideLib = app.memtracelib
        else:
            warning_p('Memory trace library not found: \"{}\", default library is used'.format(app.memtracelib))
    gtpinParameters += ['-t', strideLib]
    gtpinParameters += ['--allow_sregs', '1']
    if DEBUG:
        gtpinParameters += ['-d']
    if len(gtpinArgs) > 0:
        gtpinParameters += gtpinArgs
    if app.resultsDir != '':
        gtpinParameters += ['--output_dir', os.path.abspath(os.path.join(app.resultsDir))]

    # stride tool run
    gtpinParameters += ['--dump_debug_data']
    gtpinParameters += ['--dump_isa']

    app.envi['IGC_ShaderDumpEnable'] = str(1)
    app.envi['IGC_DumpToCustomDir'] = os.path.join(app.resultsDir, 'shaderdump')
    if len(app.kernelsToProfile) > 0: # specify kernel to profile
        for ker in app.kernelsToProfile:
            gtpinParameters += ['--filter', 'I:name:'+ker]
    if len(app.enqueuesToProfile) > 0: # specify enqueues to profile
        for enq in app.enqueuesToProfile:
            gtpinParameters += ['--enqueue', str(enq)]
    command = app.app_loader + [gtpinBin] + gtpinParameters + ['--', app.applicationBin] + app.parameters
    if DEBUG:
        info_p('GTPin command: {}'.format(' '.join(command)))

    retCode = executeGTPinCommand(app, command, phase = 1, subProcess=subProcess)
    if retCode != ERROR_CODE['Success']:
        warning_p('GTPin stride analysis return code: {}'.format(retCode))

    # Save App output
    for outputType in ['std', 'err']:
        for phase in [1]:
            outputFileName = 'out_{}_phase_{}.txt'.format(outputType, phase)
            try:
                with open(os.path.join(app.resultsDir, outputFileName), 'w') as f:
                    f.write(getattr(app, '{}OutputPhase{}'.format(outputType, phase)))
            except Exception as e:
                warning_p('Save output file: \"{}\"'.format(
                    os.path.join(app.resultsDir, outputFileName)))
                exception_p('{}\\nl\\{}'.format(e, traceback.format_exc()))

    return ERROR_CODE['Success']

def runGTPinMemorytrace(gtpinKit, gtpinArgs: list, app: Application, subProcess=subprocess) -> int:
    def readPhase1Func(kernelName, enqueue, threads, bufferSize, kernelID):
        app.maxTraceSize = max(app.maxTraceSize, bufferSize)
        kernelRun[kernelID] = kernelRun.get(kernelID, 0)
        if kernelRun[kernelID] in app.kernelRuns and enqueue not in app.enqueuesToProfile:
            app.enqueuesToProfile.append(enqueue)
        kernelRun[kernelID] += 1
        if kernelName not in app.kernelsToProfile:
            for regex in app.kernelsToProfileRegEx:
                # if DEBUG: info_p(' [FILTER] Kernel name: "'+kernelName+'" regex: "'+regex+'", enqueue: '+str(enqueue)+', '+('' if bool(re.match(regex, kernelName)) else 'not') +' match')
                if bool(re.match(regex, kernelName)):
                    app.kernelsToProfile.append(kernelName)
                    break
        return True

    kernelRun = app.executedKernels
    updateStatus(app, 1, 'GTPin phase 1')
    if not os.path.isfile(os.path.join(app.workDirectory, app.applicationBin)):
        updateStatus(app, 1, 'Application not found: {}'.format(app.applicationBin))
        error_p('Application not found: {}'.format(app.applicationBin))
        return ERROR_CODE['Application not found']

    app.envi = os.environ.copy()
    for envVar in app.envVars:
        envVarData = envVar.split('=')
        if len(envVarData) == 2:
            app.envi[envVarData[0]] = envVarData[1]
        else:
            warning_p('Unable to recogize env var: {}'.format(envVar))

    gtpinBin = os.path.join(gtpinKit, 'Bin', 'gtpin'+exe)
    if not os.path.isfile(gtpinBin):
        updateStatus(app, 1, 'GTPin executable not found: {}'.format(gtpinBin))
        error_p('GTPin executable not found: {}'.format(gtpinBin))
        return ERROR_CODE['GTPin not found']

    gtpinCommonParameters = []
    memtracelib = 'memorytrace'
    if len(app.memtracelib):
        if os.path.isfile(app.memtracelib):
            memtracelib = app.memtracelib
        else:
            warning_p('Memory trace library not found: \"{}\", default library is used'.format(app.memtracelib))
    gtpinCommonParameters += ['-t', memtracelib]
    gtpinCommonParameters += ['--allow_sregs', '1']
    if DEBUG:
        gtpinCommonParameters += ['-d']
    if len(gtpinArgs) > 0:
        gtpinCommonParameters += gtpinArgs
    if app.resultsDir != '':
        gtpinCommonParameters += ['--output_dir', os.path.abspath(os.path.join(app.resultsDir))]

    # First phase
    gtpinParameters = gtpinCommonParameters.copy()
    gtpinParameters += ['--phase', '1']
    command = app.app_loader + [gtpinBin] + gtpinParameters + ['--', app.applicationBin] + app.parameters
    if DEBUG:
        info_p('GTPin command: {}'.format(' '.join(command)))

    retCode = executeGTPinCommand(app, command, phase = 1, subProcess=subProcess)
    if retCode != ERROR_CODE['Success']:
        warning_p('GTPin analysis phase 1 return code: {}'.format(retCode))

    if len(app.kernelRuns) or len(app.kernelsToProfileRegEx) or app.collectAll:
        fp = os.path.join(app.workDirectory, SW_THREADS_FILE_NAME)
        try:
            if os.path.isfile(fp):
                readFilteringFileData(app, filePath = fp, getDataFunc=readPhase1Func)
            else:
                raise FileExistsError
        except Exception as e:
            error_p('Can\'t find GTPin phase 1 data: \"{}\"'.format(fp))
            exception_p('{}\\nl\\{}'.format(e, traceback.format_exc()))
            return ERROR_CODE['GTPin phase 1 fail']
        if DEBUG: info_p('[Kernel name selection] Kernels to profile:\n\t'+ '\n\t'.join([str(x) for x in app.kernelsToProfile]))

    updateStatus(app, 2, 'GTPin phase 2')
    # Second run 
    gtpinParameters = gtpinCommonParameters.copy()
    gtpinParameters += ['--dump_debug_data']
    gtpinParameters += ['--dump_isa']
    gtpinParameters += ['--max_buffer_mb', str(GTPIN_MEMTRACE_MB)]

    app.envi['IGC_ShaderDumpEnable'] = str(1)
    app.envi['IGC_DumpToCustomDir'] = os.path.join(app.resultsDir, 'shaderdump')
    if (len(app.kernelsToProfile) == 0 and len(app.enqueuesToProfile) == 0 and len(app.kernelsToProfileRegEx) > 0):
        error_p('None of the kernel matches the regex: '+str(app.kernelsToProfileRegEx)+', all kernels will be profiled')
    if len(app.kernelsToProfile) > 0: # specify kernel to profile
        gtpinParameters += ['--filter', ','.join(['I:name:{}'.format(x) for x in app.kernelsToProfile])]
    if len(app.enqueuesToProfile) > 0: # specify enqueues to profile
        for enq in app.enqueuesToProfile:
            gtpinParameters += ['--enqueue', str(enq)]
    gtpinParameters += ['--phase', '2']

    numberOfRuns = 1
    collectPercentage = app.collectPercentage
    if app.collectAll:
        numberOfRuns = 1<<(int(-(-app.maxTraceSize//(GTPIN_MEMTRACE_MB*1024*1024)))-1).bit_length()
        collectPercentage = 100.0 / numberOfRuns
        if DEBUG:
            info_p('Collect all configuration. Required trace size: {}, Max buffer size: {}, Number of runs: {},'
                ' Collect Percentage: {:5.2f}%, Filter directon: {}, Filtering option: {}'.format(
                    app.maxTraceSize, GTPIN_MEMTRACE_MB*1024*1024, 
                    numberOfRuns, collectPercentage, app.filterDirection, setupFiltering(collectPercentage, direction = app.filterDirection)
                ))

    for runNum in range(numberOfRuns):
        if numberOfRuns > 1: info_p('='*10+' GTPin run # {} of {} '.format(runNum+1, numberOfRuns)+'='*10)
        gtpinParametersPhase2 = gtpinParameters.copy()
        gtpinParametersPhase2 += setupFiltering(collectPercentage, direction = app.filterDirection, shift = runNum)
        command = app.app_loader + [gtpinBin] + gtpinParametersPhase2 + ['--', app.applicationBin] + app.parameters
        if DEBUG:
            info_p('GTPin command: {}'.format(' '.join(command)))
        retCode = executeGTPinCommand(app, command, phase = 2, subProcess=subProcess)
        if retCode != ERROR_CODE['Success']:
                warning_p('GTPin analysis phase 2 return code: {}'.format(retCode))

    # Move first phase files to result dir
    try:
        if os.path.isfile(os.path.join(app.workDirectory, PRE_PROC_FILE_NAME)):
            shutil.move(os.path.join(app.workDirectory, PRE_PROC_FILE_NAME),
                    os.path.join(app.resultsDir, PRE_PROC_FILE_NAME))
        else:
            warning_p('Phase 1 file not found: {}'.format(
                os.path.join(app.resultsDir, PRE_PROC_FILE_NAME)))
        if os.path.isfile(os.path.join(app.workDirectory, SW_THREADS_FILE_NAME)):
            shutil.move(os.path.join(app.workDirectory, SW_THREADS_FILE_NAME),
                    os.path.join(app.resultsDir, SW_THREADS_FILE_NAME))
        else:
            warning_p('Normalization file not found: {}'.format(
                os.path.join(app.resultsDir, SW_THREADS_FILE_NAME)))
    except Exception as e:
        warning_p('Cannot copy phase 1 files: \"{}\" & \"{}\"'.format(
            os.path.join(app.workDirectory, PRE_PROC_FILE_NAME), 
            os.path.join(app.workDirectory, SW_THREADS_FILE_NAME)))
        exception_p('{}\\nl\\{}'.format(e, traceback.format_exc()))

    # Save App output
    for outputType in ['std', 'err']:
        for phase in [1, 2]:
            outputFileName = 'out_{}_phase_{}.txt'.format(outputType, phase)
            try:
                with open(os.path.join(app.resultsDir, outputFileName), 'w') as f:
                    f.write(getattr(app, '{}OutputPhase{}'.format(outputType, phase)))
            except Exception as e:
                warning_p('Save output file: \"{}\"'.format(
                    os.path.join(app.resultsDir, outputFileName)))
                exception_p('{}\\nl\\{}'.format(e, traceback.format_exc()))

    return ERROR_CODE['Success']

def getTracesGTPinDir(directory: str) -> dict:
    traceList = dict()
    for kernelHashRaw in os.listdir(os.path.join(directory, 'Session_Final')):
        if kernelHashRaw == 'ISA':
            continue
        _, _, kernelID = parseGTPinUniqueName(kernelHashRaw)
        traceList[kernelID] = list()
        for traceDir in os.listdir(os.path.join(directory, 'Session_Final', kernelHashRaw)):
            localPath = os.path.join(directory, 'Session_Final', kernelHashRaw, traceDir)
            if not os.path.isdir(localPath):
                continue
            if os.path.isfile(os.path.join(localPath, MEMORY_TRACE_FILE_ZIP)):
                if os.path.isfile(os.path.join(localPath, MEMORY_TRACE_FILE)):
                    traceList[kernelID] += [os.path.join(localPath, MEMORY_TRACE_FILE)]
                else:
                    traceList[kernelID] += [os.path.join(localPath, MEMORY_TRACE_FILE_ZIP)]
            elif os.path.isfile(os.path.join(localPath, MEMORY_TRACE_FILE)):
                traceList[kernelID] += [os.path.join(localPath, MEMORY_TRACE_FILE)]
            elif os.path.isfile(os.path.join(localPath, STRIDE_FILE)):
                traceList[kernelID] += [os.path.join(localPath, STRIDE_FILE)]
    return traceList

def getTraces(app: Application) -> int:
    if app.dirType == dirTypes['gtpin']:
        traces = getTracesGTPinDir(app.resultsDir)
        for kernelID in traces:
            if len(traces[kernelID]):
                app.getKernelById(kernelID).traceFiles += traces[kernelID]
    elif app.dirType == dirTypes['maa']:
        gtpinDir = -1
        traces = dict()
        for folder in os.listdir(app.resultsDir):
            if folder.startswith(GTPIN_MEMORY_TRACE_DIR_PATTERN):
                folderNStr = folder[len(GTPIN_MEMORY_TRACE_DIR_PATTERN):]
                folderStr = GTPIN_MEMORY_TRACE_DIR_PATTERN
            elif folder.startswith(GTPIN_STRIDE_DIR_PATTERN):
                folderNStr = folder[len(GTPIN_STRIDE_DIR_PATTERN):]
                folderStr = GTPIN_STRIDE_DIR_PATTERN
            else:
                continue
            if not folderNStr.isdigit():
                continue
            gtpinDir = int(folderNStr)
            sessionFinalDir = os.path.join(
                app.resultsDir, 
                folderStr+str(gtpinDir),
                'Session_Final')
            if not os.path.isdir(sessionFinalDir):
                error_p('GTPin result not found: {}. Interrupting'.format(sessionFinalDir))
                return ERROR_CODE['GTPin result not found']
            traces = getTracesGTPinDir(os.path.join(
                app.resultsDir, 
                folderStr+str(gtpinDir)))
            for kernelID in traces:
                if len(traces[kernelID]):
                    app.getKernelById(kernelID).traceFiles += traces[kernelID]
    elif app.dirType == dirTypes['trace']:
        app.kernels[0] = app.kernels.get(0, Kernel(0))
        app.kernels[0].traceFiles += [app.resultsDir]
    else:
        error_p('GTPin result not found: {}. Interrupting'.format(app.resultsDir))
        return ERROR_CODE['Unknown']
    return ERROR_CODE['Success']

def updateAnalysisStatus(index: int, value: float) -> None:
    global statusArray
    statusArray[index] = value
    if len(statusArray) == 0:
        return
    totalValue = sum(statusArray)/len(statusArray)*100
    print('\r\tAnalyzed: {:5.2f} %           '.format(totalValue), end='')
    if totalValue == 100:
        print()

def updateFileStatus(app: Application) -> None:
    global statStrList
    if not app.updateStatusEnabled or len(statusArray) == 0:
        return
    while True:
        if statStrList[-1].startswith('\tAnalyzed: '):
            statStrList.pop()
        totalValue = sum(statusArray)/len(statusArray)*100
        statusMessage = '\tAnalyzed: {:5.2f} %           '.format(totalValue)
        updateStatus(app, 3, statusMessage)
        if totalValue == 100:
            break
        time.sleep(0.5)

def analyzeStrideFile(
        kernel: Kernel, traceFile: str) -> Kernel:
    pass
    if not os.path.isfile(traceFile):
        error_p('Trace file not found: {}'.format(traceFile))
        return kernel
    sends = kernel.sends
    numOfSends = {}
    getOffset = {}
    cacheLines = set()
    stride = 0
    numOfRecords = 0
    numOfThreads = 0
    threadsInd = 0
    recordsInd = 0
    if os.path.islink(traceFile):
        return kernel
    try:
        with open(traceFile, 'r') as fIn:
            pass
            enqueueNum = 0
            try:
                enqueueNum = int(os.path.split(traceFile)[0].split('_')[-1])
            except Exception as e:
                error_p('Cannot get enqueue number: \"{}\"'.format(traceFile))
                exception_p('{}'.format(e))
            enqueue = kernel.getEnqueue(enqueueNum)
            workGroupId = (0, 0, 0)
            workGroup = enqueue.getWorkGroup(workGroupId)
            lines = fIn.readlines()
            linesNum = len(lines)
            currentLine = 0
            while (currentLine < linesNum):
                dd = lines[currentLine][:-1].split(' ')
                currentLine -= -1
                if dd[0].startswith('S_'):
                    offset = int(dd[1])
                    attr = int(dd[2])
                    execSize = int(dd[3])
                    channelOffset = int(dd[4])
                    amount = int(dd[5]) # hw count
                    cachelines = int(dd[6])
                    strideNum = int(dd[7])
                    calls = int(dd[8]) # lanes
                    notClAligned = int(dd[9])
                    ovfLow = int(dd[10])
                    ovfHigh = int(dd[11])
                    sends[offset] = sends.get(offset, Send(offset, attr, execSize, channelOffset))
                    sendData = workGroup.getSendData(offset)
                    sendData.calls += calls
                    sendData.amount += amount
                    if not sends[offset].isSlm:
                        sendData.CacheLineNumber += cachelines
                        sendData.notClAligned += notClAligned
                    for _ in range(strideNum):
                        dd = lines[currentLine][:-1].split(' ')
                        currentLine -= -1
                        sendData.stride[int(dd[4])] = sendData.stride.get(int(dd[4]), 0) + int(dd[5])
                    if ovfHigh:
                        sendData.stride['ovfHigh'] = int(ovfHigh)
                    if ovfLow:
                        sendData.stride['ovfLow'] = int(ovfLow)
    except Exception as e:
        error_p('Can\'t read file: \"{}\"{}{}'.format(
            traceFile,
            (' at thread {} of {} threads'.format(threadsInd, numOfThreads) if (numOfThreads and threadsInd) else ''),
            (' and at record {} of {} records'.format(numOfRecords, recordsInd) if (numOfRecords and recordsInd) else '')))
        exception_p('{}'.format(e))
        return kernel
    return kernel

### Callback function example
# def sendCallback(offset, send, sendData, tid, addresses): # pylint: disable=unused-argument
#     return False # for continue default analysis
#     return True # for avoid default analysis

def collectMemTrace(offset, send, sendData, tid, addresses, offsetsToProfile) -> bool: # pylint: disable=unused-argument
    if offset in offsetsToProfile:
        sendData.trace.append([offset, tid, addresses.copy()])
        return True # for avoid default analysis

def analyzeTraceFile(kernel: Kernel, traceFile: str, allowCompress=True, index: int = 0,
                     sendCallbackFunc=lambda offset, send, sendData, tid, addresses: False) -> Kernel:
    # pylint: disable=line-too-long,too-many-nested-blocks,too-many-statements
    if not os.path.isfile(traceFile):
        error_p('Trace file not found: {}'.format(traceFile))
        updateAnalysisStatus(index, 1)
        return kernel
    sends = kernel.sends
    numOfSends = {}
    getOffset = {}
    cacheLines = set()
    stride = 0
    numOfRecords = 0
    numOfThreads = 0
    threadsInd = 0
    recordsInd = 0
    if os.path.islink(traceFile):
        return kernel
    try:
        openFunction = None
        if traceFile.endswith(MEMORY_TRACE_FILE_ZIP): # uncompress it
            openFunction = gzip.open
        elif traceFile.endswith(MEMORY_TRACE_FILE):
            openFunction = open
        else:
            error_p('Trace file not recognized: \"{}\", format not recognized: \"{}\"'.format(
                traceFile, traceFile[-4:]))
            updateAnalysisStatus(index, 1)
            return kernel
        with openFunction(traceFile, 'rb') as fIn:
            enqueueNum = 0
            try:
                enqueueNum = int(os.path.split(traceFile)[0].split('_')[-1])
            except Exception as e:
                error_p('Cannot get enqueue number: \"{}\"'.format(traceFile))
                exception_p('{}'.format(e))
            enqueue = kernel.getEnqueue(enqueueNum)
            workGroupId = (0, 0, 0)
            workGroup = enqueue.getWorkGroup(workGroupId)
            
            # read header
            bblNum = struct.unpack('I', fIn.read(4))[0]
            for _ in range(bblNum):
                bblId = struct.unpack('I', fIn.read(4))[0]
                numOfSends[bblId] = struct.unpack('I', fIn.read(4))[0]
                getOffset[bblId] = [0]*numOfSends[bblId]
                for s in range(numOfSends[bblId]):
                    send = Send(fIn)
                    offset = send.offset
                    sends[offset] = sends.get(offset, send)
                    getOffset[bblId][s] = offset
            registerSizeBits  =  struct.unpack('I', fIn.read(4))[0]*8
            numOfTiles = 1
            if WA['TILE_ID_SUPPORTED']:
                numOfTiles = struct.unpack('I', fIn.read(4))[0]
            for tileIdx in range(numOfTiles):
                if WA['TILE_ID_SUPPORTED']:
                    TileID = int(struct.unpack('I', fIn.read(4))[0])
                numOfThreads = struct.unpack('I', fIn.read(4))[0] # number of used EUs threads
                # read trace
                for threadsInd in range(numOfThreads): # for all threads
                    updateAnalysisStatus(index, float(threadsInd) / numOfThreads)
                    SliceID = int(struct.unpack('I', fIn.read(4))[0])
                    DualSubSliceID = int(struct.unpack('I', fIn.read(4))[0])
                    SubSliceID = int(struct.unpack('I', fIn.read(4))[0])
                    EuId = int(struct.unpack('I', fIn.read(4))[0])
                    Id = int(struct.unpack('I', fIn.read(4))[0])
                    tidl = [SliceID, DualSubSliceID, SubSliceID, EuId, Id]
                    numOfRecords = int(struct.unpack('I', fIn.read(4))[0])
                    for recordsInd in range(numOfRecords): # for all records in thread
                        bblId = struct.unpack('I', fIn.read(4))[0]
                        execMask = struct.unpack('I', fIn.read(4))[0]
                        for s in range(numOfSends[bblId]):
                            offset = getOffset[bblId][s]
                            send = sends[offset]
                            payloadLen = send.payloadLen
                            sendData = workGroup.getSendData(offset)
                            if payloadLen > 0:
                                addrWidth = send.addrWidth
                                if not send.isScatter and payloadLen != 1:
                                    warning_p('The scatter send has payload > 1. Trace corrupted')
                                pl = payloadLen*registerSizeBits//addrWidth # count of addresses
                                addresses = array.array('I' if addrWidth == 32 else 'Q')
                                addresses.fromfile(fIn, pl)
                                if bblId == 0 and offset == 0:
                                    workGroupId = (addresses[1], addresses[6], addresses[7])
                                    workGroup = enqueue.getWorkGroup(workGroupId)
                                    continue
                                if sendCallbackFunc(offset, send, sendData, tidl, addresses):
                                    continue
                                if send.isMedia:
                                    sendData.amount += 1
                                    sendData.calls += 1
                                    Xoffset = addresses[0]
                                    # Yoffset = addresses[1]
                                    control = addresses[2]
                                    width = (control & 0x3F) + 1 # Bytes
                                    heigth = ((control >> 16) & 0x3F) + 1 # Rows
                                    send.accessSize = width * heigth
                                    sendData.CacheLineNumber += heigth*(1 if (Xoffset//CACHE_LINE_SIZE) == ((Xoffset+width-1)//CACHE_LINE_SIZE) else 2)
                                    sendData.mediaBytes += width * heigth
                                    sendData.mediaBlockSizes.add((width, heigth))
                                    continue
                                if send.isScatter: # scatter
                                    sendData.amount += 1
                                    prev = 0
                                    if not send.execSize:
                                        continue
                                    if send.isSlm:
                                        if execMask & (1 << (send.channelOffset)):
                                            addr = addresses[0]
                                            prev = addr
                                            sendData.calls += 1
                                        for a in range(1, min(pl, send.execSize)): # for Threads in SIMD (one memory access)
                                            addr = addresses[a]
                                            if execMask & (1 << (send.channelOffset + a)):
                                                stride = addr - prev
                                                if stride in sendData.stride:
                                                    sendData.stride[stride] += 1
                                                else:
                                                    sendData.stride[stride] = 1
                                                prev = addr
                                                sendData.calls += 1
                                    else:
                                        cacheLines.clear()
                                        if execMask & (1 << (send.channelOffset)):
                                            addr = addresses[0]
                                            prev = addr
                                            cacheLines.add(addr//CACHE_LINE_SIZE)
                                            sendData.calls += 1
                                        for a in range(1, min(pl, send.execSize)): # for Threads in SIMD (one memory access)
                                            addr = addresses[a]
                                            if execMask & (1 << (send.channelOffset + a)):
                                                stride = addr - prev
                                                if stride in sendData.stride:
                                                    sendData.stride[stride] += 1
                                                else:
                                                    sendData.stride[stride] = 1
                                                prev = addr
                                                cacheLines.add(addr//CACHE_LINE_SIZE)
                                                sendData.calls += 1
                                        if addresses[0] % CACHE_LINE_SIZE != 0:
                                            sendData.notClAligned += 1
                                        sendData.CacheLineNumber += len(cacheLines)
                                        sendData.CacheLineMax = max(len(cacheLines), sendData.CacheLineMax)
                                        sendData.CacheLineMin = min(len(cacheLines), sendData.CacheLineMin)
                                else: # unscattered
                                    sendData.amount += 1
                                    addr = addresses[2]
                                    sendData.CacheLineNumber += 1 if (addr%CACHE_LINE_SIZE + send.accessSize <= CACHE_LINE_SIZE) else 2
                                    sendData.calls += 1
                            else:
                                sendData.amount += 1
                                if sendCallbackFunc(offset, send, sendData, tidl, []):
                                    continue
    except Exception as e:
        error_p('Can\'t read file: \"{}\"{}{}'.format(
            traceFile,
            (' at thread {} of {} threads'.format(threadsInd, numOfThreads) if (numOfThreads and threadsInd) else ''),
            (' and at record {} of {} records'.format(numOfRecords, recordsInd) if (numOfRecords and recordsInd) else '')))
        exception_p('{}'.format(e))
        return kernel
    if allowCompress and traceFile.endswith(MEMORY_TRACE_FILE): # compress trace file
        if os.path.islink(traceFile):
            return kernel
        try:
            with open(traceFile, 'rb') as fIn:
                with gzip.open(traceFile+'.gz', 'wb') as fOut:
                    shutil.copyfileobj(fIn, fOut)
            os.remove(traceFile)
        except Exception as e:
            error_p('Trace file compression error: \"{}\"'.format(traceFile))
            exception_p('{}\\nl\\{}'.format(e, traceback.format_exc()))
    updateAnalysisStatus(index, 1)
    return kernel

def getAsm(app: Application):
    BBL_STRING = '// BBL'
    try:
        asmFilesPath = ''
        if app.dirType == dirTypes['maa']:
            if app.stride:
                asmFilesPath = os.path.join(
                    app.resultsDir,
                    GTPIN_STRIDE_DIR_PATTERN+str(0),
                    # 'Session_Final',
                    'ISA')
            else:
                asmFilesPath = os.path.join(
                    app.resultsDir,
                    GTPIN_MEMORY_TRACE_DIR_PATTERN+str(1),
                    # 'Session_Final',
                    'ISA')
        elif app.dirType == dirTypes['gtpin']:
            asmFilesPath = os.path.join(app.resultsDir, 'ISA') # 'Session_Final',
        elif app.dirType == dirTypes['trace']:
            warning_p('Can\'t find ISA files for this type of results folder \"{}\"'.format(
                app.resultsDir))
        else:
            error_p('Wrong file type: \"{}\", type: \"{}\"'.format(
                app.resultsDir, app.dirType))
            return ERROR_CODE['Cannot read ASM file']
        if not os.path.isdir(asmFilesPath):
            error_p('Incorrect ISA directory: \"{}\", type: \"{}\"'.format(
                asmFilesPath, app.dirType))
            return ERROR_CODE['Cannot read ASM file']

        reportAsmDir = os.path.join(app.resultsDir, ASM_DIR)
        if not os.path.isdir(reportAsmDir):
            os.mkdir(reportAsmDir)
        asmFileNames = os.listdir(asmFilesPath)
        if DEBUG: info_p('Assembly files directory: {} has {} files: {}'.format(asmFilesPath, len(asmFileNames), asmFileNames))
        for kernelID, kernel in app.kernels.items():
            kernelName = kernel.name
            fullFileName = ''
            lastFileName = ''
            for asmFileName in asmFileNames:
                _, _, kernelFileID = parseGTPinUniqueName(asmFileName)
                if kernelFileID == kernelID:
                    lastFileName = asmFileName
                    break
            else:
                warning_p('Assembly file not found for kernel: \"{}\"'.format(kernelName))
                continue
            fullFileName =  os.path.join(asmFilesPath, lastFileName)
            if DEBUG: info_p('Assembly file \"{}\"\n\t for kernel \"{}\" found'.format(fullFileName, kernelName))
            if os.path.islink(fullFileName):
                warning_p('Unable to work with {}'.format(fullFileName))
                continue
            with open(fullFileName, 'r', encoding=ENCODING) as f:
                bbl_n = 0
                curr_instr_num = 0
                for row in f.readlines():
                    row_split = row[:-1].split(']  */')
                    if isInt(row_split[0].replace('/* [', ''), 16):
                        curr_instr_num += 1
                        instr_num = str(curr_instr_num)
                        offset = str(int(row_split[0].replace('/* [', ''), 16))
                        asm = row_split[1]
                    else:
                        instr_num = '-1'
                        offset = '-1'
                        asm = row[:-1]
                    if asm.startswith(BBL_STRING):
                        bbl_n = asm[len(BBL_STRING):].split(' ')[0]
                    try:
                        instr_num = int(instr_num.replace(' ', ''))
                        offset = int(offset)
                        bbl_n = int(bbl_n)
                        kernel.asm.append([instr_num, offset, asm])
                    except Exception as e:
                        warning_p('Asm was not recognized: '
                                  '\"{}\",\"{}\",\"{}\" in file: \"{}\"'.format(
                                      instr_num,
                                      offset,
                                      bbl_n,
                                      fullFileName))
                        exception_p('{}\\nl\\{}'.format(e, traceback.format_exc()))
                # [print(a) for a in kernel.asm] # print asm to console
            fileEx = '.asm'
            reportAsmFile = os.path.join(reportAsmDir, kernelName[:MAX_FILE_NAME_LENGTH-len(fileEx)]+fileEx)
            if os.path.islink(reportAsmFile):
                continue
            with open(reportAsmFile, 'w') as f:
                for row in kernel.asm:
                    f.write('{:10}{}\n'.format('[0x{:06x}]'.format(row[1])
                                               if row[1] >= 0 else '', row[2]))
    except Exception as e:
        error_p('Error reading asm file')
        exception_p('{}\\nl\\{}'.format(e, traceback.format_exc()))
        return ERROR_CODE['Cannot read ASM file']
    return ERROR_CODE['Success']

def getSourceLineMapping(app: Application):
    shaderDir = os.path.join(app.resultsDir, 'shaderdump')
    elfDir = ''
    if app.dirType == dirTypes['gtpin']:
        elfDir = os.path.join(app.resultsDir, 'TMP')
    else:
        elfDir = os.path.join(app.resultsDir, GTPIN_MEMORY_TRACE_DIR_PATTERN + '1', 'TMP')

    if not os.path.isdir(elfDir):
        error_p('Debug data directory not found: {}'.format(elfDir))
        return ERROR_CODE['Debug data not found']
    elfFiles = [x for x in os.listdir(elfDir) if x.endswith('.elf')]
    if DEBUG: info_p('Debug data directory: {}, has {} \'*.elf\' files: \n\t{}'.format(elfDir, len(elfFiles), '\n\t'.join([x for x in elfFiles])))
    for kernelID, kernel in app.kernels.items():
        kernelName = kernel.name
        lastFileName = ''
        lastKernelDriverHash = 'asm0'
        for elfFile in elfFiles:
            kernelDriverHash, _, kernelGTPinID = parseGTPinUniqueName(elfFile.replace('.elf', ''))
            if kernelGTPinID != kernelID:
                continue
            lastFileName = elfFile
            lastKernelDriverHash = kernelDriverHash
            break
        else:
            warning_p('Elf file not found for kernel: {}'.format(kernelName))
            continue

        elfFileFull = os.path.join(elfDir, lastFileName)
        if not os.path.isfile(elfFileFull):
            error_p('Error reading file: {}'.format(elfFileFull))
            continue
        try:
            mapping = getMappingFromFile(elfFileFull)
            for offset in [x[1] for x in kernel.asm if x[1] >= 0]:
                m = mapping.getitem(offset)
                filePath = m[0]
                fileName = m[1]
                row = m[2]
                column = m[3]
                fullFileName = os.path.join(filePath, fileName)
                if not os.path.isfile(fullFileName) and os.path.isdir(shaderDir):
                    filePath = os.path.join(shaderDir)
                    clFiles = [x for x in os.listdir(filePath) if x.endswith('.cl')
                            and x.startswith('_'.join(['OCL', lastKernelDriverHash]))]
                    if len(clFiles) > 0:
                        fileName = clFiles[0]
                kernel.sourceMapping[offset] = SourceMap(
                    app.getSourceFile(filePath, fileName),
                    row,
                    column)
            if DEBUG: info_p('Source maping for the kernel \"{}\" has {} records, elf file: {}'.format(kernelName, len(kernel.sourceMapping), lastFileName))
            # print source mapping for each instruction
            # [print(x, kernel.sourceMapping[x]) for x in kernel.sourceMapping]
        except Exception as e:
            error_p('Can\'t read debug information: \"{}\"'.format(elfFileFull))
            exception_p('{}'.format(e))
    return ERROR_CODE['Success']

def readFilteringFileData(app: Application, filePath = None, getDataFunc = None):
    if app.stride:
        return ERROR_CODE['Success']
    if filePath == None:
        filePath = ''
        if app.dirType == dirTypes['maa']:
            filePath = os.path.join(app.resultsDir, SW_THREADS_FILE_NAME)
        elif app.dirType == dirTypes['gtpin']:
            filePath = os.path.join(app.resultsDir, '..', SW_THREADS_FILE_NAME)
        elif app.dirType == dirTypes['trace']:
            warning_p('Filtration correction is not supported in case of trace analysis')
            return ERROR_CODE['Success']
        else:
            error_p('Wrong file type: \"{}\", type: \"{}\"'.format(app.resultsDir, app.dirType))
            return ERROR_CODE['Unknown']
    if DEBUG:
        info_p('Filtering file: \"{}\"'.format(filePath))
    if os.path.islink(filePath):
        return ERROR_CODE['Link file found']
    try:
        with open(filePath, 'r', encoding=ENCODING) as f:
            for row in f.readlines():
                row = row.replace('\n', '')
                rr = row.split(' ')
                rr = [x for x in rr if x != '']
                if len(rr)!=6:
                    warning_p('Normalization file read error, cannot read line: {}'.format(row))
                    continue
                uniqueName = '_'.join(rr[0].split('_')[-4:]) if WA['OLD_UNIQUE_NAME_FORMAT'] else '_'.join(rr[0].split('_')[-5:])
                kernelName = '_'.join(rr[0].split('_')[:-6]) if WA['OLD_UNIQUE_NAME_FORMAT'] else '_'.join(rr[0].split('_')[:-7])
                kernelDriverHash, simdw, kernelGTPinID = parseGTPinUniqueName(uniqueName)
                kernel = app.getKernelById(kernelGTPinID)
                kernel.kernelDriverHash = kernelDriverHash
                kernel.simdw = simdw
                enqueue = int(rr[5])
                threads = int(rr[2])
                bufferSize = int(rr[1])
                if getDataFunc != None and getDataFunc(kernelName, enqueue, threads, bufferSize, kernelGTPinID): continue
                if DEBUG:
                    info_p('Read filtering file. kernel: {}, kernel hash: {}, '
                           'enqueue: {}, threads executed: {}, simd width: {}, '
                           'GTPin ID: {}'.format(
                            kernelName,
                            kernelDriverHash,
                            enqueue,
                            threads,
                            simdw,
                            kernelGTPinID
                            ))
                kernel.getEnqueue(enqueue).totalThreadsExecuted = threads
    except Exception as e:
        error_p('Normalization file read failure: \"{}\"'.format(
            os.path.join(app.resultsDir, SW_THREADS_FILE_NAME)))
        exception_p('{}\\nl\\{}'.format(e, traceback.format_exc()))
        return ERROR_CODE['Cannot read file']
    return ERROR_CODE['Success']

def main(argv):
    global DEBUG, statusArray, PARALLEL_ANALYSIS, WA
    # parse arguments
    parser = argparse.ArgumentParser(description='GPU Memory Access Ananlysis')
    parser.add_argument(
        'application',
        metavar='APPLICATION',
        default='application',
        type=str, nargs='?',
        help='Profiled application')
    parser.add_argument(
        'parameters',
        metavar='PARAMETERS',
        default=[],
        type=str,
        nargs='*',
        help='Parameters')
    parser.add_argument(
        '-w',
        '--work_directory',
        metavar='DIRECTORY',
        default='',
        dest='work_directory',
        help='Work directory of application')
    parser.add_argument(
        '-f',
        '--report_directory',
        metavar='DIRECTORY',
        default='',
        dest='report_directory',
        help='Directory to save or analysis results')
    parser.add_argument(
        '-E',
        '--env_var',
        metavar='ENVIRONMENT_VARIABLE',
        default=[],
        dest='env_vars',
        action='append',
        help='Specify environment variables for application')
    parser.add_argument(
        '-k',
        '--kernel',
        metavar='KERNEL_NAME',
        default=[],
        dest='kernels',
        action='append',
        help='Name of the profiled kernel. For regex use \"regex:\" prefix \"--kernel regex:compute_kernel_name_.*\"')
    parser.add_argument(
        '-r',
        '--result',
        default='',
        dest='existing',
        help='Specify the existing result directory for analysis, application will not start')
    parser.add_argument(
        '-e',
        '--enqueue',
        metavar='ENQUEUE_NUM',
        default=[],
        type=int,
        dest='enqueues',
        action='append',
        help='Enqueues to profile')
    parser.add_argument(
        '--kernel_run',
        metavar='RUN_N',
        default=[],
        type=str,
        dest='kernel_runs',
        action='append',
        help='Specify kernel run number to profile. Applied for all analyzed kernels. Accepted multiple times.'
        'Examples: \"--kernel_run 0 --kernel_runs 4\" - profile enqueues 0 and 4 for all kernels; '
        '\"--kernel_run 2:6\" - profile enqueues from 2 to 6 (2,3,4,5,6) for all kernels; '
        '\"--kernel_run 2:10:3\" - profile enqueues from 2 to 10 with step 3 (2,5,8) for all kernels;')
    parser.add_argument(
        '-l',
        '--limit',
        metavar='VALUE',
        default=0.1,
        type=float,
        dest='limit',
        help='Filter by workgroup, in percentage. Examples: \"-l 50\" - profiles each second workgroup(50%%), \"-l 25\" - profiles each forth workgroup(25%%). Also: \"-l 0\" profiles only workgroup (0;0;0)')
    parser.add_argument(
        '--collect_all',
        default=False,
        dest='collect_all',
        action='store_true',
        help='Run application as many times as needed to collect all enqueues')
    parser.add_argument(
        '-g',
        '--gtpin',
        metavar=os.path.join('path', 'to', 'Profillers'),
        default=os.path.join(SCRIPT_DIR, 'Profilers'),
        dest='gtpin_kit',
        help='Path to specific GTPin Profilers directory')
    parser.add_argument(
        '-a',
        '--gtpin_args',
        metavar='ARGS',
        default=[],
        dest='gtpin_args',
        action='append',
        help='Arguments, passed to GTPin')
    parser.add_argument(
        '-V',
        '--version',
        default=False,
        dest='version',
        action='store_true',
        help='Print version')
    parser.add_argument(
        '-d',
        '--debug',
        default=DEBUG,
        dest='debug',
        action='store_true',
        help='Print debug output')
    parser.add_argument(
        '-m',
        '--memtrace',
        metavar=os.path.join('path', 'to', 'memorytrace.so'),
        default='',
        dest='library',
        help='Path to specific memorytrace tool')
    parser.add_argument(
        '-s',
        '--stride',
        default=False,
        dest='stride',
        action='store_true',
        help='Use stride tool for analysis')
    parser.add_argument(
        '-se',
        '--status_enable',
        default=False,
        dest='stat_enable',
        action='store_true',
        help='Enable store status on drive, used for automated analysis')
    parser.add_argument(
        '--disable_parallel_analysis',
        default=False,
        dest='disable_parallel_analysis',
        action='store_true',
        help='Disable parrallel trace processing')
    parser.add_argument(
        '--pvc',
        default=False,
        dest='pvc',
        action='store_true',
        help='[Deprecated, no more needed] Work with PVC/DG2')
    parser.add_argument(
        '-t',
        '--collect_mem_trace',
        default=False,
        dest='collect_mem_trace',
        action='store_true',
        help='Generate memory trace report with all memory accesses')
    parser.add_argument(
        '--app_loader',
        default='',
        dest='app_loader',
        help='Specify application loader, that should be run. For example, mpirun')
    parser.add_argument(
        '-i',
        '--offset',
        metavar='SEND_OFFSET',
        default=[],
        dest='send_offsets',
        action='append',
        help='Analize only specified send offsets')

    if argv == 'sys':
        args = parser.parse_args()
    elif isinstance(argv, list):
        args = parser.parse_args(argv)
    else:
        error_p('Arguments are not recognized')
        return ERROR_CODE['Arguments not recognized']

    if args.version:
        info_p('Memory Access Analysis\nVersion: {}'.format(MAAVersion))
        return ERROR_CODE['Success']
    gtpinKit = args.gtpin_kit
    gtpinArgs = args.gtpin_args
    applicationBin = args.application
    applicationParameters = args.parameters

    app = Application(applicationBin, applicationParameters)
    app.date = str(datetime.datetime.now())
    app.analysisVersion = MAAVersion
    app.enqueuesToProfile = args.enqueues
    processKernelRuns(app, args.kernel_runs)
    processKernelNames(app, args.kernels)
    for offset in args.send_offsets:
        app.offsetsToProfile.append(int(offset, 0))
    app.collectMemTrace = args.collect_mem_trace
    app.workDirectory = args.work_directory
    app.resultsDir = args.report_directory
    app.scriptDir = SCRIPT_DIR
    DEBUG = args.debug
    if args.existing != '':
        app.existingResults = True
        app.resultsDir = args.existing
    app.envVars = args.env_vars
    app.updateStatusEnabled = args.stat_enable
    app.memtracelib = args.library
    app.collectAll = args.collect_all
    if app.collectAll: 
        app.filterDirection = COLLECT_ALL_DIRECTION
    app.stride = args.stride
    if args.app_loader != '':
        app.app_loader = args.app_loader.replace('\t',' ').split(' ')
    try:
        app.collectPercentage = float(args.limit)
    except Exception as e:
        warning_p('Input value was not recognized as a number: \"{}\", filtering disabled.'.format(args.limit))
    if args.disable_parallel_analysis or WA['DISABLE_MULTIPROCESSING']:
        PARALLEL_ANALYSIS = False

    if args.pvc:
        warning_p('\"--pvc\" option was deprecated. PVC/DG2 hardware is detected automatically')

    if DEBUG:
        info_p('Command line arguments: {}\\nl\\Recognized as: {}'.format((sys.argv if argv == 'sys' else argv), args))

    try:
        if getGTPinVersion(app, gtpinKit):
            WA['OLD_UNIQUE_NAME_FORMAT'] = app.GTPinVersion['date'] < 20221027
            WA['TILE_ID_SUPPORTED'] = app.GTPinVersion['date'] > 20221105
        else:
            app.GTPinVersion['date'] = 20300000
        if DEBUG:
            info_p('GTPin build: ' + str(app.GTPinVersion['date']))
            info_p(str('Status of WA:\n\t' + '\n\t'.join([str((name, value)) for name, value in WA.items()])))
    except Exception as e:
        warning_p('Cannot read GTPin version')
        exception_p('{}\\nl\\{}'.format(e, traceback.format_exc()))

    returnCode = setupResultsDir(app)
    if returnCode != ERROR_CODE['Success'] or app.dirType == dirTypes['error']:
        error_p('Directory not found. Interrupting')
        updateStatus(app, -1, getErrorMsg(returnCode))
        return returnCode

    updateStatus(app, 1, 'Preparation')

    if not app.existingResults: # run GTPin - collect result
        returnCode = ERROR_CODE['Success']
        if app.stride:
            returnCode = runGTPinStride(gtpinKit, gtpinArgs, app)
        else:
            returnCode = runGTPinMemorytrace(gtpinKit, gtpinArgs, app)
        if returnCode != ERROR_CODE['Success']:
            error_p('GTPin run fail: \"{}\"'.format(getErrorMsg(returnCode)))
            updateStatus(app, -1, getErrorMsg(returnCode))
            return returnCode

    updateStatus(app, 3, 'Postprocess')

    if not app.stride:
        returnCode = readFilteringFileData(app, getDataFunc=app.readPhase1Func) # read phase 1 data
        if returnCode != ERROR_CODE['Success']:
            warning_p('Filtering data could not be found. Results may be incorrect')
            updateStatus(app, 3, getErrorMsg(returnCode))

    returnCode = getTraces(app) # read list of memory traces
    if returnCode != ERROR_CODE['Success']:
        error_p('Error reading memory trace: \"{}\"'.format(getErrorMsg(returnCode)))
        updateStatus(app, -1, getErrorMsg(returnCode))
        return returnCode

    if not app.stride:
        kernelIDs = set(app.kernels)
        executedKernelsIDs = set([x for x in app.executedKernels if app.executedKernels[x] > 0])
        kernelsToRemove = kernelIDs.difference(executedKernelsIDs)
        if len(executedKernelsIDs) and len(kernelsToRemove):
            for kernelID in kernelsToRemove:
                if len(app.kernels[kernelID].traceFiles) == 0:
                    app.kernels.pop(kernelID, None)

    for kernelID, kernel in app.kernels.items(): # analyze traces + postproces
        kernelName = kernel.name
        # kernel filtration
        if len(app.kernelsToProfile) > 0 and kernelName not in app.kernelsToProfile:
            continue

        if len(kernel.traceFiles) == 0:
            updateStatus(app, 3, 'Kernel: {} has no traces'.format(kernelName))
            info_p('Kernel: {} has no traces'.format(kernelName))
            continue

        updateStatus(app, 3, 'Kernel: {}'.format(kernelName))
        info_p('Kernel: {}'.format(kernelName))

        if app.stride:
            for traceFile in kernel.traceFiles:
                analyzeStrideFile(kernel, traceFile)
        else:
            if not WA['DISABLE_MULTIPROCESSING']:
                pi = multiprocessing.Process(target=updateFileStatus, args=(app,))
                statusArray = manager.list([0] * len(kernel.traceFiles))
                pi.start()
            if PARALLEL_ANALYSIS and not WA['DISABLE_MULTIPROCESSING']:
                ### parallel version
                kernels = []
                with multiprocessing.Pool(min(multiprocessing.cpu_count(), len(kernel.traceFiles))) as p:
                    if app.collectMemTrace:
                        arguments = [(
                            Kernel(kernelID),
                            traceFile,
                            COMPRESS_TRACE,
                            index,
                            partial(collectMemTrace, offsetsToProfile=app.offsetsToProfile)
                            ) for index, traceFile in enumerate(kernel.traceFiles)]
                    else:
                        arguments = [(
                            Kernel(kernelID),
                            traceFile,
                            COMPRESS_TRACE,
                            index,
                            ) for index, traceFile in enumerate(kernel.traceFiles)]
                    kernels = p.starmap(analyzeTraceFile, arguments)
                for analyzedKernel in kernels: # merge results
                    kernel.mergeAnalyzed(analyzedKernel)
            else:
                ### one-thread version
                for index, traceFile in enumerate(kernel.traceFiles):
                    if app.collectMemTrace:
                        analyzeTraceFile(
                            kernel,
                            traceFile,
                            COMPRESS_TRACE,
                            index,
                            partial(collectMemTrace, offsetsToProfile=app.offsetsToProfile))
                    else:
                        analyzeTraceFile(
                            kernel,
                            traceFile,
                            COMPRESS_TRACE,
                            index)
            if not WA['DISABLE_MULTIPROCESSING']:
                pi.join()
    if app.dirType != dirTypes['trace']:
        returnCode = readFilteringFileData(app) # read phase 1 data
        if returnCode != ERROR_CODE['Success']:
            warning_p('Filtering data could not be found. Results may be incorrect')
            updateStatus(app, 3, getErrorMsg(returnCode))
        returnCode = getAsm(app)
        if returnCode != ERROR_CODE['Success']:
            warning_p('Can\'t find ASM')
            updateStatus(app, 3, getErrorMsg(returnCode))
        returnCode = getSourceLineMapping(app)
        if returnCode != ERROR_CODE['Success']:
            warning_p(
                'Cannot find source line mapping. '
                'Build kernels with \"-g\" or \"-gline-tables-only\" option')
            updateStatus(app, 3, getErrorMsg(returnCode))
    returnCode = app.postProcess()
    if returnCode != ERROR_CODE['Success']:
        error_p('Cannot post process data')
        updateStatus(app, 3, getErrorMsg(returnCode))

    # print results + save to drive
    reportDir = app.resultsDir if app.dirType != dirTypes['trace'] else ''
    try:
        tr = maaReport.generateTextReport(app)
        print(tr)
        txtReportPath = os.path.join(reportDir, TXT_REPORT_NAME)
        if not os.path.islink(txtReportPath):
            with open(txtReportPath, 'w') as f:
                f.write(tr)
        else:
            error_p('ERROR: Suspicious operation prevented: '
            'unexpected symbolic link at {}'.format(txtReportPath))
            updateStatus(app, 3, 'ERROR: Suspicious operation prevented: '
            'unexpected symbolic link at {}'.format(txtReportPath))
            return ERROR_CODE['Link file found']
    except Exception as e:
        error_p('Cannot generate text report')
        updateStatus(app, 3, 'Cannot generate text report')
        exception_p('{}'.format(e))

    kernelCsvReportDir = os.path.join(reportDir, 'CSV')
    try:
        if not os.path.isdir(kernelCsvReportDir):
            os.mkdir(kernelCsvReportDir)
        cr = maaReport.generateCsvReport(app)
        csvReportPath = os.path.join(kernelCsvReportDir, CSV_REPORT_NAME)
        if not os.path.islink(csvReportPath):
            with open(csvReportPath, 'w') as f:
                f.write(cr)
        else:
            error_p('ERROR: Suspicious operation prevented: '
            'unexpected symbolic link at {}'.format(csvReportPath))
            updateStatus(app, 3, 'ERROR: Suspicious operation prevented: '
            'unexpected symbolic link at {}'.format(csvReportPath))
            return ERROR_CODE['Link file found']
        fileEx = '.csv'
        for kernelID, kernel in app.kernels.items():
            kernelName = kernel.name
            ckr = maaReport.generateKernelCsvReport(kernel)
            csvReportPath = os.path.join(kernelCsvReportDir, kernelName[:MAX_FILE_NAME_LENGTH-len(fileEx)] + fileEx)
            if os.path.islink(csvReportPath):
                continue
            with open(csvReportPath, 'w') as f:
                f.write(ckr)
    except Exception as e:
        error_p('Cannot generate CSV report')
        updateStatus(app, 3, 'Cannot generate CSV report')
        exception_p('{}'.format(e))

    try:
        jr = maaReport.generateJsonReport(app, bareJson=True)
        jsonReportPath = os.path.join(reportDir, JSON_REPORT_NAME)
        if not os.path.islink(jsonReportPath):
            with open(jsonReportPath, 'w') as f:
                f.write(jr)
        else:
            error_p('ERROR: Suspicious operation prevented: '
            'unexpected symbolic link at {}'.format(jsonReportPath))
            updateStatus(app, 3, 'ERROR: Suspicious operation prevented: '
            'unexpected symbolic link at {}'.format(jsonReportPath))
            return ERROR_CODE['Link file found']
    except Exception as e:
        error_p('Cannot generate JSON report')
        updateStatus(app, 3, 'Cannot generate JSON report')
        exception_p('{}'.format(e))

    htmlReportPath = os.path.join(reportDir, HTML_REPORT_NAME)
    try:
        hr = maaReport.generateHtmlReport(app)
        if not os.path.islink(htmlReportPath):
            with open(htmlReportPath, 'w') as f:
                f.write(hr)
        else:
            error_p('ERROR: Suspicious operation prevented: '
            'unexpected symbolic link at {}'.format(htmlReportPath))
            updateStatus(app, 3, 'ERROR: Suspicious operation prevented: '
            'unexpected symbolic link at {}'.format(htmlReportPath))
            return ERROR_CODE['Link file found']
    except Exception as e:
        error_p('Cannot generate HTML report')
        updateStatus(app, 3, 'Cannot generate HTML report')
        exception_p('{}'.format(e))

    info_p('Results available: {}'.format(reportDir))

    updateStatus(app, 4, 'Report available:')
    updateStatus(app, 5, '{}'.format(os.path.join(reportDir, HTML_REPORT_NAME)))

    return ERROR_CODE['Success']

if __name__ == '__main__':
    sys.exit(main('sys'))
