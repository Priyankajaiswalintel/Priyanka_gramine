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

import json
import os

from MAAT import *
from printer import info_p, warning_p, error_p, exception_p

def echoRp(string: str) -> str:
    return string
def byteRp(num: int) -> str:
    try: 
        num = int(num)
    except Exception as e:
        error_p('Can not represent: \"{}\"'.format(num))
        exception_p('{}'.format(e))
        return echoRp(num)
    return numbRp(num, th=1000)+'B'
def procRp(num: float) -> str:
    return numbRp(num)+'%'
def numbRp(num: float, th: int = 1000) -> str:
    try:
        # if num == '': num = 0.0
        num = float(num)
        _ = 1/th
    except Exception as e:
        error_p('Can not represent: \"{}\"'.format(num))
        exception_p('{}'.format(e))
        return echoRp(num)
    se = ['', 'K', 'M', 'G', 'T', 'P', 'E','Z', 'Y']
    i = 0
    while num > 5000:
        num = float(num)/th
        i += 1
    return '{:>5.1f}{}'.format(float(num), se[i]) if i or num%1!=0 else '{:>5}'.format(int(num))
def hexnRp(num: int) -> str:
    return '0x{:04x}'.format(num)
def tableHeader(data,width):
    return tableRow([], width, delimiter='=') + tableRow(data, width, delimiter='=')
def tableRow(data,width, dataType = [], delimiter ='-') -> str:
    vertical = '|'
    tr = ''
    for indR, rowD in enumerate(data):
        tr += vertical
        for indC, colD in enumerate(rowD):
            wid = width[indC] if len(width)>indC else 8 
            tr += '{:<{ww}}{}'.format(str(dataType[indR][indC](colD) if len(dataType) else echoRp(colD))[:wid], vertical, ww=wid)
        tr += '\n'
    tr += delimiter*(sum(width)+len(width))+'\n'
    return tr
def isNumb(num) -> bool:
    try: 
        float(num)
    except ValueError:
        return False
    return True

def generateTextReport(app): #: Application) -> str:
    tr = ''
    # Print application general information
    tr += '\n'*5+'='*80+'\n'+'='*80+'\n'
    tr += 'Application: {}\n'.format(app.name)
    tr += 'Parameters: {}\n\n'.format(app.parameters)
    tr += 'Data per all profiled enqueue\n'

    width = [16,7,12,11,10]
    data = [
        ['Kernel',  'Enqu',     'Global',   '$Line usage',  'Local' ],
        ['name',    ' eues',    'R & W',    'R & W',        'R & W', ],
        ['',        '',         'Read',     'Read',         'Read', ],
        ['',        '',         'Write',    'Write',        'Write',],
    ]
    dataType = []
    tr += tableHeader(data, width)
    for kernelID, kernel in app.kernels.items(): 
        kernelName = kernel.name

        data = [
            ['', len(kernel.enqueues), '','', '',],
            ['','','', '','',],
            ['','', '', '' ,'',]
        ]

        # kernel name
        data[0][0] = kernelName[:width[0]]

        kadt = kernel.aggregatedDataTotal
        # global bytes
        data[0][2] = kadt.adGlobalReadTransferred+kadt.adGlobalWriteTransferred
        data[1][2] = kadt.adGlobalReadTransferred
        data[2][2] = kadt.adGlobalWriteTransferred
        # global cache line util
        if (kadt.adGlobalReadCacheLineNumber+kadt.adGlobalWriteCacheLineNumber):
            data[0][3] = (kadt.adGlobalReadUsed+kadt.adGlobalWriteUsed)/((kadt.adGlobalReadCacheLineNumber+kadt.adGlobalWriteCacheLineNumber)*64)*100
        else:
            data[0][3] = 100
        data[1][3] = kadt.adGlobalReadUsed/(kadt.adGlobalReadCacheLineNumber*64)*100 if kadt.adGlobalReadCacheLineNumber else 100
        data[2][3] = kadt.adGlobalWriteUsed/(kadt.adGlobalWriteCacheLineNumber*64)*100 if kadt.adGlobalWriteCacheLineNumber else 100

        # local bytes
        data[0][4] = kadt.adLocalReadTransferred+kadt.adLocalWriteTransferred
        data[1][4] = kadt.adLocalReadTransferred
        data[2][4] = kadt.adLocalWriteTransferred

        dataType = [
            [echoRp, numbRp, byteRp, procRp, byteRp, ],
            [echoRp, echoRp, byteRp, procRp, byteRp, ],
            [echoRp, echoRp, byteRp, procRp, byteRp, ]
        ]
        tr += tableRow(data, width, dataType)
    
    # Print legend
    tr += '\n'
    tr += 'Enqueues     - The number of executed enqueues\n'
    tr += 'Global       - Accesses to global memory\n'
    tr += 'Local        - Accesses to local (SLM) memory\n'
    tr += '$Line usage  - Cache line utilization, ratio between useful and transferred data\n'
    tr += 'Read         - Data for read accesses\n'
    tr += 'Write        - Data for write accesses\n'
    tr += 'R & W        - Sum of read and write accesses\n'

    # Print kernel-specific information
    widthBase = [16,7,8,8,9,6,7,7,7,12]
    for kernelID, kernel in app.kernels.items(): 
        kernelName = kernel.name
        
        noSourceMap = True
        for sendOffset in kernel.sends:
            if sendOffset in kernel.sourceMapping and not kernel.sourceMapping[sendOffset].isDefault():
                noSourceMap = False
                break
        width = widthBase[1:] if noSourceMap else widthBase
        
        tr += '\n\nKernel: {}\n'.format(kernelName)
        tr += 'Enqueues profiled: {}\n'.format(len(kernel.enqueues))
        tr += 'Data per all profiled enqueue\n'
        # print header
        data = [
            ['file',   'Offset',   'Type', 'Count',    'Used', 'Inten',    'Stride',    'Stride',      'Distri',   'Pattern',],
            ['row',    '',         '',     '',         'Transf','sity',    '(bytes)',   '(units)',      'bution',   '',],
            ['column', '',         '',     '',         'Ratio','',         '',          '',             '',         '',],
        ]
        if noSourceMap: 
            data = [x[1:] for x in data]
        tr += tableHeader(data, width)

        for access in kernel.accesses:
            if not len(access.sendOffsets): continue
            sendOffset = access.sendOffsets[0]
            send = kernel.sends[sendOffset]
            if send.isEot or send.payloadLen==0:
                continue
            if sendOffset not in kernel.sendDataTotal:
                error_p('send data not found: 0x{:04x}'.format(sendOffset))
                continue
            if access.sendData == None: continue
            sendData = access.sendData
            data = [
                ['',   sendOffset,  send.typeStr()[0], sendData.calls,    sendData.used,       send.intensity,  '',   '',   '',   sendData.pattern,],
                ['',    '',         send.typeStr()[1],     '',         sendData.transferred,       '',          '',   '',   '',   '',],
                ['',    '',         send.typeStr()[2],     '',         sendData.CacheLineUtil,            '',          '',   '',   '',   '',],
            ]
            dataType = [
                [echoRp, hexnRp, echoRp, numbRp, byteRp, byteRp, echoRp, echoRp, echoRp, echoRp, ],
                [echoRp, echoRp, echoRp, echoRp, byteRp, echoRp, echoRp, echoRp, echoRp, echoRp, ],
                [echoRp, echoRp, echoRp,     echoRp, procRp, echoRp, echoRp, echoRp, echoRp, echoRp, ]
            ]
            
            # source mapping
            if sendOffset in kernel.sourceMapping:
                ksm = kernel.sourceMapping[sendOffset]
                data[0][0] = ksm.file.fileName#[:width[0]]
                data[1][0] = ksm.row
                data[2][0] = ksm.column
            # remove data for local sends
            if send.isSlm:
                data[1][4] = ''
                dataType[1][4] = echoRp
                data[2][4] = ''
                dataType[2][4] = echoRp
            # add strides to table
            sortedStride = sorted(sendData.stride.items(), key=lambda kv: kv[1], reverse=True)
            other = 0
            numStridesInTable = 5
            for (i, stride) in enumerate(sortedStride):
                name = stride[0]
                value = stride[1]
                ind = i
                if ind>numStridesInTable:
                    other += value
                    if ind+1 < len(sortedStride):
                        continue
                    name = 'other'
                    value = other
                    ind = numStridesInTable
                if ind>=len(data):
                    data.append(['']*len(data[0]))
                    dataType.append([echoRp]*len(dataType[0]))
                data[ind][6] = name
                dataType[ind][6] = byteRp if isNumb(name) else echoRp
                data[ind][7] = int(name)/send.accessSize if isNumb(name) and send.accessSize else ''
                dataType[ind][7] = numbRp if isNumb(name) else echoRp
                if sendData.strideSumm:
                    data[ind][8] = 100.0*value/sendData.strideSumm
                    dataType[ind][8] = procRp
            data[1][9] = '' if sendData.aligned else 'Not aligned'
            if noSourceMap: 
                data = [x[1:] for x in data]
                dataType = [x[1:] for x in dataType]
            tr += tableRow(data, width, dataType)
        if noSourceMap: 
            tr += 'Debug info (source line mapping) was not found for this kernel. Use the \"-g\" or \"-gline-tables-only\" compile option to enable source line mapping.\n'
    # print legend
    tr += '\n'
    tr += 'Offset       - Access send instruction offsets, Instruction Pointers\n'
    tr += 'Type         - Short description of send instruction\n'
    tr += '    SIMD16   - SIMD width\n'
    tr += '    (16|M0)  - ( Execution size | execution mask )\n'
    tr += '    GRA_4    - _G_lobal/_L_ocal, _R_ead/_W_rite, _A_tomic, _M_edia, Access Size in bytes(amount of bytes which is transferred per access per SIMD lane)\n'
    tr += 'Count        - Dynamic counter of access instructions\n'
    tr += 'Used         - Number of bytes, used by kernel. == Dynamic Count * Access Size * Execution Size\n'
    tr += 'Transf       - Number of bytes transferred during all accesses. == Dynamic Count * Cache Line Number * Cache Line Size \n'
    tr += 'Ratio        - Ratio between Used and Transferred. Shows cache line utilization, ideal access is 100%\n'
    tr += 'Intensity    - Number of bytes transferred by one memory access. Low number can be caused latency problems. Intensity < 64 Bytes is caused low cache line utilization. == Execution Size * Access Size\n'
    tr += 'Stride       - Access stride between two SIMD lanes during one memory access presented in bytes and access units. Describes memory access pattern\n'
    tr += 'Distribution - Distribution value of corresponding stride in percentage(%) vs all strides of memory access\n'
    tr += 'Pattern      - Major memory access pattern\n'
    return tr

def genCsv(data, delimiter: str = ',') -> str:
    cr = ''
    for row in data:
        for col in row:
            cr += str(col) + delimiter
        cr += '\n'
    return cr

def generateCsvReport(app: Application, delimiter: str = ',') -> str:
    data = []
    ### general application data
    data.append(['Applicatoin', app.name])
    data.append(['Application Binary', app.applicationBin])
    data.append(['Parameters', str(app.parameters)])
    data.append(['Date', app.date])
    data.append(['Results Directory', app.resultsDir])
    data.append(['Collect percentage', app.collectPercentage])
    data.append(['Work Directory', app.workDirectory])
    data.append(['Env Vars', app.envVars])
    data.append(['Analysis Version', app.analysisVersion])
    data.append(['Kernels Number', len(app.kernels)])
    data.append([])
    data.append(['Data Total'])
    for attr in AggregatedData.getListAttributes():
        data.append([attr, getattr(app.aggregatedDataTotal, attr)])
    data.append([])
    data.append([])
    ### per kernel data
    data.append(['Total per all enqueues'])
    data.append([
        'Kernel Name', 
        'Enqueues Number'
        'Accesess Number'
        ]+[attr for attr in AggregatedData.getListAttributes()])
    for kernelID, kernel in app.kernels.items(): 
        kernelName = kernel.name
        kernelRow = [kernelName, len(kernel.enqueues), len(kernel.accesses)]
        for attr in AggregatedData.getListAttributes():
            kernelRow += [getattr(kernel.aggregatedDataTotal, attr)]
        data.append(kernelRow)

    return genCsv(data, delimiter)

def generateKernelCsvReport(kernel: Kernel, delimiter: str = ',') -> str:
    ### common data
    data = []
    data.append(['Kernel Name', kernel.name])
    data.append(['Enqueues Number', len(kernel.enqueues)])
    data.append(['Accesses Number', len(kernel.accesses)])
    data.append([])
    for attr in AggregatedData.getListAttributes():
        data.append([attr, getattr(kernel.aggregatedDataTotal, attr)])
    data.append([])
    data.append([])
    ### per access data
    data.append(['Total per all enqueues'])
    data.append(['Access', 'Send Offsets', 'Send Offsets Hex'] + SendData.getListAttributes() + Send.getListAttributes())
    for access in kernel.accesses:
        mapping = access.sourceMap
        accessRow = ['{}:{}:{}'.format(mapping.file.fileName, mapping.row, mapping.column), ' '.join([str(x) for x in access.sendOffsets]), ' '.join([str(hex(x)) for x in access.sendOffsets]) ]
        if access.sendData != None:
            for attr in SendData.getListAttributes():
                accessRow += [getattr(access.sendData, attr)]
            if len(access.sendOffsets):
                offset = access.sendOffsets[0]
                if offset not in kernel.sends: return
                send = kernel.sends[offset]
                for attr in Send.getListAttributes():
                    accessRow += [getattr(send, attr)]
        data.append(accessRow)
    return genCsv(data, delimiter)

def genJdSourcePane(app: Application, kernelID: str) -> dict:
    noMapp = [[],-1,-1, '', 0]
    spd = dict()
    kernel = app.kernels[kernelID]
    msd = dict()
    for offset in kernel.sourceMapping:
        mapping = kernel.sourceMapping[offset]
        row = mapping.row
        col = mapping.column
        filePath = mapping.file.filePath
        fileName = mapping.file.fileName
        if SourceFile(filePath, fileName) in kernel.sourceFiles:
            fileId = kernel.sourceFiles.index(SourceFile(filePath, fileName))
        else:
            fileId = -1
        if offset in kernel.sends:
            access = kernel.accesses.index(kernel.getAccessBySendOffset(offset))
        else:
            access = -1
        msd[fileId] = msd.get(fileId, dict())
        msd[fileId][row] = msd[fileId].get(row, dict())
        msd[fileId][row][col] = msd[fileId][row].get(col, list())
        msd[fileId][row][col].append([offset, access])
    for fileId in msd:
        spd[fileId] = spd.get(fileId, list())
        if not (0 <= fileId < len(app.sourceFiles)):
            continue
        for (rowNum, row) in enumerate(app.sourceFiles[fileId].sourceCode, 1):
            newRow = list()
            if rowNum in msd[fileId]:
                prev = 0
                sortedCols = sorted(list(msd[fileId][rowNum].keys()))
                for col in sortedCols:
                    column = col if col else 1
                    if prev!=col: newRow.append([row[prev:column-1], noMapp])
                    newRow.append([row[column-1:column], [msd[fileId][rowNum][col], rowNum, col, '', 0]])
                    prev = column
                if prev < len(row): newRow.append([row[prev:], noMapp])
            else:
                newRow.append([row, noMapp])
            spd[fileId].append(newRow)
    return spd
def genJdAccess(access: Access) -> dict:
    ja = genJdSendData(access.sendData)
    ja['sends'] = access.sendOffsets
    ja['sourceMap'] = [ access.sourceMap.file.index, access.sourceMap.row, access.sourceMap.column ]
    return ja
def genJdSend(send: Send) -> dict:
    jd = dict()
    jd['offset'] = send.offset
    jd['execSize'] = send.execSize
    jd['channelOffset'] = send.channelOffset
    jd['accessSize'] = send.accessSize
    jd['intensity'] = send.intensity
    jd['isWrite'] = send.isWrite
    jd['isScatter'] = send.isScatter
    jd['isBts'] = send.isBts
    jd['isSlm'] = send.isSlm
    jd['isScratchBlock'] = send.isScratchBlock
    jd['isAtomic'] = send.isAtomic
    jd['isEot'] = send.isEot
    jd['isMedia'] = send.isMedia
    jd['addrWidth'] = send.addrWidth
    jd['simdWidth'] = send.simdWidth
    jd['bti'] = send.bti
    jd['payloadLen'] = send.payloadLen
    jd['dataPort'] = send.dataPort
    jd['operandWidthInBytes'] = send.operandWidthInBytes
    jd['numOfElements'] = send.numOfElements
    return jd
def genJdSendData(sendData: SendData) -> dict:
    jd = dict()
    jd['stride'] = dict()
    randomStride = 0
    for stride in sendData.stride:
        if sendData.stride[stride]/sendData.strideSumm > RANDOM_STRIDE_LEVEL:
            jd['stride'][stride] = sendData.stride[stride]
        else:
            randomStride += sendData.stride[stride]
    if randomStride:
        jd['stride'][RANDOM_STRIDE] = randomStride
    jd['mediaBlockSizes'] = list(sendData.mediaBlockSizes)
    jd['calls'] = sendData.calls
    jd['amount'] = sendData.amount
    jd['CacheLineNumber'] = sendData.CacheLineNumber
    jd['CacheLineMax'] = sendData.CacheLineMax
    jd['CacheLineMin'] = sendData.CacheLineMin
    jd['mediaBytes'] = sendData.mediaBytes
    jd['CacheLineUtil'] = '{:3.2f}'.format(sendData.CacheLineUtil)
    jd['used'] = sendData.used
    jd['transferred'] = sendData.transferred
    jd['strideSumm'] = sendData.strideSumm
    jd['pattern'] = sendData.pattern + ('' if sendData.aligned else ', Not cache line aligned')
    jd['notClAligned'] = sendData.notClAligned
    jd['distribution'] = sendData.strideDistribution
    return jd
def genJdEnqueue(enqueue: Enqueue) -> dict:
    jd = dict()
    jd['id'] = enqueue.id
    jd['totalThreadsExecuted'] = enqueue.totalThreadsExecuted
    sdt = dict()
    for sendOffset in enqueue.sendDataTotal:
        sdt[sendOffset] = genJdSendData(enqueue.sendDataTotal[sendOffset])
    jd['sendDataTotal'] = sdt
    jd['aggregatedDataTotal'] = genJdAggregatedData(enqueue.aggregatedDataTotal)
    jd['aggregatedDataAvg'] = genJdAggregatedData(enqueue.aggregatedDataAvg)
    ad = list()
    for ind, access in enumerate(enqueue.accesses):
        if not len(access.sendOffsets):
            continue
        sendOffset = access.sendOffsets[0]
        if sendOffset in enqueue.sends and enqueue.sends[sendOffset].isEot:
            continue
        send = enqueue.sends[sendOffset]
        acc = genJdAccess(access)
        acc['type'] = send.typeStr()
        acc['typeLong'] = send.typeStrLong()
        acc['str'] = '{gl} {rw}{am} {es}X{aw} bytes'.format(
            gl='SLM' if send.isSlm else 'Global', 
            rw='Write' if send.isWrite else 'Read',
            am=(' Atomic' if send.isAtomic else ' Media' if send.isMedia else ''),
            es=send.execSize,
            aw=send.accessSize)
        acc['accessSize'] = send.accessSize
        acc['intensity'] = send.intensity
        acc['execSize'] = send.execSize
        acc['isSlm'] = send.isSlm
        acc['style'] = ''
        acc['id'] = ind
        acc['bti'] = send.bti
        ad.append(acc)
    jd['accesses'] = ad
    return jd
def genJdSourceFile(sourceFile: SourceFile) -> list():
    jd = dict()
    jd['fileName'] = sourceFile.fileName
    jd['filePath'] = sourceFile.filePath
    jd['sourceCode'] = sourceFile.sourceCode
    jd['index'] = sourceFile.index
    return jd
def genJdKernel(kernel: Kernel) -> dict:
    jd = dict()
    kernelName = str(kernel.id) + ' ' + kernel.name if kernel.name!='All_kernels' else kernel.name
    jd['name'] = kernelName
    jd['eotOffset'] = kernel.eotOffset
    jd['asm'] = kernel.asm

    ed = dict()
    eTotal = Enqueue(-1)
    eTotal.aggregatedDataTotal = kernel.aggregatedDataTotal
    eTotal.sendDataTotal = kernel.sendDataTotal
    eTotal.sends = kernel.sends
    if kernel.name not in ['Average_per_application', 'All_kernels']:
        eAverage = Enqueue(-2)
        eAverage.aggregatedDataTotal = kernel.aggregatedDataAvg
        eAverage.sendDataTotal = kernel.sendDataAvg
        eAverage.sends = kernel.sends
        for access in kernel.accesses:
            eTotal.addAccess(access)
            eAverage.addAccess(access)
        if len(kernel.enqueues) > 1: ed['Average_per_kernel'] = genJdEnqueue(eAverage)
    ed['All_enqueues'] = genJdEnqueue(eTotal)
    jd['enqueueOVF'] = False
    for enqueueIdx, enqueue in enumerate(kernel.enqueues):
        if enqueueIdx > 20:
            jd['enqueueOVF'] = len(kernel.enqueues) - enqueueIdx
            break
        ed[enqueue] = genJdEnqueue(kernel.enqueues[enqueue])
    jd['enqueues'] = ed
    jd['enqueueNum'] = len(kernel.enqueues)
    # accesses
    jd['accessNum'] = len(kernel.accesses)
    jd['mappingAccesses'] = [ [ x.sendOffsets, (kernel.sourceFiles.index(x.sourceMap.file) if x.sourceMap.file in kernel.sourceFiles else -1), x.sourceMap.row, x.sourceMap.column ] for x in kernel.accesses ]
    mad = dict()
    msd = dict()
    noSourceLineMapping = True
    for offset in kernel.sourceMapping:
        # if offset in kernel.sends:
        #     noSourceLineMapping = False
        mapping = kernel.sourceMapping[offset]
        row = mapping.row
        col = mapping.column
        filePath = mapping.file.filePath
        fileName = mapping.file.fileName
        if SourceFile(filePath, fileName) in kernel.sourceFiles:
            fileId = kernel.sourceFiles.index(SourceFile(filePath, fileName))
            noSourceLineMapping = False
        else:
            fileId = -1
        if offset in kernel.sends:
            access = kernel.accesses.index(kernel.getAccessBySendOffset(offset))
        else:
            access = -1
        mad[offset] = [fileId, row, col, access]
        msd[fileId] = msd.get(fileId, dict())
        msd[fileId][row] = msd[fileId].get(row, dict())
        msd[fileId][row][col] = msd[fileId][row].get(col, list())
        msd[fileId][row][col].append([offset, access])
    jd['noSourceLineMapping'] = noSourceLineMapping
    jd['mappingAsm'] = mad
    jd['mappingSource'] = msd
    return jd
def genJdAggregatedData(aggregatedData: AggregatedData) -> dict:
    jd = dict()
    for attr in AggregatedData.getListAttributes():
        jd[attr] = getattr(aggregatedData, attr)
    return jd

def generateJsonReport(app: Application, bareJson=False) -> str:
    # generates json with data
    # prepare data as dicts and lists.
    # only neccesarly data
    # use default json dump to create json
    jd = ''
    jd = dict()
    jd['name'] = app.name
    jd['applicationBin'] = app.applicationBin
    jd['parameters'] = app.parameters
    jd['date'] = app.date
    jd['resultsDir'] = app.resultsDir
    jd['collectPercentage'] = app.collectPercentage
    jd['workDirectory'] = app.workDirectory
    jd['envVars'] = app.envVars
    jd['analysisVersion'] = app.analysisVersion
    jd['updateStatusEnabled'] = app.updateStatusEnabled
    jd['sourceFiles'] = [genJdSourceFile(x) for x in app.sourceFiles]
    jd['GTPinVersion'] = app.GTPinVersion
    # kernels
    ks = dict()
    kTotal = Kernel('All_kernels')
    kTotal.name = 'All_kernels'
    kTotal.aggregatedDataTotal = app.aggregatedDataTotal
    ks['All_kernels'] = genJdKernel(kTotal)
    for kernelID, kernel in app.kernels.items():
        kernelName = str(kernelID) + ' ' + kernel.name
        ks[kernelName] = genJdKernel(kernel)
        ks[kernelName]['sourceMapping'] = genJdSourcePane(app, kernelID)

    jd['kernels'] = ks

    jsonApp = ''
    if bareJson:
        jsonApp += json.dumps(jd)
    else:
        jsonApp = 'const data = '+ json.dumps(jd)+';\n\nexport default data;' #, sort_keys=True, indent=2)

    jr = jsonApp
    return jr

def generateHtmlReport(app: Application) -> str:
    jr = generateJsonReport(app, bareJson=True)
    reportTemplate = ''
    reportTemplatePath = os.path.join(app.scriptDir,'reportTemplate.html')
    if (os.path.isfile(reportTemplatePath) and
        not os.path.islink(reportTemplatePath)):
        with open(reportTemplatePath, 'r') as rt:
            for row in rt:
                reportTemplate += str(row).replace('{REPORT_DATA:REPORT_DATA}', jr)
    else:
        error_p('HTML report template not found: {}'.format(reportTemplatePath))
        reportTemplate += '<body><h1>HTML report template not found</h1></body>'
    return reportTemplate


