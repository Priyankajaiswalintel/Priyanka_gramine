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
import sys
import argparse
import os

APPROX = 0.1

def isNumber(num):
    isNum = False
    try:
        float(num)
        isNum = True
    except Exception as e:
        isNum = False
    return isNum

nameList = list()

def compareAny(self, other):
    diff = list()
    for att in self.attScalarList:
        selfAtt = getattr(self, att)
        otherAtt = getattr(other, att)
        if 'compare' in dir(selfAtt) and 'compare' in dir(otherAtt):
            nameList.append(self.name)
            nameList.append(att)
            retDiff = selfAtt.compare(otherAtt)
            if len(retDiff):
                diff += retDiff
            nameList.pop()
            nameList.pop()
            continue
        exact = True
        if isNumber(selfAtt) and isNumber(otherAtt):
            exact = False
            selfAtt = float(selfAtt)
            otherAtt = float(otherAtt)
        if (exact and selfAtt != otherAtt) or (not exact and abs(selfAtt-otherAtt)>abs(selfAtt)*APPROX):
            # print((exact and selfAtt != otherAtt), (not exact and abs(selfAtt-otherAtt)>abs(selfAtt)*APPROX), selfAtt, otherAtt, '--'*10)
            diff.append(['_'.join(nameList)+'_'+self.name+'_'+att, selfAtt, otherAtt])
    for attdName in self.attDictList:
        attDSelf = getattr(self, attdName)
        attDOther = getattr(other, attdName)
        attDSelfKeys = set(attDSelf.keys())
        attDOtherKeys = set(attDOther.keys())
        if len(attDSelfKeys.symmetric_difference(attDOtherKeys)):
            diff.append(['_'.join(nameList)+'_'+self.name+'_'+attdName+'_DifferentKeys' , list(attDSelf.keys()), list(attDOther.keys())])
        attDAll = set()
        [attDAll.add(x) for x in attDSelf]
        [attDAll.add(x) for x in attDOther]
        for attV in attDAll:
            if attV in attDSelf and attV in attDOther:
                if 'compare' in dir(attDSelf[attV]) and 'compare' in dir(attDOther[attV]):
                    nameList.append(self.name)
                    nameList.append(attdName)
                    retDiff = attDSelf[attV].compare(attDOther[attV])
                    if len(retDiff):
                        diff += retDiff
                    nameList.pop()
                    nameList.pop()
                    continue
                elif isNumber(attDSelf[attV]) and isNumber(attDOther[attV]):
                    selfAtt = float(attDSelf[attV])
                    otherAtt = float(attDOther[attV])
                    if abs(selfAtt-otherAtt)>selfAtt*APPROX:
                        diff.append(['_'.join(nameList)+'_'+self.name+'_'+attdName+'_'+attV , attDSelf[attV], attDOther[attV]])
                    continue
                else:
                    if attDSelf[attV] != attDOther[attV]:
                        diff.append(['_'.join(nameList)+'_'+self.name+'_'+attdName+'_'+attV , attDSelf[attV], attDOther[attV]])
    for attdName in self.attListList:
        selfO = getattr(self, attdName)
        othrO = getattr(other, attdName)
        selfLen = len(selfO)
        otherLen = len(othrO)
        if selfLen != otherLen:
            diff.append(['_'.join(nameList)+'_'+self.name+'_'+attdName+'_Length' , selfLen, otherLen])
            continue
        if selfO == othrO: continue
        for ind in range(selfLen):
            if 'compare' in dir(selfO[ind]) and 'compare' in dir(othrO[ind]):
                nameList.append(self.name)
                nameList.append(attdName)
                retDiff = selfO[ind].compare(othrO[ind])
                if len(retDiff):
                    diff += retDiff
                nameList.pop()
                nameList.pop()
                continue
            elif isNumber(selfO[ind]) and isNumber(othrO[ind]):
                selfAtt = float(selfO[ind])
                otherAtt = float(othrO[ind])
                if abs(selfAtt-otherAtt)>selfAtt*APPROX:
                    diff.append(['_'.join(nameList)+'_'+self.name+'_'+attdName+'_'+attV , selfO[ind], othrO[ind]])
                continue
            else:
                if selfO[ind] != othrO[ind]:
                    diff.append(['_'.join(nameList)+'_'+self.name+'_'+attdName+'_'+attV , selfO[ind], othrO[ind]])
    return diff

class App:
    class Access:
        attScalarList = ['calls', 'amount', 'CacheLineNumber', 'CacheLineUtil', 'used', 'strideSumm', 'pattern', 'accessSize', 'intensity', 'execSize', 'isSlm', 'bti'] # TODO , 'CacheLineMax', 'CacheLineMin'
        attDictList = ['stride'] # TODO
        attListList = ['distribution', 'sends', 'sourceMap'] # TODO
        def __init__(self, data):
            for att in self.attScalarList:
                setattr(self, att, data[att])
            for att in self.attDictList:
                setattr(self, att, data[att])
            for att in self.attListList:
                setattr(self, att, data[att])
            self.name = '0x0' if len(data['sends']) == 0 else str(data['sends'][0])
        def compare(self, other):
            return compareAny(self, other)
    class SendData:
        attScalarList = ['calls', 'amount', 'CacheLineNumber', 'CacheLineUtil', 'used', 'transferred', 'strideSumm', 'pattern'] # , 'CacheLineMax', 'CacheLineMin'
        attDictList = ['stride']
        attListList = ['distribution']
        def __init__(self, data):
            for att in self.attScalarList:
                setattr(self, att, data[att])
            self.stride = data['stride']
            self.distribution = data['distribution']
            self.name = str(data['name'])
        def compare(self, other):
            return compareAny(self, other)

    class AggrD:
        mems = ['Local', 'Global']
        rws = ['Read', 'Write']
        tus = ['Used', 'Transferred', 'CacheLineNumber', 'Calls']
        def getListAttributes(self):
            ls = list()
            for mem in App.AggrD.mems:
                for rw in App.AggrD.rws:
                    for tu in App.AggrD.tus:
                        ls.append('ad{}{}{}'.format(mem, rw, tu))
            return ls
        def __init__(self, data):
            self.attScalarList = self.getListAttributes()
            self.attDictList = []
            self.attListList = []
            for att in self.attScalarList:
                setattr(self, att, data[att])
            self.name = 'name'
        def compare(self, other):
            return compareAny(self, other)

    class Kernel:
        class Enqueue:
            attScalarList = ['id', 'totalThreadsExecuted', 'aggregatedDataTotal', 'aggregatedDataAvg']
            attDictList = ['sendDataTotal']
            # attDictList = []
            attListList = ['accesses']
            def __init__(self, data):
                for att in self.attScalarList:
                    setattr(self, att, data[att])
                self.sendDataTotal = dict()
                for ky in data['sendDataTotal']:
                    data['sendDataTotal'][ky]['name'] = str(ky)
                    self.sendDataTotal[ky] = App.SendData(data['sendDataTotal'][ky])
                self.aggregatedDataTotal = App.AggrD(data['aggregatedDataTotal'])
                self.aggregatedDataAvg = App.AggrD(data['aggregatedDataAvg'])
                self.accesses = list()
                for acc in data['accesses']:
                    self.accesses.append(App.Access(acc))
                self.name = str(data['id'])
            def compare(self, other):
                return compareAny(self, other)

        attScalarList = ['name', 'enqueueNum', 'accessNum']
        attDictList = ['enqueues']
        attListList = []
        def __init__(self, data):
            for att in self.attScalarList:
                setattr(self, att, data[att])
            self.enqueues = dict()
            for enqueue in data['enqueues']:
                self.enqueues[enqueue] = App.Kernel.Enqueue(data['enqueues'][enqueue])
            self.name = str(data['name'])
        def compare(self, other):
            return compareAny(self, other)
    
    attScalarList = ['name', 'collectPercentage', 'envVars', 'analysisVersion'] # 'sourceFiles', 'date', 'resultsDir', 'applicationBin', 'workDirectory',
    attDictList = ['kernels']
    attListList = ['parameters']
    def __init__(self, data):
        for att in App.attScalarList:
            setattr(self, att, data[att])
        self.kernels = dict()
        for kernelName in data["kernels"]:
            self.kernels[kernelName] = App.Kernel(data["kernels"][kernelName])
        self.parameters = data['parameters']
        self.name = str(data['name'])
    def __str__(self):
        string = ''
        for att in App.attScalarList:
            string += '{}:{}, '.format(att,getattr(self, att))
        return string
    def compare(self, other):
        return compareAny(self, other)

def readResults(path):
    with open(path) as f:
        data = json.load(f)
    return App(data)

def main(argv):
    parser = argparse.ArgumentParser(description='GPU Memory Access Ananlysis')
    parser.add_argument(
        '-r1',
        metavar='DIRECTORY',
        default='',
        dest='results1',
        type=str,
        help='first result')
    parser.add_argument(
        '-r2',
        metavar='DIRECTORY',
        default='',
        dest='results2',
        type=str,
        help='second result')
    parser.add_argument(
        '-f',
        metavar='DIRECTORY',
        default='',
        dest='folder',
        type=str,
        help='Report directory')

    if argv == 'sys':
        args = parser.parse_args()
    elif isinstance(argv, list):
        args = parser.parse_args(argv)
    else:
        print('Arguments not recognized')
        return -1

    results1 = readResults(args.results1)
    # print(results1)
    results2 = readResults(args.results2)
    # print(results2)

    # print('calc diff')
    diff = results1.compare(results2)
    
    # print txt
    print('\n\n\nDIFFERENCE:')
    print(diff.__str__().replace('[','\n['))

    if os.path.isdir(args.folder):
        # save diff to json
        with open(os.path.join(args.folder, 'compare_report.json'), 'w') as f:
            f.write(json.dumps(diff))
        # save to txt
        with open(os.path.join(args.folder, 'compare_report.txt'), 'w') as f:
            f.write(diff.__str__().replace('[','\n['))
    return len(diff)

if __name__ == '__main__':
    sys.exit(main('sys'))
