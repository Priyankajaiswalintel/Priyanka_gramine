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

###
# Example of usage: 
# 
# from elf import getMappingFromFile
# 
# mapping = getMappingFromFile(elfFileFull)
# for offset in offsets:
#     m = mapping[offset]
#     filePath = m[0]
#     fileName = m[1]
#     row = m[2]
#     column = m[3]
#

import sys
import os

DEBUG_PRINT = False

class Elf:
    def __init__(self, data):
        self.magic = data[0:4]
        if self.magic != b'\x7fELF':
            print('Incorrect magic: {} != .ELF '.format(self.magic))
            return
        self.bits = 64 if int.from_bytes(data[4:5], 'little')==2 else 32
        self.addr_bytes = 8 if self.bits == 64 else 4
        self.endian = "little" if int.from_bytes(data[5:6], 'little')==1 else 'big'
        ptr = 24
        self.entry_point  = int.from_bytes(data[ptr:ptr+self.addr_bytes], self.endian)
        self.prog_headers = int.from_bytes(data[ptr+self.addr_bytes:ptr+2*self.addr_bytes], self.endian)
        self.sect_headers = int.from_bytes(data[ptr+2*self.addr_bytes:ptr+3*self.addr_bytes], self.endian)
        ptr = 52
        self.e_phentsize = int.from_bytes(data[ptr:ptr+2], 'little')
        ptr += 2
        self.e_phnum = int.from_bytes(data[ptr:ptr+2], 'little')
        ptr += 2
        self.e_shentsize = int.from_bytes(data[ptr:ptr+2], 'little')
        ptr += 2
        self.e_shnum = int.from_bytes(data[ptr:ptr+2], 'little')
        ptr += 2
        self.e_shstrndx = int.from_bytes(data[ptr:ptr+2], 'little')
        ptr = 64+self.sect_headers-self.e_phentsize
        self.sections = []
        for i in range(self.e_shstrndx):
            self.sections.append(dict())
            section = self.sections[i]
            section['sh_name'] = int.from_bytes(data[ptr:ptr+4],self.endian)
            ptr+=4
            section['sh_type'] = int.from_bytes(data[ptr:ptr+4],self.endian)
            ptr+=4
            section['sh_flags'] = int.from_bytes(data[ptr:ptr+self.addr_bytes],self.endian)
            ptr+=self.addr_bytes
            section['sh_addr'] = int.from_bytes(data[ptr:ptr+self.addr_bytes],self.endian)
            ptr+=self.addr_bytes
            section['sh_offset'] = int.from_bytes(data[ptr:ptr+self.addr_bytes],self.endian)
            ptr+=self.addr_bytes
            section['sh_size'] = int.from_bytes(data[ptr:ptr+self.addr_bytes],self.endian)
            ptr+=self.addr_bytes
            section['sh_link'] = int.from_bytes(data[ptr:ptr+4],self.endian)
            ptr+=4
            section['sh_info'] = int.from_bytes(data[ptr:ptr+4],self.endian)
            ptr+=4
            section['sh_addralign'] = int.from_bytes(data[ptr:ptr+self.addr_bytes],self.endian)
            ptr+=self.addr_bytes
            section['sh_entsize'] = int.from_bytes(data[ptr:ptr+self.addr_bytes],self.endian)
            ptr+=self.addr_bytes

        strtab_section = [section for section in self.sections if section['sh_type'] == 3 ]
        if len(strtab_section) == 0:
            print('Elf parse failed: strtab not found')
            return
        strtab_section = strtab_section[0]
        strtab_section_data = data[strtab_section['sh_offset']:strtab_section['sh_offset']+strtab_section['sh_size']]
        for section in self.sections:
            i = section['sh_name']
            byte = strtab_section_data[i]
            section['name'] = ''
            while byte!=0:
                i+=1
                section['name'] += str(chr(byte))
                byte = strtab_section_data[i]

        debug_abbrev_section = [section for section in self.sections if section['name'] == '.debug_abbrev']
        self.abbrev = {}
        if len(debug_abbrev_section) == 0:
            print('debug abbrev section not found')
            return
        else:
            debug_abbrev_section = debug_abbrev_section[0]
            debug_abbrev_section_data = data[debug_abbrev_section['sh_offset']: debug_abbrev_section['sh_offset']+debug_abbrev_section['sh_size']]
            self.readDebugAbbrev(debug_abbrev_section_data)

        debug_info_section = [section for section in self.sections if section['name'] == '.debug_info']
        self.debug_info = {}
        if len(debug_info_section) == 0:
            print('debug info section not found')
            return
        else:
            debug_info_section = debug_info_section[0]
            debug_info_section_data = data[debug_info_section['sh_offset']: debug_info_section['sh_offset']+debug_info_section['sh_size']]
            self.readDebugInfo(debug_info_section_data)

        debug_line_section = [section for section in self.sections if section['name'] == '.debug_line']
        self.mapping = {}
        self.directories = []
        self.files = []
        if len(debug_line_section) == 0:
            print('debug info section not found')
            return
        else:
            debug_line_section = debug_line_section[0]
            debug_line_section_data = data[debug_line_section['sh_offset']: debug_line_section['sh_offset']+debug_line_section['sh_size']]
            self.readDebugLine(debug_line_section_data)
        # set build folder as 0 directory
        for abb in self.debug_info: 
            if 'DW_AT_comp_dir' not in abb.keys():
                continue
            self.directories[0] = abb['DW_AT_comp_dir']

    def readDebugAbbrev(self, debug_abbrev_section_data):
        if DEBUG_PRINT: print('\n', '='*10, 'Read Debug Abbrev', '='*10, '\n')
        D = False # DEBUG_PRINT
        i = 0
        self.abbrev = {}
        self.abbrev[0] = dict()
        self.abbrev[0]['tag'] = 'tag_num_'+str(0)
        self.abbrev[0]['list'] = []
        while 1:
            if len(debug_abbrev_section_data) <= i+3:
                break
            abbrev_num = debug_abbrev_section_data[i]
            i+=1
            self.abbrev[abbrev_num] = dict()
            dd = self.abbrev[abbrev_num]

            tag = debug_abbrev_section_data[i]
            i+=1
            
            if tag not in dwarf_tag:
                dd['tag'] = 'tag_num_'+str(tag)
                while 1:
                    m = debug_abbrev_section_data[i]
                    if m == 0: break
                    i+=1
            else:
                dd['tag'] = dwarf_tag[tag]
            dd['list'] = []
            if D : print(abbrev_num, 'tag:', dd['tag'])

            sublings = debug_abbrev_section_data[i] # format of tag (?sibling)
            i+=1
            at = debug_abbrev_section_data[i]
            while at != 0:
                if len(debug_abbrev_section_data) <= i+3:
                    break
                at = debug_abbrev_section_data[i] 
                i+=1
                form = debug_abbrev_section_data[i] 
                i+=1
                if at == 0:
                    break
                if at >= 128:
                    at = form
                    form = debug_abbrev_section_data[i] 
                    i+=1
                    dd['unknown'+str(at)] = dwarf_form[form]
                    dd['list'] += ['unknown'+str(at)]
                    if D : print('\t','unknown'+str(at),'  \t', dwarf_form[form])
                    continue
                dd[dwarf_at[at]] = dwarf_form[form]
                dd['list'] += [dwarf_at[at]]
                if D : print('\t',dwarf_at[at],'  \t', dwarf_form[form])
        return self.abbrev

    def readDebugInfo(self, debug_info_section_data):
        if DEBUG_PRINT: print('\n', '='*10, 'Read Debug Info', '='*10, '\n')
        self.debug_info = list()
        if DEBUG_PRINT: 
            print('\n     -- ', end ='')
            for j in range(16):
                print('{:3x}'.format(j), end = ' ')
            for i in range(0,30):
                print('\n0x{:3x} -- '.format(i*16), end ='')
                for j in range(16):
                    if i*16+j >= len(debug_info_section_data):
                        break
                    print('{:3x}'.format(debug_info_section_data[i*16+j]), end = ' ')
        ptr = 0
        length = int.from_bytes(debug_info_section_data[ptr:ptr+4], self.endian)
        ptr = 4
        Version = int.from_bytes(debug_info_section_data[ptr:ptr+4],self.endian)
        ptr = 8
        abbrev_offset = int.from_bytes(debug_info_section_data[ptr:ptr+2],self.endian)
        ptr = 10
        pointer_size = int.from_bytes(debug_info_section_data[ptr:ptr+1],self.endian)
        
        data = debug_info_section_data[:]
        i = 11
        while 1:
            if DEBUG_PRINT: print(i, length, i>=length)
            if i>=length:
                break
            abb = data[i]
            i+=1
            if DEBUG_PRINT: print('\t',abb,hex(i-1),self.abbrev[abb]['tag'],[str(int(x)) for x in data[i:i+40]])
            if abb == 0: continue
            if DEBUG_PRINT: print(self.abbrev[abb])
            self.debug_info.append({'tag':self.abbrev[abb]['tag'] }) 
            tag = self.debug_info[-1]
            for attr in self.abbrev[abb]['list']:
                if DEBUG_PRINT: print('    <{:05x}>  {:24} - '.format(i, attr), end=' ')
                if DEBUG_PRINT: print('({:16}) : '.format(self.abbrev[abb][attr]), end = ' ')
                data_type = self.abbrev[abb][attr]
                if data_type in ['DW_FORM_flag_present']: # flag
                    tag[attr] = True
                elif data_type in ['DW_FORM_data1', 'DW_FORM_flag']: # read 1 byte
                    tag[attr] = int.from_bytes(data[i:i+1], self.endian)
                    i+=1
                elif data_type in ['DW_FORM_data2']: # read 2 bytes
                    tag[attr] = int.from_bytes(data[i:i+2], self.endian)
                    i+=2
                elif data_type in ['DW_FORM_data4', 'DW_FORM_sec_offset']: # read 4 bytes
                    tag[attr] = int.from_bytes(data[i:i+4], self.endian)
                    i+=4
                elif data_type in ['DW_FORM_data8', 'DW_FORM_ref_sig8']: # read 8 bytes
                    tag[attr] = int.from_bytes(data[i:i+8], self.endian)
                    i+=8
                elif data_type in ['DW_FORM_data16']: # read 16 bytes
                    tag[attr] = int.from_bytes(data[i:i+16], self.endian)
                    i+=16
                elif data_type in ['DW_FORM_string']: # string till 0
                    byte = data[i]
                    i+=1
                    tag[attr] = ''
                    while byte != 0:
                        tag[attr] += chr(byte)
                        byte = data[i]
                        i+=1
                elif data_type in ['DW_FORM_ref1']:
                    tag[attr] = int.from_bytes(data[i:i+1], self.endian)
                    i+=1
                elif data_type in ['DW_FORM_ref2']:
                    tag[attr] = int.from_bytes(data[i:i+2], self.endian)
                    i+=2
                elif data_type in ['DW_FORM_ref4']:
                    tag[attr] = int.from_bytes(data[i:i+4], self.endian)
                    i+=4
                elif data_type in ['DW_FORM_ref8']:
                    tag[attr] = int.from_bytes(data[i:i+8], self.endian)
                    i+=8
                elif data_type in ['DW_FORM_addr', 'DW_FORM_strp', 'DW_FORM_ref_addr']: # read pointer size bytes
                    tag[attr] = int.from_bytes(data[i:i+pointer_size], self.endian)
                    i+=pointer_size
                elif data_type in ['DW_FORM_block1']:
                    block_size = int.from_bytes(data[i:i+1], 'big')
                    i+=1
                    tag[attr] = int.from_bytes(data[i:i+block_size], 'big')
                    i+=block_size
                elif data_type in ['DW_FORM_block2']:
                    block_size = int.from_bytes(data[i:i+2], 'big')
                    i+=2
                    tag[attr] = int.from_bytes(data[i:i+block_size], 'big')
                    i+=block_size
                elif data_type in ['DW_FORM_block4']:
                    block_size = int.from_bytes(data[i:i+4], 'big')
                    i+=4
                    tag[attr] = int.from_bytes(data[i:i+block_size], 'big')
                    i+=block_size
                elif data_type in ['DW_FORM_block']:
                    block_size, length = getULEB128(data)
                    i+=length
                    tag[attr] = int.from_bytes(data[i:i+block_size], 'big')
                    i+=block_size
                elif data_type in ['DW_FORM_sdata']:
                    value, length = getLEB128(data)
                    tag[attr] = value
                    i+=length
                elif data_type in ['DW_FORM_udata', 'DW_FORM_ref_udata']:
                    value, length = getULEB128(data)
                    tag[attr] = value
                    i+=length
                else: # not recognized
                    # 'DW_FORM_indirect', 'DW_FORM_exprloc', 'DW_FORM_strx', 'DW_FORM_addrx', 'DW_FORM_ref_sup4', 'DW_FORM_strp_sup', 'DW_FORM_line_strp', 'DW_FORM_implicit_const', 'DW_FORM_loclistx', 'DW_FORM_rnglistx', 'DW_FORM_ref_sup8', 'DW_FORM_strx1', 'DW_FORM_strx2', 'DW_FORM_strx3', 'DW_FORM_strx4', 'DW_FORM_addrx1', 'DW_FORM_addrx2', 'DW_FORM_addrx3', 'DW_FORM_addrx4'
                    tag[attr] = True
                if DEBUG_PRINT: print('{} {}'.format(
                    tag[attr],
                    hex(tag[attr]) if isinstance(tag[attr],int) else ''
                    ))
            if 'DW_TAG_compile_unit' == self.abbrev[abb]['tag']: break
        return self.debug_info

    def readDebugLine(self, debug_line_section_data):
        if DEBUG_PRINT: print('\n', '='*10, 'Read Debug Line', '='*10, '\n')
        machine = StateMachine()
        machine.run(debug_line_section_data, self.endian)
        self.mapping = machine.getMapping()
        self.directories = machine.getDirectories()
        self.files = machine.getFiles()
        return self.mapping

    def keys(self):
        return self.mapping.keys()

    def getitem(self, key: int) -> list():
        if type(key) != int:
            return [0,0,0]
        # find closest key
        sorted_keys = sorted([k for k in self.mapping if k <= key])
        if len(sorted_keys) == 0:
            return ['','',0,0]
        offset = sorted_keys[-1]
        mapi = self.mapping[offset]
        f = self.files[mapi[0]]
        d = self.directories[f[1]]
        if DEBUG_PRINT: print('myk:', key, offset, sorted_keys)
        return [d, f[0], mapi[1], mapi[2]]

    def __getitem__(self, key: int) -> list():
        return self.getitem(key)

    def __contains__(self, item):
        return item in self.mapping

    def __str__(self):
        string = ''
        for attr in [a for a in dir(self) if not a.startswith('__') and not callable(getattr(self,a))]:
            string+=attr+': '+ getattr(self,attr).__str__()+'\n'
        return string

class StateMachine:
    def __init__(self, endian='little'):
        self.endian = endian
        self.raw_mapping = dict()
        self.resetValues()

    def resetValues(self):
        self.address = 0
        self.op_index = 0 # For non-VLIW architectures, this register will always be 0.
        self.file = 1
        self.line = 1
        self.column = 0
        self.is_stmt = True
        self.basic_block = False
        self.end_sequence = False
        self.prologue_end = False
        self.epilogue_begin = False
        self.isa = 0
        self.discriminator = 0
        self.addr_bytes = 8

    def addToTable(self):
        D = DEBUG_PRINT 
        self.raw_mapping[self.address] = [self.file, self.line, self.column]
        if D: print('Added to talble: ', hex(self.address), ' -- ',self.raw_mapping[self.address])

    def copy(self):
        # Copy to table
        self.addToTable()

        # Init
        self.discriminator = 0
        self.basic_block = False
        self.prologue_end = False
        self.epilogue_begin = False

    def readSourceMap(self, data):
        D = DEBUG_PRINT
        ind = 0
        while ind < len(data): # 150: #
            opcode = data[ind]
            if opcode == 0:   # Extended Opcode
                instr_length, i = getULEB128(data[ind+1:])
                ex_opcode = int.from_bytes(data[ind+2:ind+3], self.endian)
                if ex_opcode == 1: # DW_LNE_end_sequence
                    self.end_sequence = True
                    if D: print('\n0x{:x} - {}'.format(ind+360, 'Extended Opcode: end sequeunce'))
                    # TODO: correct calculation of address for end sequence opcode
                    self.addToTable() 
                    self.resetValues()
                elif ex_opcode == 2: # DW_LNE_set_address
                    addr_width = instr_length - 1
                    self.address = int.from_bytes(data[ind+3:ind+3+addr_width], self.endian)
                    self.op_index = 0 
                    if D: print('\n0x{:x} - {}: {}'.format(ind+360, 'Extended Opcode: set address', self.address))
                elif ex_opcode == 3: # DW_LNE_set_discriminator
                    num, i = getLEB128(data[ind+1:])
                    self.discriminator = num
                    if D: print('\n0x{:x} - {}: {}'.format(ind+360, 'Extended Opcode: set discriminator', self.discriminator))
                elif ex_opcode == 128: # DW_LNE_lo_user
                    pass
                    if D: print('\n0x{:x} - {}'.format(ind+360, 'Extended Opcode: louser'))
                elif ex_opcode == 255: # DW_LNE_hi_user
                    pass
                    if D: print('\n0x{:x} - {}'.format(ind+360, 'Extended Opcode: hi user', self.line))
                ind += (i + instr_length )
                pass
            elif opcode == 1:   # 'DW_LNS_copy'
                if D: print('\n0x{:x} - {}'.format(ind+360, 'Copy'))
                self.copy()
                pass
            elif opcode == 2: # DW_LNS_advance_pc
                num, i = getULEB128(data[ind+1:])
                self.address += num
                self.op_index = 0
                if D: print('\n0x{:x} - Advance PC by {} to 0x{:4x}'.format(ind+360, num, self.address))
                self.addToTable()
                ind += i
            elif opcode == 3: # DW_LNS_advance_line
                num, i = getLEB128(data[ind+1:])
                self.line += num
                if D: print('\n0x{:x} - {} by {}: {}'.format(ind+360, 'Advance Line', num, self.line))
                ind += i
            elif opcode == 4: # DW_LNS_set_file
                num, i = getULEB128(data[ind+1:])
                self.file = num
                if D: print('\n0x{:x} - {}: {}'.format(ind+360, 'Set file', self.file))
                ind += i
            elif opcode == 5: # DW_LNS_set_column
                num, i = getULEB128(data[ind+1:])
                self.column = num
                if D: print('\n0x{:x} - {}: {}'.format(ind+360, 'Set column', self.column))
                ind += i
            elif opcode == 6: # DW_LNS_negate_stmt
                self.is_stmt = False if self.is_stmt else True
                if D: print('\n0x{:x} - {} to {}'.format(ind+360, 'STMT = ', self.is_stmt))
            elif opcode == 7: # DW_LNS_set_basic_block
                self.basic_block = True
                if D: print('\n0x{:x} - {}'.format(ind+360, 'Set BBL'))
            elif opcode == 8: # DW_LNS_const_add_pc
                adjusted_opcode = 255-self.opcode_base
                operation_advance = adjusted_opcode // self.line_range
                address_increment = self.minimum_instruction_length * ((self.op_index+operation_advance)//self.maximum_operations_per_instruction)
                line_increment = self.line_base + (adjusted_opcode % self.line_range)
                self.address = self.address + address_increment
                if D: print('\n0x{:x} - Const add PC {}, Advance address by {}, to 0x{:x}'.format(ind+360,opcode-13,address_increment, self.address))
                pass
            elif opcode == 9: # DW_LNS_fixed_advance_pc
                self.op_index = 0
                self.address += int.from_bytes(data[ind+2:ind+4], self.endian, signed=False)
                if D: print('\n0x{:x} - Fixed advance PC by {} to {} '.format(ind+360, int.from_bytes(data[ind+2:ind+4], self.endian),self.address))
                ind += 2
                pass
            elif opcode == 10: # DW_LNS_set_prologue_end
                self.prologue_end = True
                if D: print('\n0x{:x} - {}'.format(ind+360, 'Set prologue end'))
            elif opcode == 11: # DW_LNS_set_epilogue_begin
                self.epilogue_begin = True
                if D: print('\n0x{:x} - {}'.format(ind+360, 'set epilogue begin'))
            elif opcode == 12: # DW_LNS_set_isa
                num, i = getLEB128(data[ind+1:])
                self.isa = num
                if D: print('\n0x{:x} - {}: {}'.format(ind+360, 'Set isa', self.isa))
                ind += i
                pass
            elif opcode > 12: # Special 
                adjusted_opcode = opcode-self.opcode_base
                operation_advance = adjusted_opcode // self.line_range
                address_increment = self.minimum_instruction_length * ((self.op_index+operation_advance)//self.maximum_operations_per_instruction)
                line_increment = self.line_base + (adjusted_opcode % self.line_range)
                self.address = self.address + address_increment
                self.line += line_increment
                if D: print('\n0x{:x} - Special opcode {}, Advance address by {}, to 0x{:x}, line increment: {} to {}'.format(ind+360,opcode-13,address_increment, self.address, line_increment, self.line))
                self.addToTable()
            ind += 1

    def run(self, data, endian = 'little'):
        self.endian = endian
        addr_bytes = 1
        self.unit_length = int.from_bytes(data[0:3], endian)
        self.version = int.from_bytes(data[4:6], endian)
        self.address_size = int.from_bytes(data[6:7], endian)
        self.segment_selector_size = int.from_bytes(data[7:8], endian)
        self.header_length = int.from_bytes(data[8:9+addr_bytes], endian)
        pnt = 9 + addr_bytes
        self.minimum_instruction_length = int.from_bytes(data[pnt:pnt+1], endian)
        self.maximum_operations_per_instruction = int.from_bytes(data[pnt+1:pnt+2], endian)
        self.default_is_stmt = int.from_bytes(data[pnt+2:pnt+3], endian)
        self.line_base = int.from_bytes(data[pnt+3:pnt+4], endian, signed=True)
        self.line_range = int.from_bytes(data[pnt+4:pnt+5], endian)
        self.opcode_base = int.from_bytes(data[pnt+5:pnt+6], endian)
        pnt = pnt+6
        self.standard_opcode_lengths = {}
        for ind, opcode_value in enumerate(range(1, self.opcode_base)):
            self.standard_opcode_lengths[opcode_value] = int.from_bytes(data[pnt+ind:pnt+ind+1], endian)
        pnt = pnt+self.opcode_base-1
        # directory_entry_format_count
        # directory_entry_format
        curr = 0
        prev = 0
        ind = 0
        dir_num = 1
        self.directories = []
        self.directories.append('')
        self.directories.append('')
        while 1:
            prev = curr
            curr = int.from_bytes(data[pnt+ind:pnt+ind+1], endian)
            ind += 1
            if DEBUG_PRINT: print(curr, prev)
            if curr == 0:
                if DEBUG_PRINT: print(self.directories[dir_num])
                if prev == 0:
                    self.directories.pop()
                    break
                dir_num += 1
                self.directories.append('')
                continue
            self.directories[dir_num] += chr(curr)
        self.directories_count = len(self.directories)-1
        pnt = pnt+ind
        # self.file_name_entry_format_count = int.from_bytes(data[0:3], endian)
        # self.file_name_entry_format = int.from_bytes(data[0:3], endian)
        curr = 0
        prev = 0
        ind = 0
        dir_num = 1
        self.file_names =[]
        self.file_names.append(['',0,0,0])
        self.file_names.append(['',0,0,0])
        while 1:
            prev = curr
            curr = int.from_bytes(data[pnt+ind:pnt+ind+1], endian)
            ind += 1
            if curr == 0:
                if prev == 0:
                    self.file_names.pop()
                    break
                self.file_names[dir_num][1] = int.from_bytes(data[pnt+ind:pnt+ind+1], endian)
                ind += 3
                dir_num += 1
                self.file_names.append(['',0,0,0])
                continue
            self.file_names[dir_num][0] += chr(curr)
        self.file_names_count = len(self.file_names)-1
        pnt = pnt+ind
        self.readSourceMap(data[pnt:])

    def getMapping(self):
        return self.raw_mapping

    def getDirectories(self):
        return self.directories

    def getFiles(self):
        return self.file_names

    def __str__(self):
        string = ''
        for attr in [a for a in dir(self) if not a.startswith('__') and not callable(getattr(self,a))]:
            string+=attr+': '+ getattr(self,attr).__str__()+'\n'
        return string

def getULEB128(data):
    result = 0
    shift = 0
    i = 0
    while 1:
        byte = data[i]
        i+=1
        result |= (byte & 0b01111111) << shift
        shift += 7
        if not (byte & 0b10000000):
            break
    return result, i

def getLEB128(data):
    result = 0
    shift = 0
    size = 32
    i = 0
    byte = 0
    while 1:
        byte = data[i]
        if DEBUG_PRINT: print(byte, byte & 0b01111111, not byte & 0b10000000,  end = '|')
        i+=1
        result |= (byte & 0b01111111) << shift
        shift += 7
        if not (byte & 0b10000000):
            break
    if DEBUG_PRINT: print('===', byte & 0b1000000, byte, end = ' ')
    if (byte & 0b1000000):
        result |= - (1 << shift)
    return result, i


dwarf_at = {1: 'DW_AT_sibling', 2: 'DW_AT_location', 3: 'DW_AT_name', 9: 'DW_AT_ordering', 11: 'DW_AT_byte_size', 12: 'DW_AT_bit_offset', 13: 'DW_AT_bit_size', 16: 'DW_AT_stmt_list', 17: 'DW_AT_low_pc', 18: 'DW_AT_high_pc', 19: 'DW_AT_language', 21: 'DW_AT_discr', 22: 'DW_AT_discr_value', 23: 'DW_AT_visibility', 24: 'DW_AT_import', 25: 'DW_AT_string_length', 26: 'DW_AT_common_reference', 27: 'DW_AT_comp_dir', 28: 'DW_AT_const_value', 29: 'DW_AT_containing_type', 30: 'DW_AT_default_value', 32: 'DW_AT_inline', 33: 'DW_AT_is_optional', 34: 'DW_AT_lower_bound', 37: 'DW_AT_producer', 39: 'DW_AT_prototyped', 42: 'DW_AT_return_addr', 44: 'DW_AT_start_scope', 46: 'DW_AT_bit_stride', 47: 'DW_AT_upper_bound', 49: 'DW_AT_abstract_origin', 50: 'DW_AT_accessibility', 51: 'DW_AT_address_class', 52: 'DW_AT_artificial', 53: 'DW_AT_base_types', 54: 'DW_AT_calling_convention', 55: 'DW_AT_count', 56: 'DW_AT_data_member_location', 57: 'DW_AT_decl_column', 58: 'DW_AT_decl_file', 59: 'DW_AT_decl_line', 60: 'DW_AT_declaration', 61: 'DW_AT_discr_list', 62: 'DW_AT_encoding', 63: 'DW_AT_hi_user', 64: 'DW_AT_frame_base', 65: 'DW_AT_friend', 66: 'DW_AT_identifier_case', 68: 'DW_AT_namelist_item', 69: 'DW_AT_priority', 70: 'DW_AT_segment', 71: 'DW_AT_specification', 72: 'DW_AT_static_link', 73: 'DW_AT_type', 74: 'DW_AT_use_location', 75: 'DW_AT_variable_parameter', 76: 'DW_AT_virtuality', 77: 'DW_AT_vtable_elem_location', 78: 'DW_AT_allocated', 79: 'DW_AT_associated', 80: 'DW_AT_data_location', 81: 'DW_AT_byte_stride', 82: 'DW_AT_entry_pc', 83: 'DW_AT_use_UTF8', 84: 'DW_AT_extension', 85: 'DW_AT_ranges', 86: 'DW_AT_trampoline', 87: 'DW_AT_call_column', 88: 'DW_AT_call_file', 89: 'DW_AT_call_line', 90: 'DW_AT_description', 91: 'DW_AT_binary_scale', 92: 'DW_AT_decimal_scale', 93: 'DW_AT_small', 94: 'DW_AT_decimal_sign', 95: 'DW_AT_digit_count', 96: 'DW_AT_picture_string', 97: 'DW_AT_mutable', 98: 'DW_AT_threads_scaled', 99: 'DW_AT_explicit', 100: 'DW_AT_object_pointer', 101: 'DW_AT_endianity', 102: 'DW_AT_elemental', 103: 'DW_AT_pure', 104: 'DW_AT_recursive', 105: 'DW_AT_signature', 106: 'DW_AT_main_subprogram', 107: 'DW_AT_data_bit_offset', 108: 'DW_AT_const_expr', 109: 'DW_AT_enum_class', 110: 'DW_AT_linkage_name', 111: 'DW_AT_string_length_bit_size', 112: 'DW_AT_string_length_byte_size', 113: 'DW_AT_rank', 114: 'DW_AT_str_offsets_base', 115: 'DW_AT_addr_base', 116: 'DW_AT_rnglists_base', 118: 'DW_AT_dwo_name', 119: 'DW_AT_reference', 120: 'DW_AT_rvalue_reference', 121: 'DW_AT_macros', 122: 'DW_AT_call_all_calls', 123: 'DW_AT_call_all_source_calls', 124: 'DW_AT_call_all_tail_calls', 125: 'DW_AT_call_return_pc', 126: 'DW_AT_call_value', 127: 'DW_AT_call_origin', 128: 'DW_AT_call_parameter', 129: 'DW_AT_call_pc', 130: 'DW_AT_call_tail_call', 131: 'DW_AT_call_target', 132: 'DW_AT_call_target_clobbered', 133: 'DW_AT_call_data_location', 134: 'DW_AT_call_data_value', 135: 'DW_AT_noreturn', 136: 'DW_AT_alignment', 137: 'DW_AT_export_symbols', 138: 'DW_AT_deleted', 139: 'DW_AT_defaulted', 140: 'DW_AT_loclists_base', 8192: 'DW_AT_lo_user'}

dwarf_tag = {1: 'DW_TAG_array_type', 2: 'DW_TAG_class_type', 3: 'DW_TAG_entry_point', 4: 'DW_TAG_enumeration_type', 5: 'DW_TAG_formal_parameter', 8: 'DW_TAG_imported_declaration', 10: 'DW_TAG_label', 11: 'DW_TAG_lexical_block', 13: 'DW_TAG_member', 15: 'DW_TAG_hi_user', 16: 'DW_TAG_reference_type', 17: 'DW_TAG_compile_unit', 18: 'DW_TAG_string_type', 19: 'DW_TAG_structure_type', 21: 'DW_TAG_subroutine_type', 22: 'DW_TAG_typedef', 23: 'DW_TAG_union_type', 24: 'DW_TAG_unspecified_parameters', 25: 'DW_TAG_variant', 26: 'DW_TAG_common_block', 27: 'DW_TAG_common_inclusion', 28: 'DW_TAG_inheritance', 29: 'DW_TAG_inlined_subroutine', 30: 'DW_TAG_module', 31: 'DW_TAG_ptr_to_member_type', 32: 'DW_TAG_set_type', 33: 'DW_TAG_subrange_type', 34: 'DW_TAG_with_stmt', 35: 'DW_TAG_access_declaration', 36: 'DW_TAG_base_type', 37: 'DW_TAG_catch_block', 38: 'DW_TAG_const_type', 39: 'DW_TAG_constant', 40: 'DW_TAG_enumerator', 41: 'DW_TAG_file_type', 42: 'DW_TAG_friend', 43: 'DW_TAG_namelist', 44: 'DW_TAG_namelist_item', 45: 'DW_TAG_packed_type', 46: 'DW_TAG_subprogram', 47: 'DW_TAG_template_type_parameter', 48: 'DW_TAG_template_value_parameter', 49: 'DW_TAG_thrown_type', 50: 'DW_TAG_try_block', 51: 'DW_TAG_variant_part', 52: 'DW_TAG_variable', 53: 'DW_TAG_volatile_type', 54: 'DW_TAG_dwarf_procedure', 55: 'DW_TAG_restrict_type', 56: 'DW_TAG_interface_type', 57: 'DW_TAG_namespace', 58: 'DW_TAG_imported_module', 59: 'DW_TAG_unspecified_type', 60: 'DW_TAG_partial_unit', 61: 'DW_TAG_imported_unit', 63: 'DW_TAG_condition', 64: 'DW_TAG_shared_type', 65: 'DW_TAG_type_unit', 66: 'DW_TAG_rvalue_reference_type', 67: 'DW_TAG_template_alias', 68: 'DW_TAG_coarray_type', 69: 'DW_TAG_generic_subrange', 70: 'DW_TAG_dynamic_type', 71: 'DW_TAG_atomic_type', 72: 'DW_TAG_call_site', 73: 'DW_TAG_call_site_parameter', 74: 'DW_TAG_skeleton_unit', 75: 'DW_TAG_immutable_type', 16512: 'DW_TAG_lo_user'}

dwarf_form = {1: 'DW_FORM_addr', 3: 'DW_FORM_block2', 4: 'DW_FORM_block4', 5: 'DW_FORM_data2', 6: 'DW_FORM_data4', 7: 'DW_FORM_data8', 8: 'DW_FORM_string', 9: 'DW_FORM_block', 10: 'DW_FORM_block1', 11: 'DW_FORM_data1', 12: 'DW_FORM_flag', 13: 'DW_FORM_sdata', 14: 'DW_FORM_strp', 15: 'DW_FORM_udata', 16: 'DW_FORM_ref_addr', 17: 'DW_FORM_ref1', 18: 'DW_FORM_ref2', 19: 'DW_FORM_ref4', 20: 'DW_FORM_ref8', 21: 'DW_FORM_ref_udata', 22: 'DW_FORM_indirect', 23: 'DW_FORM_sec_offset', 24: 'DW_FORM_exprloc', 25: 'DW_FORM_flag_present', 26: 'DW_FORM_strx', 27: 'DW_FORM_addrx', 28: 'DW_FORM_ref_sup4', 29: 'DW_FORM_strp_sup', 30: 'DW_FORM_data16', 31: 'DW_FORM_line_strp', 32: 'DW_FORM_ref_sig8', 33: 'DW_FORM_implicit_const', 34: 'DW_FORM_loclistx', 35: 'DW_FORM_rnglistx', 36: 'DW_FORM_ref_sup8', 37: 'DW_FORM_strx1', 38: 'DW_FORM_strx2', 39: 'DW_FORM_strx3', 40: 'DW_FORM_strx4', 41: 'DW_FORM_addrx1', 42: 'DW_FORM_addrx2', 43: 'DW_FORM_addrx3', 44: 'DW_FORM_addrx4'}

dwarf_lne = {1: 'DW_LNE_end_sequence', 2: 'DW_LNE_set_address', 4: 'DW_LNE_set_discriminator', 128: 'DW_LNE_lo_user', 255: 'DW_LNE_hi_user'}

dwarf_lns = {1: 'DW_LNS_copy', 2: 'DW_LNS_advance_pc', 3: 'DW_LNS_advance_line', 4: 'DW_LNS_set_file', 5: 'DW_LNS_set_column', 6: 'DW_LNS_negate_stmt', 7: 'DW_LNS_set_basic_block', 8: 'DW_LNS_const_add_pc', 9: 'DW_LNS_fixed_advance_pc', 10: 'DW_LNS_set_prologue_end', 11: 'DW_LNS_set_epilogue_begin', 12: 'DW_LNS_set_isa'}

dwarf_lnct = {1: 'DW_LNCT_path', 2: 'DW_LNCT_directory_index', 3: 'DW_LNCT_timestamp', 4: 'DW_LNCT_size', 5: 'DW_LNCT_MD5', 8192: 'DW_LNCT_lo_user', 16383: 'DW_LNCT_hi_user'}

def getMapping(data) -> dict():
    elf = Elf(data)
    return elf

def getMappingFromFile(fileName: str) -> dict():
    if (not os.path.isfile(fileName)) or os.path.islink(fileName):
        print('ELF file not found')
        return None
    with open(fileName, 'rb') as f:
        data = f.read()
        mapping = getMapping(data)
        return mapping

if __name__=='__main__':
    if len( sys.argv)!= 2 or sys.argv[1] in ['-h', '--help','-help', '/?', '?'] :
        print('Usage: python3 elf.py /path/to/elf/file.elf\nPrint this help: -h')
        exit(0)
    print('Read file: ', sys.argv[1])
    mapping = getMappingFromFile(sys.argv[1])
    if mapping == None:
        print('File not parsed: ', sys.argv[1])
        exit(-1)
    for key in mapping.keys():
        print('0x{:04x} -- {}'.format(key, mapping[key]))
