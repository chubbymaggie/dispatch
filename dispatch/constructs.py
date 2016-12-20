import subprocess
import logging
import capstone
import string
from enums import *

import ctypes

class Function(object):
    NORMAL_FUNC = 0
    DYNAMIC_FUNC = 1

    def __init__(self, address, size, name, executable, type=NORMAL_FUNC):
        self.address = int(address)
        self.size = int(size)
        self.name = name
        self.type = type
        self._executable = executable

        # BELOW: Helpers used to explore the binary.
        # NOTE: These should *not* be directly modified at this time.
        # Instead, executable.replace_at should be used.
        self.instructions = [] # Sequential list of instructions
        self.bbs = [] # Sequential list of basic blocks. BB instructions are auto-populated from our instructions

    def __repr__(self):
        return '<Function \'{}\' at {}>'.format(self.name, hex(self.address))

    def do_bb_analysis(self):
        if self.instructions:
            bb_ends = set([self.instructions[-1].address + self.instructions[-1].size])

            for i in range(len(self.instructions) - 1):
                cur = self.instructions[i]
                next = self.instructions[i + 1]

                if cur.is_jump():
                    bb_ends.add(next.address)
                    if cur.operands[0].type == Operand.IMM:
                        bb_ends.add(cur.operands[0].imm)

            bb_ends = sorted(list(bb_ends))
            bb_instructions = []

            for ins in self.instructions:
                if ins.address == bb_ends[0] and bb_instructions:
                    bb = BasicBlock(self,
                                    bb_instructions[0].address,
                                    bb_instructions[-1].address + bb_instructions[-1].size - bb_instructions[0].address)
                    bb.instructions = bb_instructions
                    self.bbs.append(bb)

                    bb_ends = bb_ends[1:]
                    bb_instructions = [ins]
                else:
                    bb_instructions.append(ins)

            # There will always be one BB left over which "ends" at the first address of the next function, so be
            # sure to add it

            bb = BasicBlock(self,
                            bb_instructions[0].address,
                            bb_instructions[-1].address + bb_instructions[-1].size - bb_instructions[0].address)
            bb.instructions = bb_instructions
            self.bbs.append(bb)

    def contains_address(self, address):
        return self.address <= address < self.address + self.size

    def iter_bbs(self):
        for bb in self.bbs:
            yield bb

    def print_disassembly(self):
        for i in self.instructions:
            print hex(i.address) + ' ' + str(i)

    def demangle(self):
        if self.name.startswith('_Z'):
            p = subprocess.Popen(['c++filt', '-n', self.name], stdout=subprocess.PIPE)
            demangled, _ = p.communicate()
            return demangled.replace('\n','')
        elif self.name.startswith('@'):
            # TODO: MSVC demangling (look at wine debugger source)
            return self.name
        else:
            logging.debug('Call to demangle with a non-reserved function name')


class BasicBlock(object):
    def __init__(self, parent_func, address, size):
        self.parent = parent_func
        self.address = int(address)
        self.size = int(size)
        self.offset = self.parent.address - self.address
        self.instructions = []

    def __repr__(self):
        return '<Basic block at {}>'.format(hex(self.address))

    def print_disassembly(self):
        for i in self.instructions:
            print hex(i.address) + ' ' + str(i)


class Instruction(object):
    GRP_CALL = 0
    GRP_JUMP = 1

    def __init__(self, address, size, raw, mnemonic, operands, groups, backend_instruction, executable):
        self.address = int(address)
        self.size = int(size)
        self.raw = raw
        self.mnemonic = mnemonic
        self.operands = operands
        self.groups = groups
        self._backend_instruction = backend_instruction
        self._executable = executable

        self.comment = ''

    def __repr__(self):
        return '<Instruction at {}>'.format(hex(self.address))

    def __str__(self):
        s = self.mnemonic + ' ' + self.nice_op_str()
        if self.comment:
            s += '; "{}"'.format(self.comment)
        if self.address in self._executable.xrefs:
            s += '; XREF={}'.format(', '.join(hex(a)[:-1] for a in self._executable.xrefs[self.address]))
            # TODO: Print nice function relative offsets if the xref is in a function

        return s

    def is_call(self):
        return Instruction.GRP_CALL in self.groups

    def is_jump(self):
        return Instruction.GRP_JUMP in self.groups

    def redirects_flow(self):
        return self.is_jump() or self.is_call()

    def references_ip(self):
        implicit_read, implicit_written = self._backend_instruction.regs_access()
        explicit_accessed = set.union(*[op.used_regs() for op in self.operands])
        all_accessed = set.union(explicit_accessed, implicit_read, implicit_written)
        return bool(self._executable.analyzer.IP_REGS.intersection(all_accessed))

    def references_sp(self):
        implicit_read, implicit_written = self._backend_instruction.regs_access()
        explicit_accessed = set.union(*[op.used_regs() for op in self.operands])
        all_accessed = set.union(explicit_accessed, implicit_read, implicit_written)
        return bool(self._executable.analyzer.SP_REGS.intersection(all_accessed))

    def op_str(self):
        return ', '.join(str(op) for op in self.operands)

    def nice_op_str(self):
        '''
        Returns the operand string "nicely formatted." I.e. replaces addresses with function names (and function
        relative offsets) if appropriate.
        :return: The nicely formatted operand string
        '''
        op_strings = [str(op) for op in self.operands]

        # If this is an immediate call or jump, try to put a name to where we're calling/jumping to
        if self.is_call() or self.is_jump():
            # jump/call destination will always be the last operand (even with conditional ARM branch instructions)
            operand = self.operands[-1]
            # TODO: Don't only do this when we've got an IMM operation
            if operand.type == Operand.IMM:
                if operand.imm in self._executable.functions:
                    op_strings[-1] = self._executable.functions[operand.imm].name
                elif self._executable.vaddr_is_executable(operand.imm):
                    for func in self._executable.iter_functions():
                        if func.contains_address(operand.imm):
                            diff = operand.imm - func.address
                            op_strings[-1] = func.name+'+'+hex(diff)
                            break
        else: # TODO: Limit this to only be sensible instructions (e.g. mov, push, etc.)
            for i, operand in enumerate(self.operands):
                if operand.type == Operand.IMM and operand.imm in self._executable.strings:
                    referenced_string = self._executable.strings[operand.imm]
                    op_strings[i] = referenced_string.short_name
                    self.comment = referenced_string.string.strip()

        return ', '.join(op_strings)


class Operand(object):
    IMM = 0
    FP = 1
    REG = 2
    MEM = 3

    def __init__(self, type, size, instruction, **kwargs):
        self.type = type
        self.size = size
        self._instruction = instruction
        if self.type == Operand.IMM:
            self.imm = int(kwargs.get('imm'))
        elif self.type == Operand.FP:
            self.fp = float(kwargs.get('fp'))
        elif self.type == Operand.REG:
            self.reg = kwargs.get('reg')
        elif self.type == Operand.MEM:
            self.base = kwargs.get('base')
            self.index = kwargs.get('index')
            self.scale = int(kwargs.get('scale', 1))
            self.disp = int(kwargs.get('disp', 0))
        else:
            raise ValueError('Type is not one of Operand.{IMM,FP,REG,MEM}')

    def _get_simplified(self):
        # Auto-simplify ip-relative operands to their actual address
        if self.type == Operand.MEM and self.base in self._instruction._executable.analyzer.IP_REGS and self.index == 0:
            addr = self._instruction.address + self._instruction.size + self.index * self.scale + self.disp
            return Operand(Operand.MEM, self.size, self._instruction, disp=addr)

        return self

    def used_regs(self):
        if self.type == Operand.REG:
            return set([self.reg])
        elif self.type == Operand.MEM:
            return set([self.base, self.index])
        else:
            return set()

    def __str__(self):
        sizes = {
                1: 'byte',
                2: 'word',
                4: 'dword',
                8: 'qword'
                }
        if self.type == Operand.IMM:
            return sizes.get(self.size, '') + ' ' + hex(self.imm)
        elif self.type == Operand.FP:
            return str(self.fp)
        elif self.type == Operand.REG:
            return self._instruction._executable.analyzer.REG_NAMES[self.reg]
        elif self.type == Operand.MEM:
            simplified = self._get_simplified()

            s = '['

            show_plus = False
            if simplified.base:
                s += self._instruction._executable.analyzer.REG_NAMES[simplified.base]
                show_plus = True
            if simplified.index:
                if show_plus:
                    s += ' + '

                s += self._instruction._executable.analyzer.REG_NAMES[simplified.index]
                if simplified.scale > 1:
                    s += '*'
                    s += str(simplified.scale)

                show_plus = True
            if simplified.disp:
                if show_plus:
                    s += ' + '
                s += hex(simplified.disp)

            s += ']'

            return sizes.get(self.size, '') + ' ' + s


def operand_from_cs_op(csOp, instruction):
    size = csOp.size if hasattr(csOp, 'size') else None
    if csOp.type == capstone.CS_OP_IMM:
        return Operand(Operand.IMM, size, instruction, imm=csOp.imm)
    elif csOp.type == capstone.CS_OP_FP:
        return Operand(Operand.FP, size, instruction, fp=csOp.fp)
    elif csOp.type == capstone.CS_OP_REG:
        return Operand(Operand.REG, size, instruction, reg=csOp.reg)
    elif csOp.type == capstone.CS_OP_MEM:
        return Operand(Operand.MEM, size, instruction, base=csOp.mem.base, index=csOp.mem.index, scale=csOp.mem.scale, disp=csOp.mem.disp)


def instruction_from_cs_insn(csInsn, executable):
    groups = []

    if executable.architecture in (ARCHITECTURE.ARM, ARCHITECTURE.ARM_64):
        if csInsn.mnemonic.startswith('bl'):
            groups.append(Instruction.GRP_CALL)
        elif csInsn.mnemonic.startswith('b'):
            groups.append(Instruction.GRP_JUMP)
    else:
        if capstone.CS_GRP_JUMP in csInsn.groups:
            groups.append(Instruction.GRP_JUMP)
        if capstone.CS_GRP_CALL in csInsn.groups:
            groups.append(Instruction.GRP_CALL)

    instruction = Instruction(csInsn.address, csInsn.size, csInsn.bytes, csInsn.mnemonic, [], groups, csInsn, executable)

    # We manually pull out the instruction details here so that capstone doesn't deepcopy everything which burns time
    # and memory
    detail = ctypes.cast(csInsn._raw.detail, ctypes.POINTER(capstone._cs_detail)).contents

    if executable.architecture == ARCHITECTURE.X86 or executable.architecture == ARCHITECTURE.X86_64:
        detail = detail.arch.x86
    elif executable.architecture == ARCHITECTURE.ARM:
        detail = detail.arch.arm
    elif executable.architecture == ARCHITECTURE.ARM_64:
        detail = detail.arch.arm64

    operands = [operand_from_cs_op(detail.operands[i], instruction) for i in range(detail.op_count)]

    instruction.operands = operands

    return instruction


class String(object):
    def __init__(self, s, vaddr, executable):
        self.string = s
        self.short_name = reduce(lambda s, r: s.replace(r, ''), ' '+string.punctuation, self.string)[:8]
        self.vaddr = vaddr
        self._executable = executable

    def __repr__(self):
        return '<String \'{}\' at {}>'.format(self.string, hex(self.vaddr))

    def __str__(self):
        return self.string


class CFGEdge(object):
    # Edge with no special information. Could be from a default fall-through, unconditional jump, etc.
    DEFAULT = 0

    # Edge from a conditional jump. Two of these should be added for each cond. jump, one for the True, and one for False
    COND_JUMP = 1

    # Edge from a switch/jump table. One edge should be added for each entry, and the corresponding key set as the value
    SWITCH = 2

    # Edge from a call instruction.
    CALL = 3

    def __init__(self, src, dst, type, value=None):
        self.src = src
        self.dst = dst
        self.type = type
        self.value = value

    def __eq__(self, other):
        if isinstance(other, CFGEdge) and self.src == other.src and self.dst == other.dst and self.type == other.type:
            return True
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        return '<CFGEdge from {} to {}>'.format(hex(self.src), hex(self.dst))
