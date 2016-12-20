import capstone
from capstone import *
from capstone.x86_const import *
import logging
import collections
import struct

from ..constructs import *
from .base_analyzer import BaseAnalyzer

class X86_Analyzer(BaseAnalyzer):
    def __init__(self, executable):
        super(X86_Analyzer, self).__init__(executable)

        self._disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        self._disassembler.detail = True
        self._disassembler.skipdata = True

        self.REG_NAMES = dict([(v,k[8:].lower()) for k,v in capstone.x86_const.__dict__.iteritems() if k.startswith('X86_REG')])
        self.IP_REGS = set([26, 34, 41])
        self.SP_REGS = set([6, 7, 20, 30, 36, 44, 47, 48])
        self.NOP_INSTRUCTION = '\x90'

    def _gen_ins_map(self):
        for section in self.executable.sections_to_disassemble():
            for ins in self._disassembler.disasm(section.raw, section.vaddr):
                if ins.id: # .byte "instructions" have an id of 0
                    self.ins_map[ins.address] = instruction_from_cs_insn(ins, self.executable)

    def disassemble_range(self, start_vaddr, end_vaddr):
        size = end_vaddr - start_vaddr
        self.executable.binary.seek(self.executable.vaddr_binary_offset(start_vaddr))

        instructions = []

        for ins in self._disassembler.disasm(self.executable.binary.read(size), start_vaddr):
            if ins.id:
                instructions.append(instruction_from_cs_insn(ins, self.executable))
            else:
                print ins

        return instructions

    def ins_modifies_esp(self, instruction):
        return 'pop' in instruction.mnemonic or 'push' in instruction.mnemonic \
                or instruction.operands[0] in self.SP_REGS

    def _identify_functions(self):
        """
        This has to take into account 3 possibilities:

        1) No symbols whatsoever. Here we basically end up just doing basic prologue/epilogue analysis and hoping that
        the functions aren't weird and are relatively predictable.

        2) Symbols with no size. We use the symbols we have as known starting points (replacing the prologue) but still
        look for a epilogue (or the start of another function) to signal the end of the function.

        3) Symbols with size.
        """

        STATE_NOT_IN_FUNC, STATE_IN_PROLOGUE, STATE_IN_FUNCTION = 0, 1, 2

        state = STATE_NOT_IN_FUNC

        cur_func = None

        ops = []

        for cur_ins in self.ins_map:
            if cur_ins.address in self.executable.functions:
                state = STATE_IN_FUNCTION
                cur_func = self.executable.functions[cur_ins.address]

                logging.debug('Analyzing function {} with pre-populated size {}'.format(cur_func, cur_func.size))

                if not cur_func.size:
                    # Function from symtab has no size, so start to keep track of it
                    cur_func.size += cur_ins.size

            elif cur_func and cur_func.contains_address(cur_ins.address):
                # Current function under analysis has a pre-populated size so just continue on until we get to the end
                continue

            # Windows sometimes puts `mov edi, edi` as the first instruction in a function for hot patching, so we check
            # for this case to make sure the function we detect starts at the correct address.
            #  https://blogs.msdn.microsoft.com/oldnewthing/20110921-00/?p=9583
            elif state == STATE_NOT_IN_FUNC and cur_ins.mnemonic == 'mov' and \
                    cur_ins.operands[0].type == Operand.REG and \
                    cur_ins.operands[0].reg == X86_REG_EDI and \
                    cur_ins.operands[1].type == Operand.REG and \
                    cur_ins.operands[1].reg == X86_REG_EDI:

                state = STATE_IN_PROLOGUE
                ops.append(cur_ins)

            elif state in (STATE_NOT_IN_FUNC, STATE_IN_PROLOGUE) and cur_ins.mnemonic == 'push' and \
                    cur_ins.operands[0].type == Operand.REG and \
                    cur_ins.operands[0].reg in (X86_REG_EBP, X86_REG_RBP):

                state = STATE_IN_PROLOGUE
                ops.append(cur_ins)

            elif state == STATE_IN_PROLOGUE and \
                            cur_ins.mnemonic == 'mov' and \
                            cur_ins.operands[0].type == Operand.REG and \
                            cur_ins.operands[0].reg in (X86_REG_EBP, X86_REG_RBP) and \
                            cur_ins.operands[1].type == Operand.REG and \
                            cur_ins.operands[1].reg in self.SP_REGS:


                state = STATE_IN_FUNCTION
                ops.append(cur_ins)

                logging.debug('Identified function by prologue at {} with prologue ops {}'.format(hex(cur_ins.address), ops))
                cur_func = Function(ops[0].address,
                                    sum(i.size for i in ops),
                                    'sub_'+hex(ops[0].address)[2:],
                                    self.executable)
                ops = []

            elif state == STATE_IN_FUNCTION and 'ret' in cur_ins.mnemonic:
                state = STATE_NOT_IN_FUNC
                cur_func.size += cur_ins.size

                logging.debug('Identified function epilogue at {}'.format(hex(cur_ins.address)))

                self.executable.functions[cur_func.address] = cur_func

                cur_func = None

            elif state == STATE_IN_FUNCTION:
                cur_func.size += cur_ins.size


    def cfg(self):
        edges = set()

        for f in self.executable.iter_functions():
            if f.type == Function.NORMAL_FUNC:
                for ins in f.instructions:
                    #TODO: understand non-immediates here
                    if ins.is_call() and ins.operands[-1].type == Operand.IMM:
                        call_addr = ins.operands[-1].imm
                        if self.executable.vaddr_is_executable(call_addr):
                            edge = CFGEdge(ins.address, call_addr, CFGEdge.CALL)
                            edges.add(edge)

                for cur_bb in f.bbs:
                    last_ins = cur_bb.instructions[-1]

                    if last_ins.is_jump():
                        if last_ins.operands[-1].type == Operand.IMM:
                            jmp_addr = last_ins.operands[-1].imm

                            if self.executable.vaddr_is_executable(jmp_addr):
                                if last_ins.mnemonic == 'jmp':
                                    edge = CFGEdge(last_ins.address, jmp_addr, CFGEdge.DEFAULT)
                                    edges.add(edge)
                                else:  # Conditional jump
                                    # True case
                                    edge = CFGEdge(last_ins.address, jmp_addr, CFGEdge.COND_JUMP, True)
                                    edges.add(edge)

                                    # Default/fall-through case
                                    next_addr = last_ins.address + last_ins.size
                                    edge = CFGEdge(last_ins.address, next_addr, CFGEdge.COND_JUMP, False)
                                    edges.add(edge)
                    elif last_ins != f.instructions[-1]:
                        # Otherwise, if we're just at the end of a BB that's not the end of the function, just fall
                        # through to the next of the instruction
                        edge = CFGEdge(last_ins.address, last_ins.address + last_ins.size, CFGEdge.DEFAULT)
                        edges.add(edge)

            edges.update(self._do_jump_table_detection(f))

        return edges

    def _do_jump_table_detection(self, f):
        # Basic idea is to label each BB as one of these types based on its contents
        class BB_TYPE:
            NONE  = 0  # Seemingly not associated with a switch
            VALUE = 1  # A simple value compare (cmp and jmp)
            RANGE = 2  # A range compare (cmp and jl/jle/jg/jge)
            TABLE = 3  # A jump to a jump table (anything with [_+_*(4,8)]


        # BB address -> (type, important instruction)
        bb_types = {}

        for bb in f.iter_bbs():
            bb_type = (BB_TYPE.NONE, None)

            # Table detection
            # NOTE: We *should* do full register tracing if this instruction is a mov/lea,
            #  but we can relatively safely assume that the jump at the end of the BB
            #  will be a `jmp {reg}` if this is indeed a jump table
            # NOTE: Value tables will be marked as a TABLE, but sanity checking later on
            #  prevents values from being interpreted as jump destinations
            for i, ins in enumerate(bb.instructions):
                if any(o.type == Operand.MEM and o.scale in [4,8] for o in ins.operands):
                    bb_type = (BB_TYPE.TABLE, ins)
                    break

            # Range detection
            cmp_ins = None
            for i, ins in enumerate(bb.instructions):
                if ins.mnemonic == 'cmp': # Anything else? Is sub used in ranges in clang?
                    cmp_ins = ins

                # TODO: replace `in ...` with `not in`
                elif cmp_ins and ins.is_jump() and ins.mnemonic in ('jb','jnae','jnb','jae','jbe',
                                                                    'jna','ja','jnbe','jl','jnge',
                                                                    'jge','jnl','jle','jng','jg','jnle'):
                    bb_type = (BB_TYPE.RANGE, cmp_ins)

            # Value detection
            cmp_ins = None
            for i, ins in enumerate(bb.instructions):
                if ins.mnemonic in ('cmp', 'test', 'sub'): # TODO: Properly check for clang's use of `sub`
                    cmp_ins = ins

                elif cmp_ins and ins.mnemonic in ('je', 'jne'):
                    bb_type = (BB_TYPE.VALUE, cmp_ins)

            logging.debug("Marking BB at {} as type {}".format(hex(bb.address), bb_type))
            bb_types[bb.address] = bb_type


        # Start address of table -> (type, scale, {relative location})
        table_types = {}

        class TABLE_TYPE:
            ADDR_REL = 0  # Values in the table are relative to a constant loaded elsewhere
            ABS = 1       # Values in the table are absolute

        ins_to_table = []

        # TODO: Look for _CSWTCH symbols

        for bb in f.iter_bbs():
            if bb_types[bb.address][0] == BB_TYPE.TABLE:
                for ins in bb.instructions:
                    # Special-case the various ways of doing a jump table

                    # Option 1 (seemingly most common): lea {reg}, {ip-rel const}
                    # NOTE: This could either be a jump table or a value table
                    if ins.mnemonic == 'lea' and ins.operands[1].type == Operand.MEM:
                        insn_with_mem_op = bb_types[bb.address][1]
                        if len(insn_with_mem_op.operands) > 1 and insn_with_mem_op.operands[1].type == Operand.MEM:
                            table_scale = insn_with_mem_op.operands[1].scale

                            table_addr = ins.address + ins.size + ins.operands[1].disp

                            logging.debug("Marking table at {} as an ADDR_REL table".format(hex(table_addr)))
                            table_types[table_addr] = (TABLE_TYPE.ADDR_REL, table_scale, ins.address + ins.size)
                            ins_to_table.append((ins.address, table_addr))
                            break

                    # Option 2: offset is directly in the jumps mem. operand
                    elif bb_types[bb.address][1].operands[-1].type == Operand.MEM:
                        mem_offset = bb_types[bb.address][1].operands[-1].disp
                        if mem_offset:
                            logging.debug("Marking table at {} as an ABS table".format(hex(mem_offset)))
                            table_types[mem_offset] = (TABLE_TYPE.ABS, bb_types[bb.address][1].operands[-1].scale)
                            ins_to_table.append((ins.address, mem_offset))
                            break

                    logging.debug("Couldn't find anything with a table offset in BB at {}".format(hex(bb.address)))


        # Add the end of the segment as an upper bound

        table_types[self.executable.executable_segment_vaddr() + self.executable.executable_segment_size()] = None

        # http://stackoverflow.com/questions/32030412/twos-complement-sign-extension-python
        def sign_extend(value, bits):
            sign_bit = 1 << (bits - 1)
            return (value & (sign_bit - 1)) - (value & sign_bit)

        # Start address of table -> [destination addresses]
        table_values = collections.defaultdict(list)

        table_addrs = sorted(table_types.keys())

        for start_a, end_a in zip(table_addrs[:-1], table_addrs[1:]):
            if not table_types[start_a]:
                continue
            t_type = table_types[start_a][0]
            scale = table_types[start_a][1]
            for addr in range(start_a, end_a, scale):
                # sometimes, our addr+scale ends up not being in the executable,
                # usually because they compute a relative offset and then add a
                # base address to it. For now, we'll just skip the address.
                # TODO: Is there a way to do this without basically implementing
                #       symbolic execution?
                try:
                    raw = self.executable.get_binary_vaddr_range(addr, addr+scale)
                    data_val = struct.unpack(self.executable.pack_endianness+('i' if scale == 4 else 'q'), raw)[0]
                except KeyError:
                    logging.warning("Invalid vaddrs requested during jump table analysis, skipping this vaddr: {:08x}".format(addr))
                    continue
                if t_type == TABLE_TYPE.ADDR_REL:
                    addr_bit_len = 8*self.executable.address_length()
                    abs_val = (start_a+sign_extend(data_val, addr_bit_len)) & (2**(addr_bit_len+1) - 1)
                else:
                    abs_val = data_val

                # Only add the values if they land us in the executable segment
                # TODO: Be smarter here. Add restrictions to make sure that the table doesn't extend
                #  past the end of a section/segment before making sure the address is valid
                valid_start = self.executable.executable_segment_vaddr()
                valid_end = valid_start + self.executable.executable_segment_size()

                if valid_start <= abs_val < valid_end:
                    table_values[start_a].append(abs_val)
                else:
                    break

        edges = set()
        for addr, table in ins_to_table:
            for dst in table_values[table]:
                edges.add(CFGEdge(addr, dst, CFGEdge.SWITCH))

        return edges

class X86_64_Analyzer(X86_Analyzer):
    def __init__(self, executable):
        super(X86_64_Analyzer, self).__init__(executable)

        self._disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
        self._disassembler.detail = True
        self._disassembler.skipdata = True
