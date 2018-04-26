import os
import logging

try:
    from keystone import *
except:
    logging.warning('Keystone assembler not found so assembling will not work')

from StringIO import StringIO

from ..analysis.x86_analyzer import *
from ..analysis.arm_analyzer import *

from ..enums import *

class BaseExecutable(object):
    '''
    The executable classes expose the raw binary in higher-level chunks.
    They automatically lift the .text segment (or equiv.) for quick use, keep a map of offset->vaddrs for lookups in
    the rewriting process, and more. You can think of them as the middle-man that sits between the disassembly and the
    underlying binary.
    '''
    def __init__(self, file_path):
        if not os.path.exists(file_path):
            raise Exception('No such file')

        self.fp = file_path
        self.binary = StringIO(open(self.fp).read())

        self.architecture = None
        self.pack_endianness = None

        self.helper = None

        self.analyzer = None
        self.libraries = []
        self.functions = {} # Vaddr: Function
        self.strings = {}
        self.xrefs = {}

        self.next_injection_vaddr = None

    def __repr__(self):
        return '<{} {} \'{}\'>'.format(self.architecture, self.__class__.__name__, self.fp)
    
    def _identify_arch(self):
        '''
        Identifies the architecture that the executable is compiled for.
        :return: None
        '''
        raise NotImplementedError()
    
    def is_64_bit(self):
        '''
        Determines if the executable is 64 bit or 32 bit.
        :return: True if the executable is 64 bit, otherwise false.
        '''
        return self.architecture in (ARCHITECTURE.X86_64, ARCHITECTURE.ARM_64)

    def address_length(self):
        '''
        :return: Number of bytes an address in this executable will have (i.e. 4 for 32 bit, 8 for 64 bit)
        '''
        return 8 if self.is_64_bit() else 4

    def entry_point(self):
        '''
        Gets the entry point of the executable.
        :return: The entry point of the executable.
        '''
        raise NotImplementedError()

    def sections_to_disassemble(self):
        '''
        Iterates through each section in the executable that is supposed to be disassembled.
        :return: Iterator
        '''
        for s in self.sections:
            if s.executable:
                yield s

    def iter_string_sections(self):
        '''
        Returns the section(s) with strings in this executable
        :return: Section(s) with strings.
        '''
        raise NotImplementedError()

    def vaddr_is_executable(self, vaddr):
        '''
        Determine if the given virtual address is in a mapped executable memory segment.
        :param vaddr: Virtual address to check
        :return: True if the vaddr is in an executable segment, False otherwise
        '''
        for section in self.sections:
            if section.executable and section.contains_vaddr(vaddr):
                return True

        return False

    def section_containing_vaddr(self, vaddr):
        for section in self.sections:
            if section.contains_vaddr(vaddr):
                return section

        return None

    def function_containing_vaddr(self, vaddr):
        for f in self.iter_functions():
            if f.contains_address(vaddr):
                return f

        return None

    def bb_containing_vaddr(self, vaddr):
        for f in self.iter_functions():
            for bb in f.bbs:
                if bb.address <= vaddr < bb.address + bb.size:
                    return bb

        return None

    def vaddr_binary_offset(self, vaddr):
        '''
        Gets the offset in the binary file for a given virtual address.
        :param vaddr: The virtual address to get the offset for.
        :return: The offset in the binary of the virtual address.
        '''
        for section in self.sections:
            if section.contains_vaddr(vaddr):
                return section.offset + vaddr - section.vaddr

        return None

    def _extract_symbol_table(self):
        '''
        Extracts the symbol table from the binary and creates named functions as appropriate.
        Called from the analyzer in the main analysis function.
        :return: None
        '''
        raise NotImplementedError()

    def get_binary(self):
        '''
        Gets the entire binary.
        :return: The raw bytes of the entire binary.
        '''
        return self.binary.getvalue()

    def get_binary_vaddr_range(self, start, end):
        '''
        Gets the raw bytes from the binary within a virtual address range
        :param start: Starting virtual address
        :param end: Ending virtual address
        :raises: KeyError if either the start or end virtual addresses do not actually exist in the binary
        :return: The bytes in the binary between the two virtual addresses
        '''
        start_offset = self.vaddr_binary_offset(start)
        end_offset = self.vaddr_binary_offset(end)
        # if either of these returns None we don't want to slice up -- raise an error
        if start_offset and end_offset:
            return self.get_binary()[start_offset:end_offset]

        bad_addr = start if not start_offset else end # which address triggered our error
        raise KeyError("Vaddr is not in binary: {:x}".format(bad_addr))
    
    def analyze(self):
        '''
        Creates an analyzer for the binary and then runs the initial analysis routine.
        :return: The created analyzer object.
        '''
        if self.architecture == ARCHITECTURE.X86:
            self.analyzer = X86_Analyzer(self)
        elif self.architecture == ARCHITECTURE.X86_64:
            self.analyzer = X86_64_Analyzer(self)
        elif self.architecture == ARCHITECTURE.ARM:
            self.analyzer = ARM_Analyzer(self)
        elif self.architecture == ARCHITECTURE.ARM_64:
            self.analyzer = ARM_64_Analyzer(self)

        if self.analyzer:
            self.analyzer.analyze()
        else:
            logging.error('Could not create analyzer for {}'.format(self))

        return self.analyzer

    def _ks_symbol_resolver(self, symbol, value):
        f = self.function_named(symbol)

        if f:
            value = f.address
            return True

        return False

    def assemble(self, s, vaddr=0):
        '''
        Assemble the given string relative to the given virtual address
        :param s: String of assembly commands to be assembled
        :param vaddr: Virtual address the code is assembled relative to
        :return: A bytearray with the resulting machine code
        '''
        if self.architecture == ARCHITECTURE.X86:
            ks = Ks(KS_ARCH_X86, KS_MODE_32)
        elif self.architecture == ARCHITECTURE.X86_64:
            ks = Ks(KS_ARCH_X86, KS_MODE_64)
        elif self.architecture == ARCHITECTURE.ARM:
            ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
        elif self.architecture == ARCHITECTURE.ARM_64:
            ks = Ks(KS_ARCH_ARM64, KS_MODE_ARM)
        else:
            logging.error('Could not create assembler for {}'.format(self))
            raise Exception('Architecture not supported')

        ks.sym_resolver =  self._ks_symbol_resolver

        encoding, count = ks.asm(s, vaddr)

        return bytearray(encoding)

    def prepare_for_injection(self):
        '''
        Prepares the binary for code injection, creating sections/segments where needed.
        This should *always* be called before inject() is called, as it provides the initial values for
        next_injection_vaddr which may be required to do certain IP-relative computations.
        :return: None
        '''
        raise NotImplementedError()

    def inject(self, asm, update_entry=False):
        '''
        Injects the given assembly into the binary, optionally updating the entry point if the injected code is to run
        before initialization.
        :param asm: The assembly to inject.
        :param update_entry: Whether or not to update the binary entry point to point to the injected code.
        :return: (offset of injected assembly in binary, virtual address of injected assembly)
        '''
        raise NotImplementedError()

    def hook(self, vaddr, asm):
        '''
        Patches the given binary to call `asm` at `vaddr`.
        :param vaddr: The virtual address of the instruction to hook/patch
        :param asm: The assembly (either string of assembly, bytearray of assembled opcodes, or list of Instructions) to
        be written
        :return: The virtual address of the created hook
        '''

        # TODO: Move below to its own function and use in replace_instruction and inject
        if type(asm) not in [str, list, bytearray]:
            raise ValueError('asm is not a valid type. Must be str, list, or bytearray')

        if self.next_injection_vaddr is None:
            self.prepare_for_injection()

        # We first replace the original instruction with a call to a new code chunk
        jmp = self.assemble('call '+hex(self.next_injection_vaddr), vaddr) #TODO: Architecture independent
        overwritten_instructions = self.replace_at(vaddr, jmp)

        if type(asm) == str:
            # Assemble with keystone
            pulled_list = [x.mnemonic + ' ' + x.op_str() for x in overwritten_instructions] 
            asm = ' ; '.join(pulled_list) + ' ; ' + asm
            asm = self.assemble(asm, self.next_injection_vaddr)
            new_chunk = asm
        elif type(asm) == list:
            # TODO: reassemble to fix offsets in overwritten instructions
            # Assemble each Instruction object
            asm = sum((ins.raw for ins in asm), bytearray())
            new_chunk = sum((ins.raw for ins in overwritten_instructions), bytearray()) + asm

        # Then we inject that new code chunk. This is composed of the instructions we wrote over to create the jump
        # as well as the assembly we actually want to call
        hook_addr = self.inject(new_chunk)
        logging.debug('Replaced instruction at {} with jump to {}'.format(vaddr, hook_addr))

        return hook_addr


    def iter_functions(self):
        '''
        Iterates over the functions in this executable
        :return: Iterator
        '''
        return iter(self.functions.values())

    def function_named(self, name):
        '''
        Finds a function with a given name if it exists.
        :param name: The name of the function to search for.
        :return: The function if it is found, else None.
        '''
        for func in self.iter_functions():
            if func.name == name or func.name == 'sub_'+name or func.name == name+'@PLT':
                return func

        return None

    def replace_at(self, vaddr, new_asm):
        '''
        Replaces an instruction with the given assembly.
        :param vaddr: The address of the existing instruction(s) to overwrite.
        :param new_asm: The new assembly that will be written over the old instruction.
        :return: The original instruction(s) that was/were overwritten
        '''

        if not vaddr in self.analyzer.ins_map:
            raise Exception('Starting virtual address to replace must be an existing instruction')

        # Find all instructions we will be overwriting, and warn if they are referenced elsewhere.

        # If an instruction is being referenced elsewhere (most likely in a jump), it's possible that the jump
        # (or whatever it is) will end up going to the middle of our replaced asm which can obviously make the program
        # behave unexpectedly.
        overwritten_insns = self.analyzer.ins_map[vaddr:vaddr + max(len(new_asm), 1)]
        for ins in overwritten_insns:
            if ins.address in self.xrefs:
                logging.warning('{} will be overwritten but there are xrefs to it: {}'.format(ins,
                                                                                              self.xrefs[ins.address]))

        # Write the new bytes
        offset = self.vaddr_binary_offset(vaddr)
        self.binary.seek(offset)
        logging.debug('Replacing instruction(s) at offset {}'.format(offset))
        self.binary.write(new_asm)

        # Find how much is left over in the original instruction(s) and NOP them out
        overwritten_size = sum(i.size for i in overwritten_insns)
        padding = self.analyzer.NOP_INSTRUCTION * ((overwritten_size - len(new_asm)) / len(self.analyzer.NOP_INSTRUCTION))
        self.binary.write(padding)

        # Disassemble the new instructions
        new_instructions = self.analyzer.disassemble_range(vaddr, vaddr + len(new_asm))

        func = self.function_containing_vaddr(vaddr)

        insert_point = func.instructions.index(overwritten_insns[0])

        # Remove the old instructions from the function
        for ins in overwritten_insns:
            func.instructions.remove(ins)

        # Insert the new instructions where we just removed the old ones
        func.instructions = func.instructions[:insert_point] + new_instructions + func.instructions[insert_point:]

        # Re-analyze the function for BBs
        func.do_bb_analysis()

        # Finally clear the instructions out from the global instruction map
        for ins in overwritten_insns:
            del self.analyzer.ins_map[ins.address]

        for ins in new_instructions:
            self.analyzer.ins_map[ins.address] = ins

        return overwritten_insns

    def save(self, file_name):
        with open(file_name, 'wb') as f:
            f.write(self.get_binary())
