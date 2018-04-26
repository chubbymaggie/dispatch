import pefile
from .SectionDoubleP import SectionDoubleP

from .base_executable import *
from .section import *

SECTION_SIZE = 0x1000

class PEExecutable(BaseExecutable):
    def __init__(self, file_path):
        super(PEExecutable, self).__init__(file_path)

        self.helper = pefile.PE(self.fp)

        self.architecture = self._identify_arch()

        if self.architecture is None:
            raise Exception('Architecture is not recognized')

        logging.debug('Initialized {} {} with file \'{}\''.format(self.architecture, type(self).__name__, file_path))

        self.pack_endianness = '<'

        self.sections = [section_from_pe_section(s, self.helper) for s in self.helper.sections]

        if hasattr(self.helper, 'DIRECTORY_ENTRY_IMPORT'):
            self.libraries = [dll.dll for dll in self.helper.DIRECTORY_ENTRY_IMPORT]
        else:
            self.libraries = []
    
    def _identify_arch(self):
        machine = pefile.MACHINE_TYPE[self.helper.FILE_HEADER.Machine]
        if machine == 'IMAGE_FILE_MACHINE_I386':
            return ARCHITECTURE.X86
        elif machine == 'IMAGE_FILE_MACHINE_AMD64':
            return ARCHITECTURE.X86_64
        elif machine == 'IMAGE_FILE_MACHINE_ARM':
            return ARCHITECTURE.ARM
        else:
            return None

    def entry_point(self):
        return self.helper.OPTIONAL_HEADER.AddressOfEntryPoint

    def get_binary(self):
        return self.helper.write()

    def iter_string_sections(self):
        STRING_SECTIONS = ['.rdata']
        for s in self.sections:
            if s.name in STRING_SECTIONS:
                yield s

    def _extract_symbol_table(self):
        # Load in stuff from the IAT if it exists
        if hasattr(self.helper, 'DIRECTORY_ENTRY_IMPORT'):
            for dll in self.helper.DIRECTORY_ENTRY_IMPORT:
                for imp in dll.imports:
                    if imp.name:
                        name = imp.name + '@' + dll.dll
                    else:
                        name = 'ordinal_' + str(imp.ordinal) + '@' + dll.dll

                    self.functions[imp.address] = Function(imp.address,
                                                           self.address_length(),
                                                           name,
                                                           self)

        # Load in information from the EAT if it exists
        if hasattr(self.helper, 'DIRECTORY_ENTRY_EXPORT'):
            for symbol in self.helper.DIRECTORY_ENTRY_EXPORT.symbols:
                if symbol.address not in self.functions:
                    self.functions[symbol.address] = Function(symbol.address,
                                                              0,
                                                              symbol.name,
                                                              self)
                else:
                    self.functions[symbol.address].name = symbol.name

    def prepare_for_injection(self):
        sdp = SectionDoubleP(self.helper)
        to_inject = '\x00' * SECTION_SIZE
        self.helper = sdp.push_back(Name='.inject', Characteristics=0x60000020, Data=to_inject)
        self.next_injection_vaddr = self.helper.sections[-1].VirtualAddress + self.helper.OPTIONAL_HEADER.ImageBase

    def inject(self, asm, update_entry=False):
        has_injection_section = [s for s in self.helper.sections if s.Name.startswith('.inject')]

        if not has_injection_section:
            logging.warning(
                'prepare_for_injection() was not called before inject(). This may cause unexpected behavior')
            self.prepare_for_injection()

        inject_rva = self.next_injection_vaddr - self.helper.OPTIONAL_HEADER.ImageBase
        self.helper.set_bytes_at_rva(inject_rva, asm)

        if update_entry:
            self.helper.OPTIONAL_HEADER.AddressOfEntryPoint = inject_rva

        self.next_injection_vaddr += len(asm)

        return inject_rva + self.helper.OPTIONAL_HEADER.ImageBase

    def replace_at(self, vaddr, new_asm):
        # Identical to the implementation in base_executable except for the commented section

        if not vaddr in self.analyzer.ins_map:
            raise Exception('Starting virtual address to replace must be an existing instruction')

        overwritten_insns = self.analyzer.ins_map[vaddr:vaddr + max(len(new_asm), 1)]
        for ins in overwritten_insns:
            if ins.address in self.xrefs:
                logging.warning('{} will be overwritten but there are xrefs to it: {}'.format(ins,
                                                                                              self.xrefs[ins.address]))

        logging.debug('Replacing instruction(s) at vaddr {}'.format(vaddr))

        # Since we're using pefile to keep track of the (changed) binary, use pefile's methods to write the new asm
        self.helper.set_bytes_at_rva(vaddr - self.helper.OPTIONAL_HEADER.ImageBase, new_asm)

        overwritten_size = sum(i.size for i in overwritten_insns)
        padding = self.analyzer.NOP_INSTRUCTION * ((overwritten_size - len(new_asm)) / len(self.analyzer.NOP_INSTRUCTION))
        self.helper.set_bytes_at_rva(vaddr - self.helper.OPTIONAL_HEADER.ImageBase + len(new_asm), padding)

        new_instructions = self.analyzer.disassemble_range(vaddr, vaddr + len(new_asm))

        func = self.function_containing_vaddr(vaddr)

        insert_point = func.instructions.index(overwritten_insns[0])

        for ins in overwritten_insns:
            func.instructions.remove(ins)

        func.instructions = func.instructions[:insert_point] + new_instructions + func.instructions[insert_point:]

        func.do_bb_analysis()

        for ins in overwritten_insns:
            del self.analyzer.ins_map[ins.address]

        for ins in new_instructions:
            self.analyzer.ins_map[ins.address] = ins

        return overwritten_insns