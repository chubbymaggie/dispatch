from elftools.elf.elffile import ELFFile
from elftools.elf.enums import *
from elftools.elf.constants import *
from elftools.elf.sections import SymbolTableSection
import logging

from .base_executable import *
from .section import *

INJECTION_SIZE = 0x1000

class ELFExecutable(BaseExecutable):
    def __init__(self, file_path):
        super(ELFExecutable, self).__init__(file_path)

        self.helper = ELFFile(self.binary)

        self.architecture = self._identify_arch()

        if self.architecture is None:
            raise Exception('Architecture is not recognized')

        logging.debug('Initialized {} {} with file \'{}\''.format(self.architecture, type(self).__name__, file_path))

        self.pack_endianness = '<' if self.helper.little_endian else '>'
        self.address_pack_type = 'I' if self.helper.elfclass == 32 else 'Q'

        self.sections = [section_from_elf_section(s) for s in self.helper.iter_sections()]

        self.executable_segment = [s for s in self.helper.iter_segments() if s['p_type'] == 'PT_LOAD' and s['p_flags'] & 0x1][0]

        dyn = self.helper.get_section_by_name('.dynamic')
        if dyn:
            self.libraries = [t.needed for t in dyn.iter_tags() if t['d_tag'] == 'DT_NEEDED']

        self.next_injection_offset = None

    def _identify_arch(self):
        machine = self.helper.get_machine_arch()
        if machine == 'x86':
            return ARCHITECTURE.X86
        elif machine == 'x64':
            return ARCHITECTURE.X86_64
        elif machine == 'ARM':
            return ARCHITECTURE.ARM
        elif machine == 'AArch64':
            return ARCHITECTURE.ARM_64
        else:
            return None

    def entry_point(self):
        return self.helper['e_entry']

    def executable_segment_vaddr(self):
        return self.executable_segment['p_vaddr']

    def executable_segment_size(self):
        # TODO: Maybe limit this because we use this as part of our injection method?
        return self.executable_segment['p_memsz']

    def iter_string_sections(self):
        STRING_SECTIONS = ['.rodata', '.data', '.bss']
        for s in self.sections:
            if s.name in STRING_SECTIONS:
                yield s

    def _extract_symbol_table(self):
        # Add in symbols from the PLT/rela.plt
        # .rela.plt contains indexes to reference both .dynsym (symbol names) and .plt (jumps to GOT)

        if self.is_64_bit():
            reloc_section = self.helper.get_section_by_name('.rela.plt')
        else:
            reloc_section = self.helper.get_section_by_name('.rel.plt')

        if reloc_section:
            dynsym = self.helper.get_section(reloc_section['sh_link']) # .dynsym
            if isinstance(dynsym, SymbolTableSection):
                plt = self.helper.get_section_by_name('.plt')
                for idx, reloc in enumerate(reloc_section.iter_relocations()):
                    # Get the symbol's name from dynsym
                    symbol_name = dynsym.get_symbol(reloc['r_info_sym']).name

                    # The address of this function in the PLT is the base PLT offset + the index of the relocation.
                    # However, since there is the extra "trampoline" entity at the top of the PLT, we need to add one to the
                    # index to account for it.

                    # While sh_entsize is sometimes defined, it appears to be incorrect in some cases so we just ignore that
                    # and calculate it based off of the total size / num_relocations (plus the trampoline entity)
                    entsize = (plt['sh_size'] / (reloc_section.num_relocations() + 1))

                    plt_addr = plt['sh_addr'] + ((idx+1) * entsize)

                    logging.debug('Directly adding PLT function {} at vaddr {}'.format(symbol_name, hex(plt_addr)))

                    f = Function(plt_addr,
                                 entsize,
                                 symbol_name + '@PLT',
                                 self,
                                 type=Function.DYNAMIC_FUNC)
                    self.functions[plt_addr] = f
            else:
                logging.debug('.rel(a).plt section had sh_link to {}. Not parsing symbols...'.format(dynsym))

        if self.helper.get_section_by_name('.dynsym'):
            for symbol in self.helper.get_section_by_name('.dynsym').iter_symbols():
                if symbol.entry['st_info']['type'] == 'STT_FUNC' and symbol.entry['st_size'] > 0:
                    vaddr = symbol.entry['st_value']
                    if vaddr not in self.functions:
                        logging.debug('Adding function from .dynsym directly at vaddr {}'.format(vaddr))
                        f = Function(vaddr,
                                     symbol.entry['st_size'],
                                     symbol.name,
                                     self,
                                     type=Function.DYNAMIC_FUNC)
                        self.functions[vaddr] = f


        # Some things in the symtab have st_size = 0 which confuses analysis later on. To solve this, we keep track of
        # where each address is in the `function_vaddrs` set and go back after all symbols have been iterated to compute
        # size by taking the difference between the current address and the next recorded address.

        # We do this for each executable section so that the produced functions cannot span multiple sections.

        for section in self.helper.iter_sections():
            if self.executable_segment.section_in_segment(section):
                name_for_addr = {}

                function_vaddrs = set([section['sh_addr'] + section['sh_size']])

                symbol_table = self.helper.get_section_by_name('.symtab')
                if symbol_table:
                    for symbol in symbol_table.iter_symbols():
                        if symbol['st_info']['type'] == 'STT_FUNC' and symbol['st_shndx'] != 'SHN_UNDEF':
                            if section['sh_addr'] <= symbol['st_value'] < section['sh_addr'] + section['sh_size']:
                                name_for_addr[symbol['st_value']] = symbol.name
                                function_vaddrs.add(symbol['st_value'])

                                if symbol['st_size']:
                                    logging.debug('Eagerly adding function {} from .symtab at vaddr {} with size {}'
                                                  .format(symbol.name, hex(symbol['st_value']), hex(symbol['st_size'])))
                                    f = Function(symbol['st_value'],
                                                 symbol['st_size'],
                                                 symbol.name,
                                                 self)
                                    self.functions[symbol['st_value']] = f


                function_vaddrs = sorted(list(function_vaddrs))

                for cur_addr, next_addr in zip(function_vaddrs[:-1], function_vaddrs[1:]):
                    # If st_size was set, we already added the function above, so don't add it again.
                    if cur_addr not in self.functions:
                        func_name = name_for_addr[cur_addr]
                        size = next_addr - cur_addr
                        logging.debug('Lazily adding function {} from .symtab at vaddr {} with size {}'
                                      .format(func_name, hex(cur_addr), hex(size)))
                        f = Function(cur_addr,
                                     next_addr - cur_addr,
                                     name_for_addr[cur_addr],
                                     self,
                                     type=Function.DYNAMIC_FUNC)
                        self.functions[cur_addr] = f

        # TODO: Automatically find and label main from call to libc_start_main

    def prepare_for_injection(self):
        """
        Derived from http://vxheavens.com/lib/vsc01.html
        """
        modified = StringIO(self.binary.getvalue())

        # Add INJECTION_SIZE to the section header list offset to make room for our injected code
        elf_hdr = self.helper.header.copy()
        elf_hdr.e_shoff += INJECTION_SIZE
        logging.debug('Changing e_shoff to {}'.format(elf_hdr.e_shoff))

        modified.seek(0)
        modified.write(self.helper.structs.Elf_Ehdr.build(elf_hdr))

        # Find the main RX LOAD segment and also adjust other segment offsets along the way
        executable_segment = None

        for segment_idx, segment in enumerate(self.helper.iter_segments()):
            segment_hdr = segment.header.copy()
            segment_hdr_offset = self.helper._segment_offset(segment_idx)

            if executable_segment is not None:
                # Already past the executable segment, so just update the offset if needed (i.e. don't update things
                # that come before the expanded section)
                if segment_hdr.p_offset > last_exec_section['sh_offset']:
                    segment_hdr.p_offset += INJECTION_SIZE

            elif segment['p_type'] == 'PT_LOAD' and segment['p_flags'] & P_FLAGS.PF_X:
                # Found the executable LOAD segment.
                # Make room for our injected code.

                logging.debug('Found executable LOAD segment at index {}'.format(segment_idx))
                executable_segment = segment

                last_exec_section_idx = max([idx for idx in range(self.helper.num_sections()) if
                                             executable_segment.section_in_segment(self.helper.get_section(idx))])
                last_exec_section = self.helper.get_section(last_exec_section_idx)

                segment_hdr.p_filesz += INJECTION_SIZE
                segment_hdr.p_memsz += INJECTION_SIZE

                logging.debug('Rewriting segment filesize and memsize to {} and {}'.format(
                    segment_hdr.p_filesz, segment_hdr.p_memsz)
                )

            modified.seek(segment_hdr_offset)
            modified.write(self.helper.structs.Elf_Phdr.build(segment_hdr))

        if executable_segment is None:
            logging.error("Could not locate an executable LOAD segment. Cannot continue injection.")
            return False

        logging.debug('Last section in executable LOAD segment is at index {} ({})'.format(last_exec_section_idx,
                                                                                           last_exec_section.name))

        self.next_injection_offset = last_exec_section['sh_offset'] + last_exec_section['sh_size']
        self.next_injection_vaddr = last_exec_section['sh_addr'] + last_exec_section['sh_size']

        # Update sh_size for the section we grew
        section_header_offset = self.helper._section_offset(last_exec_section_idx)
        section_header = last_exec_section.header.copy()

        section_header.sh_size += INJECTION_SIZE

        modified.seek(section_header_offset)
        modified.write(self.helper.structs.Elf_Shdr.build(section_header))

        # Update sh_offset for each section past the last section in the executable segment
        for section_idx in range(last_exec_section_idx + 1, self.helper.num_sections()):
            section_header_offset = self.helper._section_offset(section_idx)
            section_header = self.helper.get_section(section_idx).header.copy()

            section_header.sh_offset += INJECTION_SIZE
            logging.debug('Rewriting section {}\'s offset to {}'.format(section_idx, section_header.sh_offset))

            modified.seek(section_header_offset)
            modified.write(self.helper.structs.Elf_Shdr.build(section_header))

        # TODO: Architecture-specific padding
        # Should be something that won't immediately crash, but can be caught (e.g. SIGTRAP on x86)
        modified = StringIO(modified.getvalue()[:self.next_injection_offset] +
                            '\xCC'*INJECTION_SIZE +
                            modified.getvalue()[self.next_injection_offset:])

        self.binary = modified
        self.helper = ELFFile(self.binary)

        return True

    def inject(self, asm, update_entry=False):
        if self.next_injection_offset is None or self.next_injection_vaddr is None:
            logging.warning(
                'prepare_for_injection() was not called before inject(). Calling now, but this may cause unexpected behavior')
            self.prepare_for_injection()

        for segment in self.helper.iter_segments():
            if segment['p_type'] == 'PT_LOAD' and segment['p_flags'] & P_FLAGS.PF_X:
                injection_section_idx = max(i for i in range(self.helper.num_sections()) if segment.section_in_segment(self.helper.get_section(i)))
                break

        injection_section = self.helper.get_section(injection_section_idx)

        # If we haven't injected code before or need to expand the section again for this injection, go ahead and
        # shift stuff around.
        if injection_section['sh_size'] < INJECTION_SIZE or \
                        injection_section['sh_offset'] + injection_section['sh_size'] < self.next_injection_offset + len(asm):
            logging.debug('Automatically expanding injection section to accommodate for assembly')

            # NOTE: Could this change the destination address for the code that gets injected?
            self.prepare_for_injection()
        elif self.next_injection_offset == 0:
            used_code_len = len(injection_section.data().rstrip('\xCC'))
            self.next_injection_offset = injection_section['sh_offset'] + used_code_len
            self.next_injection_vaddr = injection_section['sh_addr'] + used_code_len

        # "Inject" the assembly
        logging.debug('Injecting {} bytes of assembly at offset {}'.format(len(asm), self.next_injection_offset))
        self.binary.seek(self.next_injection_offset)
        self.binary.write(asm)

        # Update e_entry if requested
        if update_entry:
            logging.debug('Rewriting ELF entry address to {}'.format(self.next_injection_vaddr))
            elf_hdr = self.helper.header
            elf_hdr.e_entry = self.next_injection_vaddr

            self.binary.seek(0)
            self.binary.write(self.helper.structs.Elf_Ehdr.build(elf_hdr))

        self.helper = ELFFile(self.binary)

        self.next_injection_vaddr += len(asm)
        self.next_injection_offset += len(asm)

        return self.next_injection_vaddr - len(asm)