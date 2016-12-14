import logging
import struct

from macholib.MachO import MachO
from macholib.mach_o import *

from .base_executable import *
from .section import *

INJECTION_SEGMENT_NAME = 'INJECT'
INJECTION_SECTION_NAME = 'inject'

class MachOExecutable(BaseExecutable):
    def __init__(self, file_path):
        super(MachOExecutable, self).__init__(file_path)

        self.helper = MachO(self.fp)

        if self.helper.fat:
            raise Exception('MachO fat binaries are not supported at this time')

        self.architecture = self._identify_arch()

        if self.architecture is None:
            raise Exception('Architecture is not recognized')

        logging.debug('Initialized {} {} with file \'{}\''.format(self.architecture, type(self).__name__, file_path))

        self.pack_endianness = self.helper.headers[0].endian

        self.sections = []
        for lc, cmd, data in self.helper.headers[0].commands:
            if lc.cmd in (LC_SEGMENT, LC_SEGMENT_64):
                for section in data:
                    self.sections.append(section_from_macho_section(section, cmd))

        self.executable_segment = [cmd for lc, cmd, _ in self.helper.headers[0].commands
                                   if lc.cmd in (LC_SEGMENT, LC_SEGMENT_64) and cmd.initprot & 0x4][0]

        self.libraries = [fp.rstrip('\x00') for lc, cmd, fp in self.helper.headers[0].commands if lc.cmd == LC_LOAD_DYLIB]

    def _identify_arch(self):
        if self.helper.headers[0].header.cputype == 0x7:
            return ARCHITECTURE.X86
        elif self.helper.headers[0].header.cputype == 0x01000007:
            return ARCHITECTURE.X86_64
        elif self.helper.headers[0].header.cputype == 0xc:
            return ARCHITECTURE.ARM
        elif self.helper.headers[0].header.cputype == 0x0100000c:
            return ARCHITECTURE.ARM_64
        else:
            return None

    def executable_segment_vaddr(self):
        return self.executable_segment.vmaddr

    def executable_segment_size(self):
        return self.executable_segment.vmsize

    def entry_point(self):
        for lc, cmd, _ in self.helper.headers[0].commands:
            if lc.cmd == LC_MAIN:
                return cmd.entryoff
        return

    def _extract_symbol_table(self):
        ordered_symbols = []

        symtab_command = self.helper.headers[0].getSymbolTableCommand()

        if symtab_command:
            self.binary.seek(symtab_command.stroff)
            symbol_strings = self.binary.read(symtab_command.strsize)

            self.binary.seek(symtab_command.symoff)

            for i in range(symtab_command.nsyms):
                if self.is_64_bit():
                    symbol = nlist_64.from_fileobj(self.binary, _endian_=self.pack_endianness)
                else:
                    symbol = nlist.from_fileobj(self.binary, _endian_=self.pack_endianness)

                symbol_name = symbol_strings[symbol.n_un:].split('\x00')[0]

                if symbol.n_type & N_STAB == 0:
                    is_ext = symbol.n_type & N_EXT and symbol.n_value == 0

                    # Ignore Apple's hack for radar bug 5614542
                    if not is_ext and symbol_name != 'radr://5614542':
                        size = 0
                        logging.debug('Adding function {} from the symtab at vaddr {} with size {}'
                                      .format(symbol_name, hex(symbol.n_value), hex(size)))
                        f = Function(symbol.n_value, size, symbol_name, self)
                        self.functions[symbol.n_value] = f

                ordered_symbols.append(symbol_name)

        dysymtab_command = self.helper.headers[0].getDynamicSymbolTableCommand()
        if dysymtab_command:
            self.binary.seek(dysymtab_command.indirectsymoff)
            indirect_symbols = self.binary.read(dysymtab_command.nindirectsyms*4)

            sym_offsets = struct.unpack(self.pack_endianness + 'I'*dysymtab_command.nindirectsyms, indirect_symbols)

            for lc, cmd, sections in self.helper.headers[0].commands:
                if lc.cmd in (LC_SEGMENT, LC_SEGMENT_64) and cmd.initprot & 0x4:
                    for section in sections:
                        if section.flags & S_NON_LAZY_SYMBOL_POINTERS == S_NON_LAZY_SYMBOL_POINTERS \
                            or section.flags & S_LAZY_SYMBOL_POINTERS == S_LAZY_SYMBOL_POINTERS \
                            or section.flags & S_SYMBOL_STUBS == S_SYMBOL_STUBS:

                            logging.debug('Parsing dynamic entries in {}.{}'.format(section.segname, section.sectname))

                            if section.flags & S_SYMBOL_STUBS:
                                stride = section.reserved2
                            else:
                                stride = (64 if self.is_64_bit() else 32)

                            count = section.size / stride

                            for i in range(count):
                                addr = self.executable_segment.vmaddr + section.offset + (i * stride)
                                idx = sym_offsets[i + section.reserved1]
                                if idx == 0x40000000:
                                    symbol_name = "INDIRECT_SYMBOL_ABS"
                                elif idx == 0x80000000:
                                    symbol_name = "INDIRECT_SYMBOL_LOCAL"
                                else:
                                    symbol_name = ordered_symbols[idx]
                                logging.debug('Adding function {} from the dynamic symtab at vaddr {} with size {}'
                                              .format(symbol_name, hex(addr), hex(stride)))
                                f = Function(addr, stride, symbol_name, self, type=Function.DYNAMIC_FUNC)
                                self.functions[addr] = f

    def iter_string_sections(self):
        STRING_SECTIONS = ['__const', '__cstring', '__objc_methname', '__objc_classname']
        for s in self.sections:
            if s.name in STRING_SECTIONS:
                yield s

    def prepare_for_injection(self):
        # Total size of the stuff we're going to be adding in the middle of the binary
        offset = 72+80 if self.is_64_bit() else 56+68  # 1 segment header + 1 section header

        fileoff = (self.binary.len & ~0xfff) + 0x1000

        vmaddr = self.function_named('__mh_execute_header').address + fileoff

        logging.debug('Creating new MachOSegment at vaddr {}'.format(hex(vmaddr)))
        new_segment = segment_command_64() if self.is_64_bit() else segment_command()
        new_segment._endian_ = self.pack_endianness
        new_segment.segname = INJECTION_SEGMENT_NAME
        new_segment.fileoff = fileoff
        new_segment.filesize = 0
        new_segment.vmaddr = vmaddr
        new_segment.vmsize = 0x1000
        new_segment.maxprot = 0x7 #RWX
        new_segment.initprot = 0x5 # RX
        new_segment.flags = 0
        new_segment.nsects = 1

        logging.debug('Creating new MachOSection at vaddr {}'.format(hex(vmaddr)))
        new_section = section_64() if self.is_64_bit() else section()
        new_section._endian_ = self.pack_endianness
        new_section.sectname = INJECTION_SECTION_NAME
        new_section.segname = new_segment.segname
        new_section.addr = new_segment.vmaddr
        new_section.size = 0
        new_section.offset = new_segment.fileoff
        new_section.align = 4
        new_section.flags = 0x80000400

        lc = load_command()
        lc._endian_ = self.pack_endianness
        lc.cmd = LC_SEGMENT_64 if self.is_64_bit() else LC_SEGMENT
        lc.cmdsize = offset

        self.helper.headers[0].commands.append((lc, new_segment, [new_section]))

        self.helper.headers[0].header.ncmds += 1
        self.helper.headers[0].header.sizeofcmds += offset

        return new_segment

    def inject(self, asm, update_entry=False):
        found = [s for lc,s,_ in self.helper.headers[0].commands if lc.cmd in (LC_SEGMENT, LC_SEGMENT_64) and s.segname == INJECTION_SEGMENT_NAME]
        if found:
            injection_vaddr = found[0].vmaddr
        else:
            logging.warning(
                'prepare_for_injection() was not called before inject(). This may cause unexpected behavior')
            inject_seg = self.prepare_for_injection()
            injection_vaddr = inject_seg.vmaddr

        if update_entry:
            for lc, cmd, _ in self.helper.headers[0].commands:
                if lc.cmd == LC_MAIN:
                    cmd.entryoff = injection_vaddr
                    break

        self.binary.seek(0)

        for lc, segment, sections in self.helper.headers[0].commands:
            if lc.cmd in (LC_SEGMENT, LC_SEGMENT_64) and segment.segname == INJECTION_SEGMENT_NAME:
                injection_offset = segment.fileoff + segment.filesize
                segment.filesize += len(asm)
                if segment.filesize + len(asm) > segment.vmsize:
                    segment.vmsize += 0x1000
                for section in sections:
                    if section.sectname == INJECTION_SECTION_NAME:
                        section.size += len(asm)
                        self.next_injection_vaddr = section.addr + section.size

        self.helper.headers[0].write(self.binary)

        self.binary.seek(injection_offset)
        self.binary.write(asm)

        return injection_vaddr
