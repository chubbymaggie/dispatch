import logging
import os

from .formats.elf_executable import ELFExecutable
from .formats.pe_executable import PEExecutable
from .formats.macho_executable import MachOExecutable

from .enums import *

MAGICS = {'\x7f\x45\x4c\x46': FORMAT.ELF,
          '\x4d\x5a': FORMAT.PE,
          '\x50\x45\x00\x00': FORMAT.PE,
          '\xFE\xED\xFA\xCE': FORMAT.MACH_O,
          '\xFE\xED\xFA\xCF': FORMAT.MACH_O,
          '\xCE\xFA\xED\xFE': FORMAT.MACH_O,
          '\xCF\xFA\xED\xFE': FORMAT.MACH_O}

def _identify_format(fh):
    maxlen = max([len(m) for m in MAGICS])

    fh.seek(0)
    header = fh.read(maxlen)

    for m in MAGICS:
        if header.startswith(m):
            return MAGICS[m]

    return None

def read_executable(file_path):
    if not os.path.exists(file_path):
        raise Exception('No such file')

    fmt = _identify_format(open(file_path, 'rb'))

    if fmt == FORMAT.ELF:
        exe = ELFExecutable(file_path)
    elif fmt == FORMAT.PE:
        exe = PEExecutable(file_path)
    elif fmt == FORMAT.MACH_O:
        exe = MachOExecutable(file_path)
    else:
        raise Exception('Could not determine executable format.')

    logging.info('Extracting symbol table')
    exe._extract_symbol_table()

    return exe