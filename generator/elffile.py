from collections import namedtuple

from elftools.elf.elffile import ELFFile
from elftools.elf.elffile import SymbolTableSection

ElfSym = namedtuple("ElfSym", "num value size type bind vis ndx name")
ElfSym.__new__.__defaults__ = (None,) * len(ElfSym._fields)

class ElfFile:
	def __init__(self, path):
		self.path = path

	def symbols(self):
		symbols = []
		with open(self.path, 'rb') as f:
			self.elf = ELFFile(f)

			section = self.elf.get_section_by_name('.symtab')
			if not section:
				print('  No symbol table found. Perhaps this ELF has been stripped?')
				return
			for num in range(0, section.num_symbols()):
				s = section.get_symbol(num)
				symbol = ElfSym(num, s['st_value'],
						s['st_size'], s['st_info'].type,
						s['st_info'].bind,
						s['st_other'].visibility,
						s['st_shndx'], s.name)
				if symbol.type in [ "STT_FUNC", "STT_OBJECT" ]:
					symbols.append(symbol)

		return symbols
