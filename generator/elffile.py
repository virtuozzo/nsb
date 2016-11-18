from collections import namedtuple

from elftools.elf.elffile import ELFFile
from elftools.elf.elffile import SymbolTableSection
from elftools.elf.descriptions import describe_p_flags
from elftools.elf.constants import P_FLAGS

ElfSym = namedtuple("ElfSym", "num value size type bind vis ndx name")
ElfSection = namedtuple("ElfSection", "name offset addr size")

class ElfFile:
	def __init__(self, stream):
		self.stream = stream
		self.elf = ELFFile(self.stream)

	def symbols(self):
		symbols = []

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

	def get_sections(self):
		sections = {}
		for i in range(self.elf.num_sections()):
			s = self.elf.get_section(i)
			sections[s.name] = ElfSection(s.name, s['sh_offset'],
						      s['sh_addr'], s['sh_size'])
		return sections
