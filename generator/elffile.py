from collections import namedtuple

from elftools.elf.elffile import ELFFile
from elftools.elf.elffile import SymbolTableSection
from elftools.elf.descriptions import describe_p_flags
from elftools.elf.constants import P_FLAGS

ElfHeader = namedtuple("ElfHeader", "type machine")
ElfSym = namedtuple("ElfSym", "num value size type bind vis ndx name")
ElfSection = namedtuple("ElfSection", "name offset addr size")

class ElfFile:
	def __init__(self, stream):
		self.stream = stream
		self.elf = ELFFile(self.stream)

	def get_header(self):
		return ElfHeader(self.elf['e_type'],
				 self.elf['e_machine'])
	def __section_symbols__(self, section_name):
		symbols = {}

		section = self.elf.get_section_by_name(section_name)
		if section is None:
			return None

		for num in range(0, section.num_symbols()):
			s = section.get_symbol(num)
			symbols[num] = ElfSym(num, s['st_value'],
					s['st_size'], s['st_info'].type,
					s['st_info'].bind,
					s['st_other'].visibility,
					s['st_shndx'], s.name)

		return symbols

	def get_symbols(self):
		return self.__section_symbols__('.symtab')

	def get_sections(self):
		sections = {}
		for i in range(self.elf.num_sections()):
			s = self.elf.get_section(i)
			sections[s.name] = ElfSection(s.name, s['sh_offset'],
						      s['sh_addr'], s['sh_size'])
		return sections
