from collections import namedtuple
import sys
import bisect
from weakref import WeakKeyDictionary

from elftools.elf.elffile import ELFFile
from elftools.elf.elffile import SymbolTableSection
from elftools.elf.descriptions import describe_p_flags, describe_reloc_type
from elftools.elf.constants import P_FLAGS, SH_FLAGS
from elftools.elf.enums import ENUM_SH_TYPE

from consts import *
from util import memoize

set_const_raw(SH_FLAGS.__dict__)
set_const_str(ENUM_SH_TYPE)

ElfHeader = namedtuple("ElfHeader", "type machine")
ElfSym = namedtuple("ElfSym", "num value size type bind vis ndx name")
ElfSection = namedtuple("ElfSection", "offset addr size")
ElfSegment = namedtuple("ElfSegment", "type offset vaddr paddr mem_sz flags align file_sz")
ElfRelaPlt = namedtuple("ElfRelaPlt", "offset info_type addend")

def get_build_id(elf):
	section_name = '.note.gnu.build-id'
	n_type = 'NT_GNU_BUILD_ID'

	sec = elf.get_section_by_name(section_name)
	if sec is None:
		return
	
	for note in sec.iter_notes():
		if note['n_type'] == n_type:
			return note['n_desc']

	print ("ELF section %s doesn't have %s descriptor" %
			(section, n_type))

class ElfFile:
	def __init__(self, stream):
		self.stream = stream
		self.elf = ELFFile(self.stream)
		self.symbols = None
		self.dynamic_symbols = None

	@property
	def syms(self):
		if self.symbols is None:
			self.symbols = self.__section_symbols__('.symtab')
		return self.symbols

	@property
	def dynsyms(self):
		if self.dynamic_symbols is None:
			self.symbols = self.__section_symbols__('.dynsym')
		return self.symbols

	def get_header(self):
		return ElfHeader(self.elf['e_type'],
				 self.elf['e_machine'])

	def __get_section__(self, name):
		section = self.elf.get_section_by_name(name)
		if section and section['sh_type'] == "SHT_NOBITS":
			print "section '%s' type is NOBITS" % name
			print "Perhabs this ELF was stripped"
			sys.exit(1)
		return section

	def __section_symbols__(self, section_name):
		symbols = {}

		section = self.__get_section__(section_name)
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
			sections[s.name] = ElfSection(s['sh_offset'],
						      s['sh_addr'], s['sh_size'])
		return sections

	def get_segments(self):
		segments = []
		for s in self.elf.iter_segments():
			segment = ElfSegment(s['p_type'], s['p_offset'],
					s['p_vaddr'], s['p_paddr'],
					s['p_memsz'], s['p_flags'],
					s['p_align'], s['p_filesz'])
			segments.append(segment)
		return segments

	def build_id(self):
		section = '.note.gnu.build-id'
		try:
			n_type = 'NT_GNU_BUILD_ID'

			bid = self.__get_section__(section)
			if section is None:
				return None

			for note in bid.iter_notes():
				if note['n_type'] == n_type:
					return note['n_desc']
			print ("ELF section %s doesn't have %s descriptor" %
					(section, n_type))
		except AttributeError:
			print "ELF file doesn't have %s section" % section
		return None


class AddressSpace(object):
	def __init__(self, elf):
		# See comment from get_dio_by_pos() on how lookup is done
		self._sec_info = sec_info = [(-sec.header.sh_addr, sec)
			for sec in elf.iter_sections()
				if sec.header.sh_flags & RAW.SHF_ALLOC]

		sec_info.append((1, None))
		sec_info.sort()

	def get_section(self, addr):
		key = (-addr,)
		idx = bisect.bisect(self._sec_info, key)
		_, sec = self._sec_info[idx]
		if not sec:
			return

		if addr - sec.header.sh_addr >= sec.header.sh_size:
			return
		return sec

get_address_space = memoize(WeakKeyDictionary)(AddressSpace)

class MemoryStream(object):
	def __init__(self, elf):
		self.elf = elf
		self._address_space = get_address_space(elf)

	def seek(self, addr):
		self._addr = addr

	def tell(self):
		return self._addr

	def _read(self, size):
		assert size >= 0
		if not size:
			return ""

		get_section = self._address_space.get_section

		addr = self._addr
		next_addr = addr + size

		sec = get_section(addr)
		if not sec:
			raise Exception("No section for address {:x}".format(addr))

		next_sec = get_section(next_addr - 1)
		# Make sure one read() call processes data from one section
		if sec is not next_sec:
			next_addr = sec.header.sh_addr + sec.header.sh_size
			size = next_addr - addr

		if sec.header.sh_type == STR.SHT_NOBITS:
			data = "\x00" * size
		else:
			stream = sec.stream
			offset = addr - sec.header.sh_addr + sec.header.sh_offset
			stream.seek(offset)
			data = stream.read(size)
			if len(data) != size:
				raise Exception("Short read: got {}, expected {}".format(
							len(data), size))

		self._addr = next_addr
		return data

	def read(self, size, allow_short=False):
		data = self._read(size)
		assert len(data) <= size
		if not allow_short and len(data) < size:
			raise Exception("Short read: got {}, expected {}".format(
				len(data), size))
		return data

