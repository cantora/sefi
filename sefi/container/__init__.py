import sefi.mnemonic

import distorm3
import re

class Segment(object):
	'''
	a physically (at load time, not necessarily on file) contiguous 
	list of bytes from a file. 
	@data: the bytes as they will be projected at load time.
	@base_addr: the base virtual address from which the segment begins
	'''

	def __init__(self, data, base_addr):
		self.data = data
		self.base_addr = base_addr

class InstSeq(object):
	
	def __init__(self, base_addr, data, arch):
		self.base_addr = base_addr
		self.data = data
		self.arch = arch

		if not isinstance(self.base_addr, int) and \
				not isinstance(self.base_addr, long):
			raise TypeError("invalid base_addr: %r(%s)" % (self.base_addr, type(self.base_addr)))
		if not isinstance(self.data, str):
			raise TypeError("invalid data: %r(%s)" % (self.data, type(self.data)))
		if self.arch not in [distorm3.Decode32Bits, distorm3.Decode64Bits]:
			raise TypeError("invalid arch: %r" % (self.arch))
		

	def addr(self):
		return self.base_addr

	def disassembly(self):
		return distorm3.Decode(self.addr(), self.data, self.arch)

	@staticmethod
	def from_distorm_inst(ds_inst, arch):
		return InstSeq(
			ds_inst[0],
			ds_inst[3].decode('hex'),
			arch
		)

	def __getitem__(self, key):
		if type(key) is int:
			ins = self.disassembly()[key]
			return self.__class__.from_distorm_inst(ins, self.arch)

		elif type(key) is slice:
			arr = self.disassembly()[key]
			if len(arr) < 1:
				raise TypeError("invalid key: %r" % key)
			elif len(arr) < 2:
				return self.__class__.from_distorm_inst(arr[0], self.arch)

			return InstSeq(
				arr[0][0],
				reduce(
					lambda sum, y: sum + y[3].decode('hex'),
					arr[1:],
					arr[0][3].decode('hex')
				),
				self.arch
			)


		raise TypeError("invalid key: %r" % key)


	def proc_equal(self, other):
		'''is the procedure equal? that is, are the insructions the
			same (not regarding location in memory)'''

		if not isinstance(other, InstSeq):
			raise TypeError("invalid other: %r(%s)" % (other, type(other)))

		return self.same_str_seq(other.str_seq())


	def __len__(self):
		return len(self.disassembly())

	def __list__(self):
		return self.disassembly()

	def __reversed__(self):
		return reversed(list(self))

	def str_seq(self):
		return map(
			lambda insn: insn[2],
			self.disassembly()
		)
	
	def as_prefix(self):
		return map(
			lambda insn: insn[2],
			reversed(self.disassembly())
		)

	def __str__(self):
		return repr(list(self.str_seq()))

	def __repr__(self):
		if self.arch == distorm3.Decode64Bits:
			addr_fmt = "0x%016x"
		else:
			addr_fmt = "0x%08x"

		return "\n".join(map(
				lambda insn: \
					"%4s%-16s%2s%-16s%s" % (
						"", addr_fmt % (insn[0]),
						"", insn[3],
						insn[2]
					),
				self.disassembly()
			))

	def same_str_seq(self, str_seq):
		''' tests whether @str_seq is the same as the
			string sequence for this instruction sequence '''

		for (x,y) in zip(self.str_seq(), str_seq):
			if x != y:
				return False 
	
		return True

	def match_regexp(self, regexps):
		for ins in self.str_seq():
			for reg in regexps:
				if re.search(reg, ins, flags = re.IGNORECASE) is not None:
					return True
	
		return False

	@staticmethod
	def match_nop(ds_inst):
		if re.search('^NOP( |$)', ds_inst, flags = re.IGNORECASE) is None:
			return False

		return True

	def nop(self):
		'''is this a sequence of nops?'''
		for ins in self.str_seq():
			if not self.__class__.match_nop(ins):
				return False

		return True

	def without_nop_prefix(self):
		str_seq = self.str_seq()
		for offset in range(0, len(str_seq)):
			if not self.__class__.match_nop(str_seq[offset]):
				break

		return self[offset:]
		
	def has_uncond_ctrl_flow(self):
		regs = [
			'^CALL ',
			'^JMP '
		]
		
		return self.match_regexp(regs)

	def has_cond_ctrl_flow(self):

		return self.match_regexp(map( 
			lambda j: '^%s ' % j,
			sefi.mnemonic.JMP_NAMES
		))

	def has_ctrl_flow(self):
		return self.has_cond_ctrl_flow() or \
				self.has_uncond_ctrl_flow()


class Gadget(InstSeq):
	
	def __init__(self, addr, data, arch, parent_offset):
		super(Gadget, self).__init__(addr, data, arch)

		self.parent_offset = parent_offset

	def nop(self):
		return self.suffix().nop()

	def compact(self):
		'''remove unnecessary prefix instructions'''
		if self.nop():
			return None
		
		suf = self.suffix()
		if self.__class__.match_nop(suf.str_seq()[0]):
			suf = suf.without_nop_prefix()
			return Gadget(
				suf[0].addr(),
				suf.data + self.prefix().data,
				self.arch,
				len(suf.data)
			)
		else:
			return self
		
	def suffix(self):
		''' by "suffix" i mean the instructions preceding
			the gadget terminator (i.e. RET). by "prefix"
			i mean the gadget terminator sequence. '''

		return InstSeq(
			self.addr(),
			self.data[:self.parent_offset],
			self.arch
		)

	def parent(self):
		return InstSeq(
			self.addr() + self.parent_offset,
			self.data[self.parent_offset:],
			self.arch
		)

	def prefix(self):
		return self.parent()

	def __repr__(self):
		return "%r\n%4s%s\n%r" % (
			self.suffix(),
			"", "_"*40,
			self.prefix()
		)

	def has_bad_ins(self):
		common = [
			'^DB ',
			'^OUTS ',
			'^IN ',
			'^INS ',
			'^HLT$',
			sefi.mnemonic.RET_ALL
		]
	
		bad_ins = {
			distorm3.Decode32Bits: common,
			distorm3.Decode64Bits: common
		}

		#only check instructions after the prefix (i.e. RET)
		return self.suffix().match_regexp(bad_ins[self.arch])

