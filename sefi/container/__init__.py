
import distorm3

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
					lambda x, y: x[3].decode('hex') + y[3].decode('hex'),
					arr
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
					"%4s%-16s%2s%-12s%4s%s" % (
						"", addr_fmt % (insn[0]),
						"", insn[3],
						"", insn[2]
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

class Gadget(InstSeq):
	
	def __init__(self, addr, data, arch, parent_offset):
		super(Gadget, self).__init__(addr, data, arch)

		self.parent_offset = parent_offset

	
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

