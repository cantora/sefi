
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

	def addr(self):
		return self.base_addr

	def disassembly(self):
		return distorm3.Decode(self.addr(), self.data, self.arch)

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

		#addr_fmt % (self.addr()) + "\n" + \
		return "\n".join(map(
				lambda insn: \
					"\t" + (addr_fmt % insn[0]) + "\t" + insn[2],
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
	
	def __init__(self, parent_seq, parent_addr, addr_offset, data, arch):
		super(Gadget, self).__init__(
			parent_addr - addr_offset,
			data, arch
		)

		self.parent_seq = parent_seq
		self.parent_addr = parent_addr
		self.addr_offset = addr_offset



