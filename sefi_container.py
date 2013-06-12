
import distorm3

class Segment:
	'''
	a physically (at load time, not necessarily on file) contiguous 
	list of bytes from a file. 
	@data: the bytes as they will be projected at load time.
	@base_addr: the base virtual address from which the segment begins
	'''

	def __init__(self, data, base_addr):
		self.data = data
		self.base_addr = base_addr

class Gadget:
	
	def __init__(self, parent_seq, parent_addr, addr_offset, data, arch):
		self.parent_seq = parent_seq
		self.parent_addr = parent_addr
		self.addr_offset = addr_offset
		self.data = data
		self.arch = arch

	def addr(self):
		return self.parent_addr - self.addr_offset

	def disassembly(self):
		return distorm3.Decode(self.addr(), self.data, self.arch)

	def __repr__(self):
		if self.arch == distorm3.Decode64Bits:
			addr_fmt = "0x%016x"
		else:
			addr = "0x%08x"

		#addr_fmt % (self.addr()) + "\n" + \
		return "\n".join(map(
				lambda insn: \
					"\t" + (addr_fmt % insn[0]) + "\t" + insn[2],
				self.disassembly()
			))


