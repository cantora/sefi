import sefi.disassembler

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

	@staticmethod
	def from_arch(self, base_addr, data, arch):
		dasm = sefi.disassembler.find(arch)

		return InstSeq(base_addr, data, dasm)

	def __init__(self, base_addr, data, dasm):
		self.base_addr = base_addr
		self.data = data
		self.dasm = dasm

		if not isinstance(self.base_addr, int) and \
				not isinstance(self.base_addr, long):
			raise TypeError("invalid base_addr: %r(%s)" % (self.base_addr, type(self.base_addr)))
		if not isinstance(self.data, str):
			raise TypeError("invalid data: %r(%s)" % (self.data, type(self.data)))
		if not isinstance(self.dasm, sefi.disassembler.Disassembler):
			raise TypeError("invalid dasm: %r" % self.dasm)		

	def arch(self):
		return self.dasm.arch()

	def addr(self):
		return self.base_addr

	def disassembly(self):
		return self.dasm.decode(self.addr(), self.data)

	def __getitem__(self, key):
		if type(key) is int:
			return list(self.disassembly())[key]

		elif type(key) is slice:
			arr = list(self.disassembly())[key]
			if len(arr) < 1:
				raise TypeError("invalid key: %r" % key)

			return InstSeq(
				arr[0].addr,
				reduce(
					lambda sum, y: sum + y.data,
					arr[1:],
					arr[0].data
				),
				self.dasm
			)


		raise TypeError("invalid key: %r" % key)


	def proc_equal(self, other):
		'''
		is the procedure equal? that is, are the insructions the
		same (not regarding location in memory or equivalent
		encodings)
		'''

		if not isinstance(other, InstSeq):
			raise TypeError("invalid other: %r(%s)" % (other, type(other)))

		return self.same_str_seq(other.str_seq())


	def __list__(self):
		return list(self.disassembly())

	def __len__(self):
		return len(list(self.disassembly()))

	def __reversed__(self):
		return reversed(list(self))

	def str_seq(self):
		return map(
			lambda insn: str(insn),
			self.disassembly()
		)
	
	def as_prefix(self):
		return list(reversed(self.str_seq()))

	def __str__(self):
		return repr(list(self.str_seq()))

	def __repr__(self):
		return self.display()

	def display(self):
		return "\n".join(map(
			lambda insn: insn.display(),
			self.disassembly()
		))

	def same_str_seq(self, str_seq):
		'''
		tests whether @str_seq is the same as the
		string sequence for this instruction sequence 
		'''

		ss = self.str_seq()
		if len(ss) != len(str_seq):
			return False

		for (x,y) in zip(self.str_seq(), str_seq):
			if x != y:
				return False 
	
		return True

	def match_regexp(self, *regexps):
		for ins in self:
			if ins.match_regexp(*regexps):
				return True
	
		return False

	def test_for(self, fn):
		for ins in self:
			if fn(ins):
				return True

		return False

	def nop(self):
		'''is this a sequence of nops?'''
		return not self.test_for(lambda ins: not ins.nop())

	def without_nop_prefix(self):
		str_seq = self.str_seq()
		for offset in range(0, len(self)):
			if not self[offset].nop():
				break

		return self[offset:]
		
	def has_uncond_ctrl_flow(self):
		return self.test_for(lambda ins: ins.has_uncond_ctrl_flow())

	def has_cond_ctrl_flow(self):
		return self.test_for(lambda ins: ins.has_cond_ctrl_flow())

	def has_ctrl_flow(self):
		return self.has_uncond_ctrl_flow() or self.has_cond_ctrl_flow()

class Gadget(InstSeq):
	
	def __init__(self, addr, data, dasm, parent_offset):
		super(Gadget, self).__init__(addr, data, dasm)

		self.parent_offset = parent_offset

	def nop(self):
		return self.suffix().nop()

	def compact(self):
		'''remove unnecessary prefix instructions'''
		if self.nop():
			return None
		
		suf = self.suffix()
		if suf[0].nop():
			suf = suf.without_nop_prefix()
			return Gadget(
				suf.addr(),
				suf.data + self.prefix().data,
				self.dasm,
				len(suf.data)
			)
		else:
			return self
		
	def suffix(self):
		'''
		by "suffix" i mean the instructions preceding
		the gadget terminator (i.e. RET). by "prefix"
		i mean the gadget terminator sequence. 
		'''

		return InstSeq(
			self.addr(),
			self.data[:self.parent_offset],
			self.dasm
		)

	def parent(self):
		return InstSeq(
			self.addr() + self.parent_offset,
			self.data[self.parent_offset:],
			self.dasm
		)

	def prefix(self):
		return self.parent()

	def display(self):
		return "%r\n%4s%s\n%r" % (
			self.suffix(),
			"", "_"*40,
			self.prefix()
		)

	def has_bad_ins(self):
		return self.suffix().test_for(lambda ins: ins.bad() )

	def has_uncond_ctrl_flow(self):
		return self.suffix().has_uncond_ctrl_flow()

	def has_cond_ctrl_flow(self):
		return self.suffix().has_cond_ctrl_flow()
