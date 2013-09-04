import re
import sys

from sefi.log import debug, info, warning
from sefi.err import SefiErr

class DisassemblerErr(SefiErr):
	pass

class ArchNotSupported(DisassemblerErr):
	pass

class LibNotFound(DisassemblerErr):
	pass

class Instr(object):

	def __init__(self, addr, data, dasm):
		self.addr = addr
		self.data = data
		if not isinstance(self.data, tuple):
			raise TypeError("expected tuple for data")
		self.dasm = dasm
		self.frozen = True

	def addr(self):
		return self.addr

	def data(self):
		return self.data

	def dasm(self):
		return self.dasm

	def arch(self):
		return self.dasm.arch()

	def immutable_exception(self):
		raise Exception("%s is meant to be immutable" % self.__class__.__name__)

	def __setattr__(self, *args):
		if getattr(self, 'frozen', False):
			return self.immutable_exception()
		else:
			return super(Instr, self).__setattr__(*args)

	def __delattr__(self, *ignored):
		return self.immutable_exception()

	def __hash__(self):
		return hash((
			self.addr(),
			self.arch(),
			self.data
		))

	def __str__(self):
		'''
		returns simple form of instruction suitable
		for regexp matching
		'''
		raise Exception("not implemented")

	def display(self):
		'''
		returns pretty display form of instruction.
		'''
		raise Exception("not implemented")

	def internal_display(self, addr_fmt, instr_str, comment):
		return "%4s%-16s%2s%-23s%s%s" % (
			"", addr_fmt % (self.addr),
			"", "".join(map(lambda b: "%02x" % b, self.data)),
			instr_str, comment
		)


	
	def __len__(self):
		return len(self.data)

	def __repr__(self):
		return repr((
			self.addr,
			self.data,
			self.dasm,
			str(self)	
		))

	def __eq__(self, other):
		return (self.data == other.data) \
				and (self.addr == other.addr) \
				and (self.arch() == other.arch())

	def __hash__(self):
		raise Exception("not implemented")

	def same(self, other):
		'''
		is this instruction the same as the other? 
		this comparison doesnt test for address equality
		in the instructions.
		'''
		return (self.data == other.data) \
				and (self.arch() == other.arch())

	def match_regexp(self, *regexps):
		for reg in regexps:
			#print "match %r against %r" % (reg, ins)
			if re.search(reg, str(self), flags = re.IGNORECASE) is not None:
				return True
	
		return False

	def nop(self):
		raise Exception("not implemented")

	def has_uncond_ctrl_flow(self):
		raise Exception("not implemented")

	def has_cond_ctrl_flow(self):
		raise Exception("not implemented")

	def has_ctrl_flow(self):
		return self.has_cond_ctrl_flow() or \
				self.has_uncond_ctrl_flow()

	def bad(self):
		raise Exception("not implemented")

	def ret(self):
		raise Exception("not implemented")

	def jmp_reg_uncond(self):
		raise Exception("not implemented")

	def call_reg(self):
		raise Exception("not implemented")

class Disassembler(object):

	def decode(self, addr, data):
		raise Exception("not implemented")

	def arch(self):
		raise Exception("not implemented")

def find(arch):
	plug_fns = [
		try_llvm,
		try_distorm,
	]

	libs = []

	for plug_fn in plug_fns:
		try:
			dasm = plug_fn(arch)
			return dasm
		except LibNotFound as e:
			#sys.stderr.write("failed to load library: %r" % e)
			pass
		else:
			libs.append("distorm3")

	raise ArchNotSupported(
		"could not find disassembler for %r in " % (arch) + \
		"the following libraries: %s" % (libs)
	)

 
def try_distorm(arch):	
	from sefi.disassembler import sefi_distorm
	try:
		dasm = sefi_distorm.new(arch)
	except ArchNotSupported:
		return None

	return dasm

def try_llvm(arch):	
	from sefi.disassembler import sefi_llvm
	try:
		dasm = sefi_llvm.new(arch)
	except ArchNotSupported:
		return None

	return dasm
