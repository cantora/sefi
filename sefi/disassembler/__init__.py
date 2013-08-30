import re

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
		self.dasm = dasm

	def addr(self):
		return self.addr

	def data(self):
		return self.data

	def dasm(self):
		return self.dasm
	
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
				and (self.dasm.arch() == other.dasm.arch())

	def __hash__(self):
		raise Exception("not implemented")

	def same(self, other):
		'''
		is this instruction the same as the other? 
		this comparison doesnt test for address equality
		in the instructions.
		'''
		return (self.data == other.data) \
				and (self.dasm.arch() == other.dasm.arch())

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
	libs = []

	try:
		dasm = try_distorm(arch)
	except LibNotFound:
		pass
	else:
		libs.append("distorm3")

	if not dasm:
		raise ArchNotSupported(
			"could not find disassembler for %r in " % (arch) + \
			"the following libraries: %s" % (libs)
		)

	return dasm
 
def try_distorm(arch):	
	from sefi.disassembler import distorm
	try:
		dasm = distorm.new(arch)
	except ArchNotSupported:
		return None

	return dasm

	