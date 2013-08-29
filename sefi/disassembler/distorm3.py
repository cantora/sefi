from sefi.disassembler import *
import sefi.arch
import re

try:
	import distorm3
except Exception as e:
	raise LibNotFound("error loading distorm3: %r" % e)

class DistormInstr(Instr):

	def __init__(self, addr, data, dasm, display):
		super(DistormInstr, self).__init__(addr, data, dasm)
	
		self.display_str = display

	def __str__(self):
		return self.display_str

	def display(self):
		if self.dasm.arch == sefi.arch.x86_64:
			addr_fmt = "%016x"
		else:
			addr_fmt = "%08x"

		#[RIP+0x201ac2]
		m = re.search(
			"\[\s*(?:EIP|RIP)\s*\+\s*0x([0-9a-zA-Z]+)\s*\]",
			self.display_str,
			re.IGNORECASE
		)
		if m is not None:
			comment = (" ; 0x"+addr_fmt) % (self.addr + int(m.group(1), 16))
		else:
			comment = ""

		return "%4s%-16s%2s%-16s%s%s" % (
			"", addr_fmt % (self.addr),
			"", "".join(map(lambda b: "%02x" % b, self.data)),
			self.display_str, comment
		)

	def match_regexp(self, *regexps):
		for reg in regexps:
			#print "match %r against %r" % (reg, ins)
			if re.search(reg, self.display_str, flags = re.IGNORECASE) is not None:
				return True
	
		return False

	def nop(self):
		return self.match_regexp(NOP_ALL):

	def has_uncond_ctrl_flow(self):
		regs = [
			'^CALL ',
			'^JMP '
		]
		
		return self.match_regexp(*regs)

	def has_cond_ctrl_flow(self):

		return self.match_regexp(*map( 
			lambda j: '^%s ' % j,
			filter(lambda str: str != 'JMP', JMP_NAMES)
		))

	def has_ctrl_flow(self):
		return self.has_cond_ctrl_flow() or \
				self.has_uncond_ctrl_flow()

	def bad(self):
		regs = [
			'^DB ',
			'^OUTS ',
			'^IN ',
			'^INS ',
			'^HLT$',
			RET_ALL
		]
	
		return self.match_regexp(*regs)


class DistormDasm(Disassembler):

	def __init__(self, decode_size):
		self.decode_size = decode_size
		
	def decode(self, addr, data):
		for ds_inst in distorm3.Decode(addr, data, self.decode_size):
			yield self.make_instr(ds_instr)

	def arch(self):
		if self.decode_size == distorm3.Decode32Bits:
			return sefi.arch.x86
		else:
			return sefi.arch.x86_64

#===========================
	def make_instr(self, ds_inst):
		return Instr(
			ds_inst[0],
			ds_inst[3].decode('hex'),
			self,
			ds_inst[2]
		)


def new(arch):
	if arch == sefi.arch.x86:
		decode_size = distorm3.Decode32Bits
	elif arch == sefi.arch.x86_64:
		decode_size = distorm3.Decode64Bits
	else:
		raise ArchNotSupported("distorm3 only supports %s and %s" % (
			sefi.arch.x86,
			sefi.arch.x86_64
		))

	return DistormDasm(decode_size)
