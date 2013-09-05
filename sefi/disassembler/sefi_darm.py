from sefi.disassembler import *
import sefi.arch

try:
	import darm
except Exception as e:
	raise LibNotFound("error loading darm: %r" % e)

class DarmInstr(Instr):
	def display(self):
		addr_fmt = "%08x"

		return self.internal_display(addr_fmt, str(self), "")

class BadDarmInstr(DarmInstr):

	def __init__(self, addr, data, dasm):
		super(BadDarmInstr, self).__init__(addr, data, dasm)

	def __str__(self):
		return "(bad)"

	def nop(self):
		return False

	def has_uncond_ctrl_flow(self):
		return False

	def has_cond_ctrl_flow(self):
		return False

	def bad(self):
		return True

	def ret(self):
		return False

	def jmp_reg_uncond(self):
		return False

	def call_reg(self):
		return False


class GoodDarmInstr(DarmInstr):

	def __init__(self, addr, data, darminst, dasm):
		self.darminst = darminst
		super(GoodDarmInstr, self).__init__(addr, data, dasm)
		
	def __str__(self):
		return str(self.darminst).strip()

	def nop(self):
		reg = '^nop'
		return self.match_regexp(reg)

	def name(self):
		return str(self.darminst.instr)

	def is_call(self):
		return self.name() in set(["BL", "BLX"])

	def is_branch(self):
		return self.name() in set([
			"B",
			"CBZ",
			"CBNZ",
			"BXJ",
			"BX",
			"TBB",
			"TBH"
		])

	def is_ctrl_flow(self):
		return self.is_call() or self.is_branch()

	def cond(self):
		return str(self.darminst.cond)

	def has_uncond_ctrl_flow(self):
		return self.is_ctrl_flow() \
					and self.cond() == "AL"

	def has_cond_ctrl_flow(self):
		return self.is_ctrl_flow() \
					and self.cond() != "AL"

	def bad(self):
		return False

	def ret(self):
		raise Exception("TODO: there is no explicit 'RET' " + \
						"in arm, have to do some real work here")

	def jmp_reg_uncond(self):
		raise Exception("TODO: not sure how to access operands in darm")

	def call_reg(self):
		raise Exception("TODO: not sure how to access operands in darm")
	
class DarmDasm(Disassembler):

	def __init__(self, dasm_fn, inst_size, arch):
		self.dasm_fn = dasm_fn
		self.arch
		self.inst_size = inst_size

	class ChunkItr(object):
		
		def __init__(self, n, addr, data):
			if not isinstance(data, tuple):
				raise TypeError("expected tuple of integers for data, got %s" % type(data))
			if n < 2:
				raise ValueError("expected n > 2, got %d" % n)
			if len(data) < 1:
				raise ValueError("expected non empty data")
			
			self.n = n
			self.addr = addr
			self.data = data
			self.remainder = None

		def chunks(self):
			curr_addr = self.addr
			accum = []
			self.remainder = None

			for b in self.data:
				accum.append(b)
				if len(accum) == self.n:
					yield (curr_addr, tuple(accum))
					accum = []
					curr_addr += self.n
	
			if len(accum) > 0:
				self.remainder = (curr_addr, tuple(accum))

	def chunk_to_int(self, chunk):
		i = 0
		result = 0
		for b in chunk:
			result |= b << (8*i)
			i += 1

		return result
				
	def decode(self, addr, data):
		if len(data) < 1:
			return
		
		itr = self.__class__.ChunkItr(self.inst_size, addr, data)
		for (addr, chunk) in itr.chunks():
			n = self.chunk_to_int(chunk)
			#print("converted %r to 0x%08x" % (chunk, n))
			darm_inst = self.dasm_fn(n)
			if darm_inst is None:
				yield BadDarmInstr(addr, chunk, self)
			else:
				yield GoodDarmInstr(addr, chunk, darm_inst, self)

		#an incomplete instruction is left over		
		if not itr.remainder is None:
			yield BadDarmInstr(
				itr.remainder[0],
				itr.remainder[1],
				self
			)

	def arch(self):
		return self.arch
		

def new(arch):

	dasm_fn = None
	inst_size = 4
	if arch == sefi.arch.arm:
		dasm_fn = darm.disasm_armv7
	elif arch == sefi.arch.thumb1:
		dasm_fn = darm.disasm_thumb
		inst_size = 2
	elif arch == sefi.arch.thumb2:
		dasm_fn = darm.disasm_thumb2

	if not dasm_fn:
		raise ArchNotSupported("darm does not support " + \
								"architecture %s" % arch)

	return DarmDasm(dasm_fn, inst_size, arch)
	

