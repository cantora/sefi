# Copyright 2013 anthony cantor
# This file is part of sefi.
# 
# sefi is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#  
# sefi is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#  
# You should have received a copy of the GNU General Public License
# along with sefi.  If not, see <http://www.gnu.org/licenses/>.
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

BRANCH_INSTS = set([
	"B",
	"CBZ",
	"CBNZ",
	"BXJ",
	"BX",
	"TBB",
	"TBH"
])

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

	def writes_to_reglist(self):
		return self.name() in set(["LDM", "POP"])

	def explicitly_modifies_pc(self):
		return self.Rd_is_pc() \
			or (
				self.pc_in_reglist()
				and self.writes_to_reglist()
			)

	def is_branch(self):
		return \
			self.name() in BRANCH_INSTS \
			or ((not self.is_call())
				and (not self.ret())
				and self.explicitly_modifies_pc()
			)

	def is_ctrl_flow(self):
		return self.is_call() \
			or self.is_branch() \
			or self.ret()

	def cond(self):
		return str(self.darminst.cond)

	def is_unconditional(self):
		return self.cond() == "AL"

	def has_uncond_ctrl_flow(self):
		return self.is_ctrl_flow() \
			and self.is_unconditional()

	def has_cond_ctrl_flow(self):
		return self.is_ctrl_flow() \
			and not self.is_unconditional()

	def bad(self):
		return False

	def Rd(self):
		return str(self.darminst.Rd)

	def Rn(self):
		return str(self.darminst.Rn)

	def Rn_is_sp(self):
		return (not self.darminst.Rn is None) \
			and self.Rn() == "PC"

	def Rd_is_pc(self):
		return (not self.darminst.Rd is None) \
			and self.Rd() == "PC"

	def reglist(self):
		arr = str(self.darminst.reglist).strip('{}').split(',')
		return set(filter(lambda x: len(x) > 0, arr))

	def pc_in_reglist(self):
		return "PC" in self.reglist()

	def ret(self):
		return self.is_unconditional() \
			and self.explicitly_modifies_pc() \
			and (
				self.name() == "POP"
				or (
					self.name() == "LDM"
					and self.Rn_is_sp()
				)
			)

	def jmp_reg_uncond(self):
		return self.is_unconditional() \
			and self.is_branch() \
			and (
				(not self.darminst.Rm is None)
				or (not self.darminst.Rn is None)
			)

	def call_reg(self):
		return self.is_unconditional() \
			and self.is_call() \
			and (not self.darminst.Rm is None)
	
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
	

