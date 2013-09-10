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
	import llvm
except Exception as e:
	raise LibNotFound("error loading llvm: %r" % e)

import llvm.target
import llvm.mc
from llvm.target import TargetMachine

llvm.target.initialize_all()

class LLVMInstr(Instr):
	def display(self):
		if self.dasm.arch() == sefi.arch.x86_64:
			addr_fmt = "%016x"
		else:
			addr_fmt = "%08x"

		return self.internal_display(addr_fmt, str(self), "")

class BadLLVMInstr(LLVMInstr):

	def __init__(self, addr, data, dasm):
		super(BadLLVMInstr, self).__init__(addr, data, dasm)

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

	
class GoodLLVMInstr(LLVMInstr):

	def __init__(self, addr, data, llvminst, dasm):
		self.llvminst = llvminst
		super(GoodLLVMInstr, self).__init__(addr, data, dasm)
		
	def __str__(self):
		return str(self.llvminst).strip()

	def nop(self):
		'''
		i cant seem to find a way to get llvm to report
		whether an instruction is a nop. this will probably
		miss more nops than i would like, but i cant think
		of anything to improve it. ultimately, mistaking a
		nop for a real instruction isnt that destructive to
		finding gadgets, so its ok.
		'''

		reg = 'noo?p(?: |$)'
		return self.match_regexp(reg)

	def has_uncond_ctrl_flow(self):
		return self.llvminst.is_uncond_branch() \
					or self.ret() \
					or self.llvminst.is_call()

	def has_cond_ctrl_flow(self):
		return self.llvminst.is_cond_branch()

	def bad(self):
		return isinstance(self.llvminst, llvm.mc.BadInstr)

	def ret(self):
		return self.llvminst.is_return()

	def jmp_reg_uncond(self):
		return self.llvminst.is_uncond_branch() \
					and llvminst.is_indirect_branch()

	def call_reg(self):
		return self.llvminst.is_call() \
				and self.llvminst.operands()[0].is_reg()

class LLVMDasm(Disassembler):

	def __init__(self, llvmdasm, arch):
		self.llvmdasm = llvmdasm
		self.arch
		
	def decode(self, addr, data):
		if not isinstance(data, tuple):
			raise TypeError("expected tuple of integers for data, got %s" % type(data))

		str_data = "".join([chr(x) for x in data])
		for (addr, data, llvminst) in self.llvmdasm.decode(str_data, addr):
			if llvminst is None:
				yield BadLLVMInstr(addr, data, self)
			else:
				yield GoodLLVMInstr(addr, data, llvminst, self)
				
	def arch(self):
		return self.arch
		

def new(arch):

	tm = None
	if arch == sefi.arch.x86:
		tm = TargetMachine.x86()
	elif arch == sefi.arch.x86_64:
		tm = TargetMachine.x86_64()
	elif arch == sefi.arch.arm:
		tm = TargetMachine.arm()
	elif arch == sefi.arch.thumb1:
		tm = TargetMachine.thumb()
	else:
		tm = TargetMachine.lookup(arch)

	if not tm:
		raise ArchNotSupported("llvm does not recognize " + \
								"architecture %s" % arch)
	
	try:
		llvmdasm = llvm.mc.Disassembler(tm)
	except llvm.LLVMException as e:
		raise ArchNotSupported("llvm does not have a " + \
								"disassembler for %s" % arch)

	return LLVMDasm(llvmdasm, arch)
	

