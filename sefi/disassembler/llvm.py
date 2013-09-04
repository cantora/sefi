from sefi.disassembler import *
import sefi.arch

try:
	from llvm import mc
	from llvm import target
	import llvm
except Exception as e:
	raise LibNotFound("error loading llvm: %r" % e)

target.initialize_all()

class LLVMInstr(Instr):

	def __init__(self, addr, llvminst, dasm):
		super(LLVMInstr, self).__init__(addr, data, dasm)

		self.llvminst = llvminst
		
	def __str__(self):
		return str(llvminst).strip()

	def display(self):
		if self.dasm.arch == sefi.arch.x86_64:
			addr_fmt = "%016x"
		else:
			addr_fmt = "%08x"

		return self.internal_display(addr_fmt, str(self), "")


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
					or self.ret()

	def has_cond_ctrl_flow(self):
		return self.llvminst.is_cond_branch()

	def bad(self):
		return isinstance(self.llvminst, llvm.mc.BadInstr)

	def ret(self);
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
		for (addr, data, llvminst) in self.llvmdasm.decode(data, addr):
			yield LLVMInstr(addr, data, llvmisnt, dasm)
				
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
		llvmdasm = tm.disassembler()
	except llvm.LLVMException as e:
		raise ArchNotSupported("llvm does not have a " + \
								"disassembler for %s" % arch)

	return LLVMDasm(llvmdasm, arch)
	

