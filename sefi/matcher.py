

class Matcher(object):

	def __call__(self, *args):
		return self.match(*args)

	def match(self, inst_seq):
		raise Exception("not implemented")

class REMatcher(Matcher):
	def __init__(self, reg):
		self.reg = reg

	def match(self, inst_seq):
		return inst_seq[0].match_regexp(self.reg)

class Rets(Matcher):
	def match(self, inst_seq):
		return inst_seq[0].ret()

class JmpRegUncond(Matcher):
	def match(self, inst_seq):
		return inst_seq[0].jmp_reg_uncond()

class CallReg(Matcher):
	def match(self, inst_seq):
		return inst_seq[0].call_reg()

