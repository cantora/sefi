

class Matcher(object):

	def __init__(self, uncond_flow=True, cond_flow=True):
		self.uncond_flow = uncond_flow
		self.cond_flow = cond_flow

	def __call__(self, *args):
		return self.match(*args)

	def match(self, inst_seq):
		raise Exception("not implemented")

	def allow_uncond_flow(self):
		return self.uncond_flow

	def allow_cond_flow(self):
		return self.cond_flow

class REMatcher(Matcher):
	def __init__(self, reg):
		super(REMatcher, self).__init__()
		self.reg = reg

	def match(self, inst_seq):
		return inst_seq[0].match_regexp(self.reg)

class Rets(Matcher):
	def __init__(self):
		super(Rets, self).__init__()

	def match(self, inst_seq):
		return inst_seq[0].ret()

class JmpRegUncond(Matcher):
	def __init__(self):
		super(JmpRegUncond, self).__init__()

	def match(self, inst_seq):
		return inst_seq[0].jmp_reg_uncond()

class CallReg(Matcher):
	def __init__(self):
		super(CallReg, self).__init__()

	def match(self, inst_seq):
		return inst_seq[0].call_reg()

