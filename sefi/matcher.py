

class Matcher(object):

	def __call__(self, *args):
		return self.match(*args)

	def match(self, inst_seq):
		raise Exception("not implemented")


class AllRets(Matcher):
	pass

class JmpRetUncond(Matcher):
	pass

class CallReg(Matcher):
	pass


		
