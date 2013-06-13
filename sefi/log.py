import logging

log_obj = logging.getLogger()
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
log_obj.addHandler(ch)

def isverbose():
	global ch
	return (ch.level == logging.DEBUG)

def set_verbose():
	global ch
	ch.setLevel(logging.DEBUG)
	
def set_quiet():
	global ch
	ch.setLevel(logging.ERROR)

def debug(str):
	global ch
	if ch.level == logging.DEBUG:
		if hasattr(str, '__call__'):
			str = str()

		print str

