
log_obj = None

def set_logger(logger):
	global log_obj
	#print "set logger to %r at level %d" % (logger, logger.level)
	log_obj = logger

def get_logger():
	global log_obj
	return log_obj

def debug(str):
	global log_obj
	#print("log_obj: %r(%d)" % (log_obj, log_obj.level))
	if log_obj:
		return log_obj.debug(str)
	else:
		return None

def info(str):
	global log_obj
	if log_obj:
		return log_obj.info(str)
	else:
		return None

def warning(str):
	global log_obj
	if log_obj:
		return log_obj.warning(str)
	else:
		return None

