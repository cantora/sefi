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

