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
from err import SefiErr

class ArchErr(SefiErr):
	pass

class UnknownElfArch(ArchErr):
	pass

arches = []

def add_arch(arch):
	arches.append(arch)
	return arch

x86 	= add_arch("x86")
x86_64 	= add_arch("x86-64")
arm		= add_arch("arm")
thumb1	= add_arch("thumb")
thumb2	= add_arch("thumb2")
mips	= add_arch("mips")

def from_elf_machine_arch(machine_arch):
	ma = machine_arch.strip()
	if ma == "x64":
		return x86_64
	elif ma == "x86":
		return x86
	elif ma == "ARM":
		return arm
	else:
		for arch in arches:
			if arch == ma:
				return arch

	raise UnknownElfArch("unknown elf arch %r" % (ma))
