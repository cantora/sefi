#!/usr/bin/env python

import argparse
import sys
import os.path

from sofi_log import log
import sofi_log

def search_elf_for_ret_gadgets(io):
	return search_elf(io, [])

def search_elf(io, seq):
	from elftools.elf.elffile import ELFFile
	import sofi_elf

	eo = ELFFile(io)
	log('parsed elf file with %s sections and %s segments' % (eo.num_sections(), eo.num_segments()))

	xsegs = sofi_elf.x_segments(eo)
	for bytes in sofi_elf.segment_data(eo, xsegs):
		print('search %d bytes' % len(bytes))


	


	