#!/usr/bin/env python

import argparse
import sys
import os.path

from sefi_log import log
import sefi_log
import sefi_container

import distorm3

def search_data(segments, byte_seq, backward_search):
	bs_len = len(byte_seq)

	for segment in segments:
		log('search %d bytes starting at 0x%08x' % (len(segment.data), segment.base_addr))

		for i in range(0, len(segment.data)):
			buffer = segment.data[i:(i+bs_len)]
			if buffer == byte_seq:
				for gadget in backward_search(byte_seq, segment, i):
					yield gadget


def get_isn_seq(offset, data, arch):
	return map(
		lambda insn: insn[3],
		distorm3.Decode(offset,	data, arch)
	)

def ins_seqs_equal(a, b):
	for (x,y) in zip(a,b):
		if x != y:
			return False 

	return True

def backward_search_n(byte_seq, segment, offset, arch, n):
	bs_len = len(byte_seq)
	base_addr = segment.base_addr+offset

	if segment.data[offset:(offset+bs_len)] != byte_seq:
		raise Exception("expected %r == %r" % (segment.data[offset:(offset+bs_len)], byte_seq))

	iseq = get_isn_seq(base_addr, byte_seq, arch)
	is_len = len(iseq)

	if is_len < 1:
		raise Exception("invalid instruction sequence: %r" % byte_seq)

	log("backward search from 0x%08x for sequences ending in %r" % (base_addr, iseq))

	for i in range(1, n+1):
		data = segment.data[(offset-i):((offset-i)+bs_len+i)]
		new_seq = get_isn_seq(base_addr-i, data, arch)

		if len(new_seq) <= is_len:
			continue

		if ins_seqs_equal(new_seq[-is_len:], iseq):
			#log("  found %r" % new_seq)
			yield sefi_container.Gadget(
				byte_seq, base_addr,
				i, data, arch
			)

def search_elf_for_ret_gadgets(io, seq):
	backward_search = lambda seq, seg, offset: \
		backward_search_n(seq, seg, offset, distorm3.Decode64Bits, 20)

	return search_data(elf_executable_data(io), seq, backward_search)

def elf_executable_data(io):
	from elftools.elf.elffile import ELFFile
	import sefi_elf

	eo = ELFFile(io)
	log('parsed elf file with %s sections and %s segments' % (eo.num_sections(), eo.num_segments()))

	xsegs = sefi_elf.x_segments(eo)
	for segments in sefi_elf.segment_data(eo, xsegs):
		yield segments

			
	