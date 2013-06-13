import argparse
import sys
import os.path
import re

from sefi.log import debug, info
import sefi.container

import distorm3
import pytrie

def search_data(segments, byte_seq, backward_search):
	bs_len = len(byte_seq)

	for segment in segments:
		debug('search %d bytes starting at 0x%08x' % (len(segment.data), segment.base_addr))

		for i in range(0, len(segment.data)):
			buffer = segment.data[i:(i+bs_len)]
			if buffer == byte_seq:
				for gadget in backward_search(byte_seq, segment, i):
					yield gadget


def str_seq_match_regexp(str_seq, regexps):
	for ins in str_seq:
		for reg in regexps:
			if re.search(reg, ins, flags = re.IGNORECASE) is not None:
				return True

	return False

def str_seq_has_bad_ins(str_seq, arch):
	common = [
		'^DB ',
		'^OUTS ',
		'^IN ',
		'^INS ',
		'^HLT$',
		'^RET ',
		'^RET$'
	]

	bad_ins = {
		distorm3.Decode32Bits: common,
		distorm3.Decode64Bits: common
	}

	return str_seq_match_regexp(str_seq, bad_ins[arch])

def backward_search_n(byte_seq, segment, offset, arch, n):
	bs_len = len(byte_seq)
	base_addr = segment.base_addr+offset
	gadgets = []

	if segment.data[offset:(offset+bs_len)] != byte_seq:
		raise Exception("expected %r == %r" % (segment.data[offset:(offset+bs_len)], byte_seq))

	iseq = sefi.container.InstSeq(base_addr, byte_seq, arch)
	is_len = len(iseq)

	if is_len < 1:
		raise Exception("invalid instruction sequence: %r" % byte_seq)

	debug("backward search from 0x%08x for sequences ending in %s" % (base_addr, iseq) )

	for i in range(1, n+1):
		data = segment.data[(offset-i):((offset-i)+bs_len+i)]
		new_seq = sefi.container.InstSeq(base_addr-i, data, arch)
		ns_len = len(new_seq)

		if ns_len <= is_len:
			continue

		prefix = new_seq[-is_len:]
		if iseq.proc_equal(prefix):
			if ns_len >= 2*is_len and \
					iseq.proc_equal(new_seq[:is_len]):
				#if we find the same sequence preceding this one
				#we should have already looked at that so we can stop here
				break 

			#only check instructions after the prefix (i.e. RET)
			if str_seq_has_bad_ins(new_seq.str_seq()[:-is_len], arch):
				#debug("found bad instruction, skipping...")
				continue
			
			#sometimes the prefix we are looking for can be encoded
			#in equivalent ways. in some cases the prefix will in fact
			#be longer than the original @byte_seq that we used to
			#prototype it. in this case we have to correct the offset
			#of the prefix from the base address of the gadget.
			real_prefix_offset = i + bs_len - len(prefix.data)
			gadgets.append(
				sefi.container.Gadget(base_addr - i, data, arch, real_prefix_offset)
			)

	for gadget in maximal_unique_gadgets(gadgets, []):
		yield gadget

def maximal_unique_gadgets(gadgets, prefix = []):
	next_pre = {}
	arr_len = len(gadgets)
	plen = len(prefix)

	#debug("maximal unique gadgets:")
	#debug("gadgets: ")
	#for g in gadgets:
	#	debug("  %r" % g.as_prefix()[plen:])
	#debug("prefix: %r" % prefix)

	if arr_len <= 1:
		#debug(" => return %r" % gadgets[0].str_seq())
		return gadgets

	for g in gadgets:
		g_seq = g.as_prefix()[plen:]
		if len(g_seq) < 1:
			continue

		head, tail = g_seq[0], g_seq[1:]
		if head not in next_pre:
			next_pre[head] = [g]
		else:
			next_pre[head].append(g)

	result = []
	for head, gadgets in next_pre.items():
		#debug("head:gadgets -> %r:%r\n" % (head, map(lambda g: g.as_prefix(), gadgets)) )
		result += maximal_unique_gadgets(gadgets, prefix + [head])
	
	return result
	
def search_elf_for_ret_gadgets(io):
	from elftools.elf.elffile import ELFFile
	import sefi.elf

	elf_o = ELFFile(io)
	info('parsed elf file with %s sections and %s segments' % (elf_o.num_sections(), elf_o.num_segments()))
	if elf_o.elfclass == 64:
		dec_size = distorm3.Decode64Bits
		info('  elf file arch is 64 bit')
	elif elf_o.elfclass == 32:
		dec_size = distorm3.Decode32Bits
		info('  elf file arch is 32 bit')
	else:
		raise sefi.elf.UnsupportedElfType("unknown elf class")
	
	backward_search = lambda seq, seg, offset: \
		backward_search_n(seq, seg, offset, dec_size, 20)

	return search_data(elf_executable_data(elf_o), "\xc3", backward_search)

def elf_executable_data(elf_o):

	xsegs = sefi.elf.x_segments(elf_o)
	for segments in sefi.elf.segment_data(elf_o, xsegs):
		yield segments


	
