import argparse
import sys
import os.path
import re

from sefi.log import debug, info
import sefi.container
import sefi.mnemonic

import distorm3
import pytrie

class UnsupportedArch(Exception):
	pass

def search_data_for_byte_seq(segments, byte_seq, backward_search):
	bs_len = len(byte_seq)

	for segment in segments:
		debug('search %d bytes starting at 0x%08x' % (len(segment.data), segment.base_addr))

		for i in range(0, len(segment.data)):
			buffer = segment.data[i:(i+bs_len)]
			if buffer == byte_seq:
				for gadget in backward_search(byte_seq, segment, i):
					yield gadget

def search_data(segments, regexp, arch, backward_search):

	for segment in segments:
		debug('search %d bytes starting at 0x%08x' % (len(segment.data), segment.base_addr))

		for i in range(0, len(segment.data)):
			iseq = sefi.container.InstSeq(
				segment.base_addr+i,
				segment.data[i:(i+32)], #ive heard maximum x86 len is 15, but im not sure
				arch
			)
			match = re.search(regexp, iseq.str_seq()[0], flags = re.IGNORECASE)

			if match is not None:
				for gadget in backward_search(iseq[0], regexp, segment, i):
					yield gadget

def backward_search_n_from_byte_seq(byte_seq, segment, offset, arch, n):
	return backward_search_n(
		sefi.container.InstSeq(
			segment.base_addr+offset,
			byte_seq, 
			arch
		),
		None, segment, offset, arch, n
	)

def backward_search_n(iseq, regexp, segment, offset, arch, n):
	bs_len = len(iseq.data)
	base_addr = segment.base_addr+offset
	gadgets = []
	is_len = len(iseq)

	if is_len < 1:
		raise Exception("invalid instruction sequence: %r" % iseq)

	debug("backward search from 0x%08x for sequences ending in %s" % (base_addr, iseq) )

	for i in range(1, n+1):
		data = segment.data[(offset-i):(offset+bs_len)]
		new_seq = sefi.container.InstSeq(base_addr-i, data, arch)
		ns_len = len(new_seq)

		if ns_len <= is_len:
			continue

		prefix = new_seq[-is_len:]
		if iseq.proc_equal(prefix):
			if ns_len >= 2*is_len:
				subseq = new_seq[:is_len]
				#if we find the same sequence preceding this one
				#we should have already looked at that so we can stop here
				if iseq.proc_equal(subseq):
					break 
				if regexp and subseq.match_regexp([regexp]):
					break

			#sometimes the prefix we are looking for can be encoded
			#in equivalent ways. in some cases the prefix will in fact
			#be longer than the original @byte_seq that we used to
			#prototype it. in this case we have to correct the offset
			#of the prefix from the base address of the gadget.
			real_prefix_offset = i + bs_len - len(prefix.data)
			g = sefi.container.Gadget(base_addr - i, data, arch, real_prefix_offset)

			if g.has_bad_ins():
				#debug("found bad instruction, skipping...")
				continue

			cg = g.compact()
			if cg is not None:
				gadgets.append(cg)
			else:
				debug("compacted gadget was empty: \n%r" % g)

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

def search_elf_for_gadgets(io, backward_search_amt, regexp):
	from elftools.elf.elffile import ELFFile
	import sefi.elf

	elf_o = ELFFile(io)
	info('parsed elf file with %s sections and %s segments' % 
		(elf_o.num_sections(), elf_o.num_segments())
	)
	arch = elf_o.get_machine_arch()
	if arch == "x64":
		dec_size = distorm3.Decode64Bits
		info('  elf file arch is x86-64')
	elif arch == "x86":
		dec_size = distorm3.Decode32Bits
		info('  elf file arch is x86')
	else:
		raise UnsupportedArch("unsupported architecture: %r" % arch)
	
	backward_search = lambda seq, regexp, seg, offset: \
		backward_search_n(seq, regexp, seg, offset, dec_size, backward_search_amt)

	return search_data(elf_executable_data(elf_o), regexp, dec_size, backward_search)
	
def search_elf_for_ret_gadgets(io, backward_search_amt):
	return search_elf_for_gadgets(
		io, backward_search_amt, 
		sefi.mnemonic.RET_ALL
	)

def search_elf_for_jmp_reg_gadgets(io, backward_search_amt):
	return search_elf_for_gadgets(
		io, backward_search_amt, 
		sefi.mnemonic.JMP_REG_UNCOND
	)

def search_elf_for_call_reg_gadgets(io, backward_search_amt):
	return search_elf_for_gadgets(
		io, backward_search_amt, 
		sefi.mnemonic.CALL_REG_ALL
	)

def elf_executable_data(elf_o):

	xsegs = sefi.elf.x_segments(elf_o)
	for segments in sefi.elf.segment_data(elf_o, xsegs):
		yield segments


	
