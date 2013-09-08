import argparse
import sys
import os.path
import re

from sefi.log import debug, info
import sefi.container
import sefi.matcher
import sefi.arch
import sefi.disassembler
from sefi import elf

def search_data_for_byte_seq(segments, byte_seq, backward_search):
	bs_len = len(byte_seq)

	for segment in segments:
		debug('search %d bytes starting at 0x%08x' % (len(segment.data), segment.base_addr))

		for i in range(0, len(segment.data)):
			buffer = segment.data[i:(i+bs_len)]
			if buffer == byte_seq:
				for gadget in backward_search(byte_seq, segment, i):
					yield gadget

def search_data(segments, matcher, arch, backward_search):

	dasm = sefi.disassembler.find(arch)
	for segment in segments:
		debug('search %d bytes starting at 0x%08x' % (len(segment.data), segment.base_addr))

		for i in range(0, len(segment.data)):
			iseq = sefi.container.InstSeq(
				segment.base_addr+i,
				segment.data[i:(i+32)], #ive heard maximum x86 len is 15, but im not sure
				dasm
			)

			if matcher(iseq):
				for gadget in backward_search(iseq[0:1], matcher, segment, i):
					yield gadget

def backward_search_n_from_byte_seq(byte_seq, segment, offset, arch, n):
	dasm = sefi.disassembler.find(arch)

	return backward_search_n(
		sefi.container.InstSeq(
			segment.base_addr+offset,
			byte_seq, 
			dasm
		),
		None, segment, offset, n
	)

def backward_search_n(iseq, matcher, segment, offset, n):
	bs_len = len(iseq.data)
	base_addr = segment.base_addr+offset
	gadgets = []
	is_len = len(iseq)
	dasm = iseq.dasm

	if is_len < 1:
		raise Exception("invalid instruction sequence: %r" % iseq)

	debug("backward search from 0x%08x for sequences ending in %s" % (base_addr, iseq) )

	for i in range(1, n+1):
		data = segment.data[(offset-i):(offset+bs_len)]
		new_seq = sefi.container.InstSeq(base_addr-i, data, dasm)
		ns_len = len(new_seq)

		if ns_len <= is_len:
			continue

		#prefix is the gadget terminator at the END of the sequence
		prefix = new_seq[-is_len:]
		#if the prefix is not the same as the iseq we are looking for 
		#(a gadget terminator like "ret"), then skip this offset
		if not iseq.proc_equal(prefix):
			continue

		#sometimes the prefix we are looking for can be encoded
		#in equivalent ways. in some cases the prefix will in fact
		#be longer than the original @byte_seq that we used to
		#prototype it. in this case we have to correct the offset
		#of the prefix from the base address of the gadget.
		real_prefix_offset = i + bs_len - len(prefix.data)
		g = sefi.container.Gadget(base_addr - i, data, dasm, real_prefix_offset)

		#if we find the same sequence preceding this one
		#we should have already looked at that so we can stop here
		if g.suffix().proc_equal(iseq):
			break

		if matcher:
			#besides finding the exact same prefix repeated, we might
			#also find another prefix/terminator which also matches,
			#in which case we should have already found that sequence so
			#we can stop here.
			if matcher(g.suffix()):
				break

			if not matcher.allow_uncond_flow():
				if g.suffix().has_uncond_ctrl_flow():
					continue

			if not matcher.allow_cond_flow():
				if g.suffix().has_cond_ctrl_flow():
					continue

		#a gadget with a ret in the middle wont be
		#useful
		if g.suffix().test_for(lambda ins: ins.ret()):
			continue

		if g.has_bad_ins():
			#debug("found bad instruction, skipping...")
			continue

		cg = g.compact()
		if cg is not None:
			gadgets.append(cg)
			#debug("found gadget: %s\n%r" % (
			#	map(lambda b: "%02x" % ord(b), cg.data),
			#	cg
			#))
		else:
			pass #debug("compacted gadget was empty: \n%r" % g)

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
		#debug(" => return %r" % list(map(lambda iseq: iseq.str_seq(), gadgets)) )
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

def search_elf_for_gadgets(io, backward_search_amt, matcher):
	elf_o, arch = elf.open(io)
	
	backward_search = lambda seq, matcher, seg, offset: \
		backward_search_n(seq, matcher, seg, offset, backward_search_amt)

	return search_data(elf.executable_data(elf_o), matcher, arch, backward_search)
	
