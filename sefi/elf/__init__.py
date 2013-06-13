import sys

from elftools.elf.constants import P_FLAGS
from elftools.construct.lib.container import Container

from sefi.interval import IntervalSet, Interval

from sefi.log import debug, info, warning
import sefi.container

def x_segments(elf_o):
	''' go through elf object and find the executable segments '''
	result = []

	for sg in elf_o.iter_segments():
		if not (sg['p_flags'] & P_FLAGS.PF_X):
			continue

		result.append(sg)

	return result

def sections(elf_o, segment):
	result = []

	for sx in elf_o.iter_sections():
		if segment.section_in_segment(sx):
			result.append(sx)

	return result

def cont_pp(cont, depth=0):
	for (k,v) in cont.__dict__.items():
		if isinstance(v, Container):
			print("%s%s:" % (" "*depth, k))
			cont_pp(v, depth+1)
		else:
			sys.stdout.write("%s%s: " % (" "*depth, k) )
			if isinstance(v, int):
				print("%s" % hex(v))
			else:
				print(repr(v))

def segment_data(elf_o, xsegs):
	i_set = None
	count = 0
	
	for xs in xsegs:
		info('  %s(0x%x..0x%x)' % (xs['p_type'], xs['p_vaddr'], xs['p_vaddr']+xs['p_memsz']))
		#cont_pp(xs, 2)
		if xs['p_filesz'] < 1:
			#i think this is the right thing to do with an empty segment, not sure though.
			info('    segment is empty on file. skip it.')
			continue
		if xs['p_filesz'] != xs['p_memsz']:
			warning("im not sure how to handle segments that have a different size in " + \
					"memory than in the file; this might be bug. skipping this section")
			continue

		#we add one to the interval so that contiguous segments will merge together
		#(IntervalSet only combines intervals that overlap by at least one point)
		#this means that for memory map purposes, the lower bound in inclusive and
		#the upper bound is not.
		ivl = IntervalSet.between(xs['p_vaddr'], xs['p_vaddr'] + xs['p_memsz'] + 1)
		if not i_set:
			i_set = ivl
		else:
			i_set = i_set | ivl

	debug('executable data interval %r' % i_set)
	sorted_xsegs = sorted(xsegs, key=lambda seg: seg['p_vaddr'])

	for ivl in i_set:
		debug(repr(ivl))
		ivl_sz = (ivl.upper_bound-1 - ivl.lower_bound)

		if ivl.__class__.__name__ != "Interval":
			continue
		if ivl_sz < 1:
			continue

		#this is trying to map the file bytes onto 
		#a buffer in the same configuration that will happen
		#at load time
		bdata = ""
		for xs in sorted_xsegs:
			if xs['p_vaddr'] < ivl.lower_bound:
				continue
			elif xs['p_vaddr'] >= ivl.upper_bound:
				break #the list is sorted

			sz = xs['p_filesz'] #equal to p_memsz by assertion above
			elf_o.stream.seek(xs['p_offset'])
			data = elf_o.stream.read(sz)
			start = xs['p_vaddr'] - ivl.lower_bound
			if start == len(bdata):
				bdata += data
			else:
				tmp = bdata[0:start] + data
				if start+sz < len(bdata):
					bdata = tmp + bdata[(start+sz):]
				else:
					bdata = tmp
			
			debug('bdata is %d bytes' % len(bdata))
				
		if len(bdata) != ivl_sz:
			raise Exception(
				"len(bdata) = %d != %d = ivl_sz" % (
					len(bdata),
					ivl_sz
				)
			)
		
		yield sefi.container.Segment(bdata, ivl.lower_bound)
		count += 1

	if count < 1:
		error('didnt find any executable data in which to search for instructions. ' + \
				'if you see this message and you are sure you provided a normal ' + \
				'elf file, then this is probably a bug.')
		
	