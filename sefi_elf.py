import sys

from elftools.elf.constants import P_FLAGS
from elftools.construct.lib.container import Container
from interval import IntervalSet, Interval

from sefi_log import log

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
	i_set = IntervalSet.between(0, 0)
	count = 0

	for xs in xsegs:
		log('  %s(0x%x..0x%x)' % (xs['p_type'], xs['p_vaddr'], xs['p_vaddr']+xs['p_memsz']))
		if xs['p_filesz'] < 1:
			log('    segment is empty. skip it.')
			continue

		i_set = i_set | IntervalSet.between(xs['p_offset'], xs['p_offset'] + xs['p_filesz'])

	log('executable data interval %r' % i_set)
		
	for ivl in i_set:
		print repr(ivl)
		if ivl.__class__.__name__ != "Interval":
			continue
		if (ivl.upper_bound - ivl.lower_bound) < 1:
			continue

		elf_o.stream.seek(ivl.lower_bound)
		bdata = elf_o.stream.read(ivl.upper_bound-ivl.lower_bound)
		yield bdata
		count += 1

	if count < 1:
		log('didnt find any executable data in which to search for instructions. ' + \
				'if you see this message and you are sure you provided a normal ' + \
				'elf file, then this is probably a bug.')
		