import distorm3

RET_ALL = "^RETF?( |$)"

JMP_NAMES = [
	'JO', 	'JNO', 	'JS', 	'JNS', 	'JE', 	'JZ',
	'JNE', 	'JNZ',	'JB',	'JNAE',	'JC',	'JNB',
	'JAE',	'JNC', 	'JBE',	'JNA', 	'JA',	'JNBE',
	'JL',	'JNGE',	'JGE',	'JNL',	'JLE',	'JNG',
	'JG',	'JNLE',	'JP',	'JPE',	'JNP',	'JPO',
	'JCXE',	'JECXZ', 'JMP'
]

REGISTER_NAMES = filter(
	lambda str: len(str) > 0,
	distorm3.Registers
)

JMP_REG_FMT = "^(%%s) .*(%s).*" % (
	"|".join(REGISTER_NAMES)
)

JMP_REG_ALL = JMP_REG_FMT % ("|".join(JMP_NAMES))
JMP_REG_UNCOND = JMP_REG_FMT % ('JMP')

