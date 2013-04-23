#include "sysdep.h"
#include "opcode/oldland.h"

const struct oldland_opc oldland_arith_opc[16] = {
	[0x0] = { 0x0, "add", OLDLAND_ARITHMETIC },
	[0x1] = { 0x1, "addc", OLDLAND_ARITHMETIC },
	[0x2] = { 0x2, "sub", OLDLAND_ARITHMETIC },
	[0x3] = { 0x3, "subc", OLDLAND_ARITHMETIC },
	[0x4] = { 0x4, "lsl", OLDLAND_ARITHMETIC },
	[0x5] = { 0x5, "lsr", OLDLAND_ARITHMETIC },
	[0x6] = { 0x6, "and", OLDLAND_ARITHMETIC },
	[0x7] = { 0x7, "xor", OLDLAND_ARITHMETIC },
	[0x8] = { 0x8, "bic", OLDLAND_ARITHMETIC },
	[0x9] = { 0x9, "or", OLDLAND_ARITHMETIC },
	[0xa] = { 0xa, "movhi", OLDLAND_ARITHMETIC },
	{ 0x0, "mov", OLDLAND_ARITHMETIC },
};

const struct oldland_opc oldland_branch_opc[16] = {
	[0x0] = { 0x0, "call", OLDLAND_BRANCH },
	[0x1] = { 0x1, "ret", OLDLAND_BRANCH },
	[0x4] = { 0x4, "b", OLDLAND_BRANCH },
	[0x5] = { 0x5, "bne", OLDLAND_BRANCH },
	[0x6] = { 0x6, "beq", OLDLAND_BRANCH },
	[0x7] = { 0x7, "bgt", OLDLAND_BRANCH },
};

const struct oldland_opc oldland_ldr_str_opc[16] = {
	[0x0] = { 0x0, "ldr32", OLDLAND_LDR_STR },
	[0x1] = { 0x1, "ldr16", OLDLAND_LDR_STR },
	[0x2] = { 0x2, "ldr8", OLDLAND_LDR_STR },
	[0x4] = { 0x4, "str32", OLDLAND_LDR_STR },
	[0x5] = { 0x5, "str16", OLDLAND_LDR_STR },
	[0x6] = { 0x6, "str8", OLDLAND_LDR_STR },
};
