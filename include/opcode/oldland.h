#ifndef __OLDLAND_DIS_H__
#define __OLDLAND_DIS_H__

enum oldland_instr_class {
	OLDLAND_ARITHMETIC	= 0x0,
	OLDLAND_BRANCH		= 0x1,
	OLDLAND_LDR_STR		= 0x2,
};

struct oldland_opc {
	unsigned short		 opcode;
	const char		 *name;
	enum oldland_instr_class class;
};

extern const struct oldland_opc oldland_arith_opc[16];
extern const struct oldland_opc oldland_branch_opc[16];
extern const struct oldland_opc oldland_ldr_str_opc[16];

#endif /* __OLDLAND_DIS_H__ */
