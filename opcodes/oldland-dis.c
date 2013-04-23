#include "sysdep.h"
#include <stdio.h>

#define STATIC_TABLE
#define DEFINE_TABLE

#include "opcode/oldland.h"
#include "dis-asm.h"

static const char *reg_names[8] = {
	"$r0", "$r1", "$r2", "$r3", "$r4", "$r5", "$fp", "$sp"
};

static inline unsigned int instr_ra(unsigned int instr)
{
	return (instr >> 3) & 0x7;
}

static inline unsigned int instr_rb(unsigned int instr)
{
	return instr & 0x7;
}

static inline unsigned int instr_rd(unsigned int instr)
{
	return (instr >> 6) & 0x7;
}

static inline unsigned int instr_imm16(unsigned int instr)
{
	return (instr >> 10) & 0xffff;
}

static inline unsigned int instr_imm24(unsigned int instr)
{
	return instr & 0xffffff;
}

int print_insn_oldland(bfd_vma addr, struct disassemble_info *info)
{
	int status;
	const struct oldland_opc *opcode;
	bfd_byte buffer[4];
	fprintf_ftype fpr;
	void *stream;
	unsigned int instr;
	unsigned int op_num;
	unsigned int ra, rb, rd;
	unsigned int imm;

	stream = info->stream;
	fpr = info->fprintf_func;

	if ((status = info->read_memory_func(addr, buffer, 4, info)))
		goto err;
	instr = bfd_getl32(buffer);
	op_num = (instr >> 26) & 0xf;
	ra = instr_ra(instr);
	rb = instr_rb(instr);
	rd = instr_rd(instr);

	switch ((instr >> 30) & 0x3) {
	case OLDLAND_ARITHMETIC:
		opcode = &oldland_arith_opc[op_num];
		if (!opcode) {
			fpr(stream, "undef");
			break;
		}

		fpr(stream, "%s\t", opcode->name);
		if (instr & (1 << 9)) {
			fpr(stream, "%s, %s, %s", reg_names[rd],
			    reg_names[ra], reg_names[rb]);
		} else {
			imm = instr_imm16(instr);
			if (op_num == 0xa) {
				fpr(stream, "%s, ", reg_names[rd]);
				info->print_address_func((bfd_vma)imm, info);
			} else {
				fpr(stream, "%s, %s, ", reg_names[rd],
				    reg_names[ra]);
				info->print_address_func((bfd_vma)imm, info);
			}
		}

		break;
	case OLDLAND_BRANCH:
		opcode = &oldland_branch_opc[op_num];
		if (!opcode) {
			fpr(stream, "undef");
			break;
		}

		if (op_num == 0x1) {
			fpr(stream, "ret");
			break;
		}

		if (instr & (1 << 25)) {
			fpr(stream, "%s\t%s", opcode->name, reg_names[rb]);
		} else {
			imm = instr_imm24(instr);
			/*
			 * Sign extend the immediate and make it
			 * relative to the PC.
			 */
			imm = ((unsigned int)(((int)(imm << 8)) >> 8) << 2) +
				addr;
			fpr(stream, "%s\t", opcode->name);
			info->print_address_func((bfd_vma)imm, info);
		}

		break;
	case OLDLAND_LDR_STR:
		opcode = &oldland_ldr_str_opc[op_num];
		if (!opcode) {
			fpr(stream, "undef");
			break;
		}

		imm = instr_imm16(instr);
		if (instr & (1 << 9)) {
			/*
			 * Sign extend the immediate and make it
			 * relative to the PC.
			 */
			imm = (unsigned int)(((int)(imm << 16)) >> 16);
			imm += addr;

			fpr(stream, "%s\t%s, ", opcode->name,
			    (instr & (1 << 28)) ? reg_names[rb] : reg_names[rd]);
			info->print_address_func((bfd_vma)imm, info);
		} else {
			fpr(stream, "%s\t%s, [%s, 0x%x]", opcode->name,
			    (instr & (1 << 28)) ? reg_names[rb] : reg_names[rd],
			    reg_names[ra], imm);
		}

		break;
	default:
		fpr(stream, "undef");
		break;
	}

	return 4;

err:
	info->memory_error_func(status, addr, info);
	return -1;
}
