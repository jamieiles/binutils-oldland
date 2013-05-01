#include "sysdep.h"
#include <stdio.h>

#define STATIC_TABLE
#define DEFINE_TABLE

#include "opcode/oldland.h"
#include "dis-asm.h"

static const char *reg_names[8] = {
	"$r0", "$r1", "$r2", "$r3", "$r4", "$r5", "$fp", "$sp"
};

static inline unsigned int extract_field(unsigned int instr, unsigned int bitpos,
					 unsigned int length)
{
	return (instr >> bitpos) & ((1 << length) - 1);
}

static void print_operand(const struct oldland_operand *op, bfd_vma addr,
			  unsigned int instr, struct disassemble_info *info)
{
	int imm;
	fprintf_ftype fpr;
	void *stream;
	unsigned int m;

	imm = extract_field(instr, op->def.bitpos, op->def.length);
	stream = info->stream;
	fpr = info->fprintf_func;

	/* Sign extend. */
	if (op->pcrel)
		imm = (imm << (32 - op->def.length)) >> (32 - op->def.length);
	switch (op->type) {
	case OPERAND_IMM24:
		imm <<= 2;
	case OPERAND_IMM16PC:
		imm += addr;
		info->print_address_func((bfd_vma)imm, info);
		break;
	case OPERAND_IMM16:
		fpr(stream, "0x%x", imm);
		break;
	case OPERAND_RA:
	case OPERAND_RB:
	case OPERAND_RD:
		fpr(stream, "%s", reg_names[imm]);
		break;
	case OPERAND_INDEX:
		fpr(stream, "[");
		for (m = 0; m < op->meta.nr_ops; ++m) {
			print_operand(op->meta.ops[m], addr, instr, info);
			if (m != op->meta.nr_ops - 1)
				fpr(stream, ", ");
		}
		fpr(stream, "]");
		break;
	}
}

int print_insn_oldland(bfd_vma addr, struct disassemble_info *info)
{
	const struct oldland_instruction *opcode;
	int status;
	bfd_byte buffer[4];
	fprintf_ftype fpr;
	void *stream;
	unsigned int instr;
	unsigned int op_num;
	int use_second_op;

	stream = info->stream;
	fpr = info->fprintf_func;

	if ((status = info->read_memory_func(addr, buffer, 4, info)))
		goto err;
	instr = bfd_getl32(buffer);
	op_num = (instr >> 26) & 0xf;

	switch ((instr >> 30) & 0x3) {
	case 0x0:
		opcode = &oldland_instructions_0[op_num];
		break;
	case 0x1:
		opcode = &oldland_instructions_1[op_num];
		break;
	case 0x2:
		opcode = &oldland_instructions_2[op_num];
		break;
	case 0x3:
		opcode = &oldland_instructions_3[op_num];
		break;
	}

	if (!opcode->name) {
		fpr(stream, "undef");
		return 4;
	}

	fpr(stream, "%s\t", opcode->name);
	use_second_op = (opcode->formatsel >= 0) &&
		(instr & (1 << opcode->formatsel));

	if (opcode->nr_operands >= 1) {
		if (opcode->op1[1] && use_second_op)
			print_operand(opcode->op1[1], addr, instr, info);
		else
			print_operand(opcode->op1[0], addr, instr, info);
	}
	if (opcode->nr_operands >= 2) {
		fpr(stream, ", ");
		if (opcode->op2[1] && use_second_op)
			print_operand(opcode->op2[1], addr, instr, info);
		else
			print_operand(opcode->op2[0], addr, instr, info);
	}
	if (opcode->nr_operands == 3) {
		fpr(stream, ", ");
		if (opcode->op3[1] && use_second_op)
			print_operand(opcode->op3[1], addr, instr, info);
		else
			print_operand(opcode->op3[0], addr, instr, info);
	}

	return 4;

err:
	info->memory_error_func(status, addr, info);
	return -1;
}
