#include "as.h"
#include "safe-ctype.h"
#include "opcode/oldland.h"
#include "elf/oldland.h"
#include <stdint.h>

void md_operand(expressionS *op __attribute__((unused)))
{
}

const pseudo_typeS md_pseudo_table[] = {
	{0, 0, 0}
};

const char FLT_CHARS[] = "rRsSfFdDxXpP";
const char EXP_CHARS[] = "eE";

const char comment_chars[]        = "#";
const char line_separator_chars[] = ";";
const char line_comment_chars[]   = "#";

static struct hash_control *opcode_hash_control;

void md_begin(void)
{
	unsigned m;
	const struct oldland_instruction *opc;
	opcode_hash_control = hash_new();

	for (m = 0, opc = oldland_instructions_0;
	     m < ARRAY_SIZE(oldland_instructions_0); ++m, ++opc)
		if (opc->name)
			hash_insert(opcode_hash_control, opc->name, (char *)opc);
	for (m = 0, opc = oldland_instructions_1;
	     m < ARRAY_SIZE(oldland_instructions_1); ++m, ++opc)
		if (opc->name)
			hash_insert(opcode_hash_control, opc->name, (char *)opc);
	for (m = 0, opc = oldland_instructions_2;
	     m < ARRAY_SIZE(oldland_instructions_2); ++m, ++opc)
		if (opc->name)
			hash_insert(opcode_hash_control, opc->name, (char *)opc);
	for (m = 0, opc = oldland_instructions_3;
	     m < ARRAY_SIZE(oldland_instructions_3); ++m, ++opc)
		if (opc->name)
			hash_insert(opcode_hash_control, opc->name, (char *)opc);

	bfd_set_arch_mach(stdoutput, TARGET_ARCH, 0);
}

static char *parse_exp_save_ilp(char *s, expressionS *op)
{
	char *save = input_line_pointer;

	input_line_pointer = s;
	expression (op);
	s = input_line_pointer;
	input_line_pointer = save;

	return s;
}

static const char *reg_names[16] = {
	"$r0", "$r1", "$r2", "$r3", "$r4", "$r5", "$r6", "$r7",
	"$r8", "$r9", "$r10", "$r11", "$r12", "$fp", "$sp", "$lr",
};

static int is_register_operand(char *ptr)
{
	unsigned int m;

	for (m = 0; m < ARRAY_SIZE(reg_names); ++m)
		if (!strncmp(ptr, reg_names[m], strlen(reg_names[m])))
			return TRUE;

	return FALSE;
}

static int is_index_operand(char *ptr)
{
	return *ptr == '[';
}

static int parse_register_operand(char **ptr)
{
	char *s = *ptr;
	unsigned int m;

	for (m = 0; m < ARRAY_SIZE(reg_names); ++m)
		if (!strncmp(s, reg_names[m], 3)) {
			*ptr += 3;
			return (int)m;
		}

	as_bad(_("illegal register number"));
	ignore_rest_of_line();

	return -1;
}

enum operand_class {
	OP_CLASS_REGISTER,
	OP_CLASS_INDEX,
	OP_CLASS_IMMEDIATE,
};

static int parse_operand(const struct oldland_operand * const op[MAX_OP_TYPES],
			 char *p, char **op_end, unsigned int *instr,
			 struct oldland_instruction *opcode)
{
	enum operand_class op_class;
	int i;
	expressionS arg;

	while (ISSPACE(**op_end))
		++(*op_end);
	if (is_register_operand(*op_end))
		op_class = OP_CLASS_REGISTER;
	else if (is_index_operand(*op_end))
		op_class = OP_CLASS_INDEX;
	else
		op_class = OP_CLASS_IMMEDIATE;

	for (i = 0; i < 2 && op[i]; ++i) {
		const struct oldland_operand *opdef = op[i];
		unsigned int reloc_type;
		int pcrel, reg;

		switch (opdef->type) {
		case OPERAND_INDEX:
			if (op_class == OP_CLASS_INDEX) {
				unsigned int m;

				++(*op_end);
				for (m = 0; m < opdef->meta.nr_ops; ++m) {
					if (parse_operand(opdef->meta.ops, p,
							  op_end, instr, opcode))
						return -1;
					if (m != opdef->meta.nr_ops - 1) {
						if (**op_end != ',') {
							as_bad(_("expecting comma delimited operands\n"));
							return -1;
						}
						++(*op_end);
					}
				}
				if (**op_end != ']') {
					as_bad(_("expected terminating ]"));
					return -1;
				}
				goto out;
			}
			break;
		case OPERAND_IMM16PC:
		case OPERAND_IMM16:
		case OPERAND_IMM24:
		case OPERAND_IMM13PC:
		case OPERAND_IMM13:
			if (op_class == OP_CLASS_IMMEDIATE) {
				if (!strncmp(*op_end, "%hi(", 4)) {
					*op_end += 4;
					reloc_type = BFD_RELOC_HI16;
					pcrel = 0;
				} else if (!strncmp(*op_end, "%lo(", 4)) {
					*op_end += 4;
					reloc_type = BFD_RELOC_LO16;
					pcrel = 0;
				} else if (opdef->type == OPERAND_IMM24) {
					reloc_type = BFD_RELOC_24_PCREL;
					pcrel = 1;
				} else if (opdef->type == OPERAND_IMM16PC ||
					   opdef->type == OPERAND_IMM16) {
					reloc_type = opdef->type == OPERAND_IMM16PC ?
						BFD_RELOC_16_PCREL : BFD_RELOC_16;
					pcrel = opdef->type == OPERAND_IMM16PC;
				} else {
					reloc_type = opdef->type == OPERAND_IMM13PC ?
						BFD_RELOC_OLDLAND_PC13 :
						BFD_RELOC_OLDLAND_13;
					pcrel = opdef->type == OPERAND_IMM13PC;
				}
				*op_end = parse_exp_save_ilp(*op_end, &arg);
				fix_new_exp(frag_now,
					    (p - frag_now->fr_literal),
					    2, &arg, pcrel, reloc_type);

				if ((reloc_type == BFD_RELOC_LO16 ||
				     reloc_type == BFD_RELOC_HI16) &&
				    **op_end != ')') {
					as_bad(_("expected terminating )"));
					return -1;
				}

				goto out;
			}
			break;
		case OPERAND_RD:
		case OPERAND_RA:
		case OPERAND_RB:
			if (op_class == OP_CLASS_REGISTER) {
				reg = parse_register_operand(op_end);
				*instr |= reg << opdef->def.bitpos;
				goto out;
			}
			break;
		default:
			as_bad(_("bad operand class\n"));
			return -1;
		}
	}

	as_bad(_("failed to parse operand %s\n"), *op_end);
	return -1;

out:
	if (opcode->formatsel >= 0)
		*instr |= (i << opcode->formatsel);

	return 0;
}

void md_assemble(char *str)
{
	char *op_start, *op_end, *p;
	int nlen = 0;
	char pend;
	unsigned int instr;
	struct oldland_instruction *opcode;

	while (ISSPACE(*str))
		++str;

	op_start = str;
	for (op_end = str;
	     *op_end && !is_end_of_line[*op_end & 0xff] && !ISSPACE(*op_end);
	     ++op_end, ++nlen)
		continue;

	pend = *op_end;
	*op_end = 0;

	if (nlen == 0)
		as_bad(_("can't find opcode"));
	opcode = (struct oldland_instruction *)hash_find(opcode_hash_control, op_start);

	if (!opcode) {
		as_bad(_("unknown opcode %s"), op_start);
		return;
	}
	*op_end = pend;

	p = frag_more(4);

	instr = (opcode->class << 30) | (opcode->opcode << 26) |
		opcode->constbits;
	if (opcode->nr_operands >= 1) {
		if (parse_operand(opcode->op1, p, &op_end, &instr, opcode))
			return;
	}
	if (opcode->nr_operands >= 2) {
		while (ISSPACE(*op_end))
			++op_end;
		if (*op_end != ',')
			as_warn(_("expecting comma delimited operands"));
		++op_end;
		if (parse_operand(opcode->op2, p, &op_end, &instr, opcode))
			return;
	}
	if (opcode->nr_operands == 3) {
		while (ISSPACE(*op_end))
			++op_end;
		if (*op_end != ',')
			as_warn(_("expecting comma delimited operands"));
		++op_end;
		if (parse_operand(opcode->op3, p, &op_end, &instr, opcode))
			return;
	}

	number_to_chars_littleendian(p, instr, 4);

	while (*op_end && ISSPACE(*op_end))
		++op_end;
}

char *md_atof(int type, char *litP, int *sizeP)
{
	int prec;
	LITTLENUM_TYPE words[4];
	char *t;
	int i;

	switch (type) {
	case 'f':
		prec = 2;
		break;

	case 'd':
		prec = 4;
		break;

	default:
		*sizeP = 0;
		return _("bad call to md_atof");
	}

	t = atof_ieee(input_line_pointer, type, words);
	if (t)
		input_line_pointer = t;

	*sizeP = prec * 2;

	for (i = prec - 1; i >= 0; i--) {
		md_number_to_chars(litP, (valueT) words[i], 2);
		litP += 2;
	}

	return NULL;
}

static uint32_t read_instruction(char *val)
{
	uint32_t retval = 0;
	int n = 4, bitpos = 0;

	while (n--) {
		retval |= (*val++ & 0xff) << bitpos;
		bitpos += 8;
	}

	return retval;
}

void md_number_to_chars(char *ptr, valueT use, int nbytes)
{
	number_to_chars_littleendian(ptr, use, nbytes);
}

const char *md_shortopts = "";

struct option md_longopts[] = {
	{NULL, no_argument, NULL, 0}
};

size_t md_longopts_size = sizeof(md_longopts);

/* We have no target specific options yet, so these next
   two functions are empty.  */
int md_parse_option(int c ATTRIBUTE_UNUSED, char *arg ATTRIBUTE_UNUSED)
{
	return 0;
}

void md_show_usage(FILE *stream ATTRIBUTE_UNUSED)
{
}

long md_pcrel_from(fixS *fixP)
{
	return fixP->fx_where + fixP->fx_frag->fr_address + 4;
}

arelent *tc_gen_reloc(asection *section ATTRIBUTE_UNUSED, fixS *fixP)
{
	arelent *relP;
	bfd_reloc_code_real_type code;

	switch (fixP->fx_r_type)
	{
	case BFD_RELOC_24_PCREL:
	case BFD_RELOC_16_PCREL:
	case BFD_RELOC_OLDLAND_PC13:
		fixP->fx_offset -= 4;
	case BFD_RELOC_NONE:
	case BFD_RELOC_32:
	case BFD_RELOC_16:
	case BFD_RELOC_HI16:
	case BFD_RELOC_LO16:
	case BFD_RELOC_OLDLAND_13:
		code = fixP->fx_r_type;
		break;
	default:
		as_bad_where (fixP->fx_file, fixP->fx_line,
			      _("Semantics error.  This type of operand can not be relocated, it must be an assembly-time constant"));
		return 0;
	}

	relP = xmalloc (sizeof (arelent));
	gas_assert (relP != 0);
	relP->sym_ptr_ptr = xmalloc (sizeof (asymbol *));
	*relP->sym_ptr_ptr = symbol_get_bfdsym (fixP->fx_addsy);
	relP->address = fixP->fx_frag->fr_address + fixP->fx_where;
	relP->addend = fixP->fx_offset;

	relP->howto = bfd_reloc_type_lookup(stdoutput, code);
	if (!relP->howto) {
		const char *name = S_GET_NAME (fixP->fx_addsy);
		if (name == NULL)
			name = _("<unknown>");
		as_fatal (_("Cannot generate relocation type for symbol %s, code %s"),
			  name, bfd_get_reloc_code_name (code));
	}

	return relP;
}

void md_apply_fix(fixS *fixP ATTRIBUTE_UNUSED, valueT * valP ATTRIBUTE_UNUSED,
		  segT seg ATTRIBUTE_UNUSED)
{
	char *buf = fixP->fx_where + fixP->fx_frag->fr_literal;
	uint32_t instr;
	long val = *valP;

	switch (fixP->fx_r_type) {
	case BFD_RELOC_HI16:
		val >>= 16;
		/* Intentional fallthrough. */
	case BFD_RELOC_16:
		/* Intentional fallthrough. */
	case BFD_RELOC_LO16:
		instr = read_instruction(buf);
		instr |= (val & 0xffff) << 10;
		md_number_to_chars(buf, instr, 4);
		break;
	case BFD_RELOC_32:
		md_number_to_chars(buf, val, 4);
		break;
	case BFD_RELOC_24_PCREL:
		instr = read_instruction(buf);
		instr |= (val >> 2) & 0x00ffffff;
		md_number_to_chars(buf, instr, 4);
		break;
	case BFD_RELOC_16_PCREL:
		instr = read_instruction(buf);
		instr |= (val & 0xffff) << 10;
		md_number_to_chars(buf, instr, 4);
		break;
	case BFD_RELOC_OLDLAND_13:
	case BFD_RELOC_OLDLAND_PC13:
		instr = read_instruction(buf);
		instr |= (val & 0x1fff) << 12;
		md_number_to_chars(buf, instr, 4);
		break;
	default:
		abort();
	}

	if (!fixP->fx_addsy && !fixP->fx_pcrel)
		fixP->fx_done = 1;
}
