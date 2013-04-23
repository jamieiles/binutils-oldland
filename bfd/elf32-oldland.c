#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"
#include "elf-bfd.h"
#include "elf/oldland.h"
#include "libiberty.h"

static reloc_howto_type oldland_elf_howto_table[] = {
	HOWTO(R_OLDLAND_NONE,		/* type */
	      0,			/* rightshift */
	      2,			/* size (0 = byte, 1 = short, 2 = long) */
	      32,			/* bitsize */
	      FALSE,			/* pc relative */
	      0,			/* bitpos */
	      complain_overflow_bitfield, /* complain_on_overflow */
	      bfd_elf_generic_reloc,	/* special function */
	      "R_OLDLAND_NONE",		/* name */
	      FALSE,			/* partial inplace */
	      0,			/* src mask */
	      0,			/* dst mask */
	      FALSE),			/* pcrel_offset */
	HOWTO(R_OLDLAND_32,		/* type */
	      0,			/* rightshift */
	      2,			/* size (0 = byte, 1 = short, 2 = long) */
	      32,			/* bitsize */
	      FALSE,			/* pc relative */
	      0,			/* bitpos */
	      complain_overflow_bitfield, /* complain_on_overflow */
	      bfd_elf_generic_reloc,	/* special function */
	      "R_OLDLAND_32",		/* name */
	      FALSE,			/* partial inplace */
	      0x0,			/* src mask */
	      0xffffffff,		/* dst mask */
	      FALSE),			/* pcrel_offset */
	HOWTO(R_OLDLAND_PC24,		/* type */
	      2,			/* rightshift */
	      2,			/* size (0 = byte, 1 = short, 2 = long) */
	      24,			/* bitsize */
	      TRUE,			/* pc relative */
	      0,			/* bitpos */
	      complain_overflow_signed, /* complain_on_overflow */
	      bfd_elf_generic_reloc,	/* special function */
	      "R_OLDLAND_PC24",		/* name */
	      FALSE,			/* partial inplace */
	      0x0,			/* src mask */
	      0x00ffffff,		/* dst mask */
	      TRUE),			/* pcrel_offset */
	HOWTO(R_OLDLAND_PC16,		/* type */
	      0,			/* rightshift */
	      2,			/* size (0 = byte, 1 = short, 2 = long) */
	      16,			/* bitsize */
	      TRUE,			/* pc relative */
	      10,			/* bitpos */
	      complain_overflow_signed, /* complain_on_overflow */
	      bfd_elf_generic_reloc,	/* special function */
	      "R_OLDLAND_PC16",		/* name */
	      FALSE,			/* partial inplace */
	      0x0,			/* src mask */
	      0x03fffc00,		/* dst mask */
	      TRUE),			/* pcrel_offset */
	HOWTO(R_OLDLAND_HI16,		/* type */
	      16,			/* rightshift */
	      2,			/* size (0 = byte, 1 = short, 2 = long) */
	      16,			/* bitsize */
	      FALSE,			/* pc relative */
	      10,			/* bitpos */
	      complain_overflow_dont,	/* complain_on_overflow */
	      bfd_elf_generic_reloc,	/* special function */
	      "R_OLDLAND_HI16",		/* name */
	      FALSE,			/* partial inplace */
	      0x0,			/* src mask */
	      0x3fffc00,		/* dst mask */
	      FALSE),			/* pcrel_offset */
	HOWTO(R_OLDLAND_LO16,		/* type */
	      0,			/* rightshift */
	      2,			/* size (0 = byte, 1 = short, 2 = long) */
	      16,			/* bitsize */
	      FALSE,			/* pc relative */
	      10,			/* bitpos */
	      complain_overflow_dont,	/* complain_on_overflow */
	      bfd_elf_generic_reloc,	/* special function */
	      "R_OLDLAND_LO16",		/* name */
	      FALSE,			/* partial inplace */
	      0x0,			/* src mask */
	      0x3fffc00,		/* dst mask */
	      FALSE),			/* pcrel_offset */
	HOWTO(R_OLDLAND_16,		/* type */
	      0,			/* rightshift */
	      1,			/* size (0 = byte, 1 = short, 2 = long) */
	      16,			/* bitsize */
	      FALSE,			/* pc relative */
	      10,			/* bitpos */
	      complain_overflow_dont,	/* complain_on_overflow */
	      bfd_elf_generic_reloc,	/* special function */
	      "R_OLDLAND_16",		/* name */
	      FALSE,			/* partial inplace */
	      0x0,			/* src mask */
	      0x3fffc00,		/* dst mask */
	      FALSE),			/* pcrel_offset */
};

static const struct reloc_map {
	bfd_reloc_code_real_type bfd_reloc_val;
	unsigned int oldland_reloc_val;
} oldland_reloc_map[] = {
	{ BFD_RELOC_NONE,	R_OLDLAND_NONE },
	{ BFD_RELOC_32,		R_OLDLAND_32 },
	{ BFD_RELOC_24_PCREL,	R_OLDLAND_PC24 },
	{ BFD_RELOC_16_PCREL,	R_OLDLAND_PC16 },
	{ BFD_RELOC_HI16,	R_OLDLAND_HI16 },
	{ BFD_RELOC_LO16,	R_OLDLAND_LO16 },
	{ BFD_RELOC_16,		R_OLDLAND_16 },
};

static reloc_howto_type *
oldland_reloc_type_lookup(bfd *abfd ATTRIBUTE_UNUSED,
			  bfd_reloc_code_real_type code)
{
	unsigned int m;
	const struct reloc_map *rm;

	for (m = 0, rm = &oldland_reloc_map[0];
	     m < ARRAY_SIZE(oldland_reloc_map); ++m, ++rm)
		if (rm->bfd_reloc_val == code)
			return &oldland_elf_howto_table[rm->oldland_reloc_val];

	return NULL;
}

static reloc_howto_type * oldland_reloc_name_lookup(bfd *abfd ATTRIBUTE_UNUSED,
						    const char *r_name)
{
	unsigned int m;

	for (m = 0; m < ARRAY_SIZE(oldland_elf_howto_table); ++m)
		if (!strcasecmp(oldland_elf_howto_table[m].name, r_name))
			return &oldland_elf_howto_table[m];

	return NULL;
}

static void oldland_info_to_howto_rela(bfd *abfd ATTRIBUTE_UNUSED,
				       arelent *cache_ptr,
				       Elf_Internal_Rela *dst)
{
	unsigned int r_type = ELF32_R_TYPE(dst->r_info);

	BFD_ASSERT(r_type < (unsigned int)R_OLDLAND_max);
	cache_ptr->howto = &oldland_elf_howto_table[r_type];
}

static bfd_reloc_status_type
oldland_final_link_relocate(reloc_howto_type *howto, bfd *input_bfd,
			    asection *input_section, bfd_byte *contents,
			    Elf_Internal_Rela *rel, bfd_vma relocation)
{
	return _bfd_final_link_relocate(howto, input_bfd, input_section,
					contents, rel->r_offset, relocation,
					rel->r_addend);
}

static bfd_boolean
oldland_elf_relocate_section(bfd *output_bfd, struct bfd_link_info *info,
			     bfd *input_bfd, asection *input_section,
			     bfd_byte *contents, Elf_Internal_Rela *relocs,
			     Elf_Internal_Sym *local_syms,
			     asection **local_sections)
{
	Elf_Internal_Shdr *symtab_hdr;
	struct elf_link_hash_entry **sym_hashes;
	Elf_Internal_Rela *rel;
	Elf_Internal_Rela *relend;

	symtab_hdr = &elf_tdata(input_bfd)->symtab_hdr;
	sym_hashes = elf_sym_hashes(input_bfd);
	relend     = relocs + input_section->reloc_count;

	for (rel = relocs; rel < relend; ++rel) {
		reloc_howto_type *howto;
		unsigned long r_symndx;
		Elf_Internal_Sym *sym;
		asection *sec;
		struct elf_link_hash_entry *h;
		bfd_vma relocation;
		bfd_reloc_status_type r;
		const char *name;
		int r_type;

		r_type = ELF32_R_TYPE(rel->r_info);
		r_symndx = ELF32_R_SYM(rel->r_info);
		howto  = oldland_elf_howto_table + r_type;
		h      = NULL;
		sym    = NULL;
		sec    = NULL;

		if (r_symndx < symtab_hdr->sh_info) {
			sym = local_syms + r_symndx;
			sec = local_sections [r_symndx];
			relocation = _bfd_elf_rela_local_sym(output_bfd, sym, &sec, rel);

			name = bfd_elf_string_from_elf_section
				(input_bfd, symtab_hdr->sh_link, sym->st_name);
			name = (name == NULL) ? bfd_section_name(input_bfd, sec) : name;
		} else {
			bfd_boolean unresolved_reloc, warned;

			RELOC_FOR_GLOBAL_SYMBOL(info, input_bfd, input_section, rel,
						 r_symndx, symtab_hdr, sym_hashes,
						 h, sec, relocation,
						 unresolved_reloc, warned);

			name = h->root.root.string;
		}

		if (sec != NULL && discarded_section(sec))
			RELOC_AGAINST_DISCARDED_SECTION(info, input_bfd, input_section,
							 rel, 1, relend, howto, 0, contents);

		if (info->relocatable)
			continue;

		r = oldland_final_link_relocate(howto, input_bfd, input_section,
						contents, rel, relocation);

		if (r != bfd_reloc_ok) {
			const char * msg = NULL;

			switch (r) {
			case bfd_reloc_overflow:
				r = info->callbacks->reloc_overflow
					(info, (h ? &h->root : NULL), name, howto->name,
					 (bfd_vma) 0, input_bfd, input_section, rel->r_offset);
				break;

			case bfd_reloc_undefined:
				r = info->callbacks->undefined_symbol
					(info, name, input_bfd, input_section, rel->r_offset,
					 TRUE);
				break;

			case bfd_reloc_outofrange:
				msg = _("internal error: out of range error");
				break;

			case bfd_reloc_notsupported:
				msg = _("internal error: unsupported relocation error");
				break;

			case bfd_reloc_dangerous:
				msg = _("internal error: dangerous relocation");
				break;

			default:
				msg = _("internal error: unknown error");
				break;
			}

			if (msg)
				r = info->callbacks->warning
					(info, msg, name, input_bfd, input_section, rel->r_offset);

			if (! r)
				return FALSE;
		}
	}

	return TRUE;
}

static asection *oldland_elf_gc_mark_hook (asection *sec,
					   struct bfd_link_info *info,
					   Elf_Internal_Rela *rel,
					   struct elf_link_hash_entry *h,
					   Elf_Internal_Sym *sym)
{
	return _bfd_elf_gc_mark_hook(sec, info, rel, h, sym);
}

static bfd_boolean oldland_elf_check_relocs (bfd *abfd,
					     struct bfd_link_info *info,
					     asection *sec,
					     const Elf_Internal_Rela *relocs)
{
	Elf_Internal_Shdr *symtab_hdr;
	struct elf_link_hash_entry **sym_hashes;
	const Elf_Internal_Rela *rel;
	const Elf_Internal_Rela *rel_end;

	if (info->relocatable)
		return TRUE;

	symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
	sym_hashes = elf_sym_hashes (abfd);

	rel_end = relocs + sec->reloc_count;
	for (rel = relocs; rel < rel_end; rel++) {
		struct elf_link_hash_entry *h = NULL;
		unsigned long r_symndx;

		r_symndx = ELF32_R_SYM(rel->r_info);
		if (r_symndx >= symtab_hdr->sh_info) {
			h = sym_hashes[r_symndx - symtab_hdr->sh_info];
			while (h->root.type == bfd_link_hash_indirect
			       || h->root.type == bfd_link_hash_warning)
				h = (struct elf_link_hash_entry *)h->root.u.i.link;
		}
	}

	return TRUE;
}

#define ELF_ARCH				bfd_arch_oldland
#define ELF_MACHINE_CODE			EM_OLDLAND
#define ELF_MAXPAGESIZE				0x1

#define TARGET_LITTLE_SYM          		bfd_elf32_oldland_vec
#define TARGET_LITTLE_NAME			"elf32-oldland"

#define elf_info_to_howto_rel			NULL
#define elf_info_to_howto			oldland_info_to_howto_rela
#define elf_backend_relocate_section		oldland_elf_relocate_section
#define elf_backend_gc_mark_hook		oldland_elf_gc_mark_hook
#define elf_backend_check_relocs                oldland_elf_check_relocs

#define elf_backend_can_gc_sections		1
#define elf_backend_rela_normal			1

#define bfd_elf32_bfd_reloc_type_lookup		oldland_reloc_type_lookup
#define bfd_elf32_bfd_reloc_name_lookup		oldland_reloc_name_lookup

#include "elf32-target.h"
