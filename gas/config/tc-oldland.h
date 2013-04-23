#ifndef __TC_OLDLAND_H__
#define __TC_OLDLAND_H__

#define TC_OLDLAND			1
#define TARGET_BYTES_BIG_ENDIAN		0
#define WORKING_DOT_WORD		1
#define TARGET_FORMAT			"elf32-oldland"
#define TARGET_ARCH			bfd_arch_oldland
#define md_undefined_symbol(NAME)	0
#define md_estimate_size_before_relax(A, B) \
	(as_fatal(_("estimate size\n")), 0)
#define md_convert_frag(B, S, F) \
	(as_fatal(_("convert_frag\n")), 0)
#define MD_PCREL_FROM_SECTION(FIX, SEC) \
	md_pcrel_from(FIX)
extern long md_pcrel_from(struct fix *f);
#define md_section_align(SECTION, SIZE)	SIZE

#endif /* __TC_OLDLAND_H__ */
