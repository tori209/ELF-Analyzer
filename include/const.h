#define OPT_IDENT	(1U << 0)
#define OPT_EHDR	(1U << 1)
#define OPT_SHDR	(1U << 2)
#define OPT_PHDR	(1U << 3)
#define OPT_SYMS	(1U << 4)
#define OPT_RELRO	(1U << 5)
#define OPT_NOTE	(1U << 6)
#define OPT_DYN		(1U << 7)
#define OPT_NHDR	(1U << 8)

#define EHDR_NAMEGAP 28
#define SHDR_NAMEGAP 28
#define PHDR_NAMEGAP 28
#define SYMS_NAMEGAP 28

#define STRTAB_ENTRY_MAX 32768
