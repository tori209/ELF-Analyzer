#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "util.h"
#include "const.h"
#include "elf_common.h"
#include "elf64.h"

int main(int argc, char* argv[]) {
	int fd;
	int opt;
	char * file_dir;
	unsigned int options = 0U;
	char e_ident[EI_NIDENT];
	
	file_dir = argv[argc-1];

	if (argc < 2) {
		fprintf(stderr, "Usage: %s [options] [filename]\n", argv[0]);
		exit (1);
	}

	if ((fd = open (file_dir, O_RDONLY)) < 0) {
		fprintf(stderr, "ERROR: %s\n", strerror(errno));
		exit(1);
	}

	if (!is_elf(fd)) {
		fprintf(stderr, "ERROR: %s is not ELF file.\n", file_dir);
		exit(1);
	}

	while ((opt = getopt(argc, argv, "iesprSnd")) != -1) {
		switch (opt) {
			case 'i':
				options |= OPT_IDENT;
				break;
			case 'e': // ELF Header
				options |= OPT_EHDR;
				break;
			case 'S': // Section Header
				options |= OPT_SHDR;
				break;
			case 'p': // Program Header
				options |= OPT_PHDR;
				break;
			case 's': // Symbol Table
				options |= OPT_SYMS;
				break;
			case 'r': // RELRO Entry
				options |= OPT_RELRO;
				break;
			case 'n': // Notes
				options |= OPT_NOTE;
				break;
			case 'd': // Dynamic Tags
				options |= OPT_DYN;
				break;
			case '?': // Unknown Options
			default: // Unknown Options
				fprintf(stderr, "ERROR: Unknown Option -%c.", opt);
				exit(1);
		}
	}

	if (read_ident(fd, e_ident) < 0) {
		fprintf(stderr, "ERROR: %s\n", strerror(errno));
		exit(1);
	}

	if ((options & OPT_IDENT) == OPT_IDENT) {
		printf("\nParsing ELF Identification... ================================\n");
		elfident_print(fd);
	}

	if ((options & OPT_EHDR) == OPT_EHDR) {
		printf("\nParsing ELF Header... ========================================\n");
		if (e_ident[EI_CLASS] == 1) {    }
		if (e_ident[EI_CLASS] == 2) { ehdr64_print(fd); }
	}

	if ((options & OPT_SHDR) == OPT_SHDR) {
		printf("\nParsing Section Header Table... ==============================\n");
		if (e_ident[EI_CLASS] == 1) {    }
		if (e_ident[EI_CLASS] == 2) { shdr64_print(fd); }
	}

	if ((options & OPT_PHDR) == OPT_PHDR) {
		printf("\nParsing Program Header Table... ==============================\n");
		if (e_ident[EI_CLASS] == 1) {    }
		if (e_ident[EI_CLASS] == 2) {  phdr64_print(fd);  }
	}

	if ((options & OPT_SYMS) == OPT_SYMS) {
		printf("\nParsing Symbol Tables... ==============================\n");
		if (e_ident[EI_CLASS] == 1) {    }
		if (e_ident[EI_CLASS] == 2) {  symbol64_print(fd);  }
	}
	
	if ((options & OPT_RELRO) == OPT_RELRO) {
		printf("\nParsing Relocation Entries... ==============================\n");
		if (e_ident[EI_CLASS] == 1) {    }
		if (e_ident[EI_CLASS] == 2) {  relro64_print(fd);  }
	}

	if ((options & OPT_DYN) == OPT_DYN) {
		printf("\nParsing Dynamic Tags... ==============================\n");
		if (e_ident[EI_CLASS] == 1) {    }
		if (e_ident[EI_CLASS] == 2) {    }
	}

	if ((options & OPT_NOTE) == OPT_NOTE) {
		printf("\nParsing Notes... ==============================\n");
		if (e_ident[EI_CLASS] == 1) {    }
		if (e_ident[EI_CLASS] == 2) {    }
	}

	close(fd);
	return 0;
}
