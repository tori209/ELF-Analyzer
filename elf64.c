#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <elf.h>

#include "const.h"

int ehdr64_parser (int fd, Elf64_Ehdr * buf) {
	if (lseek(fd, 0, SEEK_SET) < 0) {
		fprintf(stderr, "ERROR: lseek failed / Reason: %s\n", strerror(errno));
		return -1;
	}

	if (read(fd, buf, sizeof(Elf64_Ehdr)) < 0) {
		fprintf(stderr, "ERROR: read failed / Reason: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

int ehdr64_print (int fd) {
	Elf64_Ehdr ehdr;
	char * str_ptr;
	if (ehdr64_parser(fd, &ehdr) < 0) {  return -1;  }

	// Object File Type
	switch (ehdr.e_type) {
		case ET_NONE:
			str_ptr = "File Type Undefined";
			break;
		case ET_REL:
			str_ptr = "Relocatable Object File";
			break;
		case ET_EXEC:
			str_ptr = "Executable File";
			break;
		case ET_DYN:
			str_ptr = "Shared Object File";
			break;
		case ET_CORE:
			str_ptr = "Core(Dump) File";
			break;
		default:
			if (ehdr.e_type >= ET_LOOS && ehdr.e_type <= ET_HIOS)
				str_ptr = "OS-Specific File";
			if (ehdr.e_type >= ET_LOPROC && ehdr.e_type <= ET_LOPROC)
				str_ptr = "Process-Specific File";
	}
	printf("%-*s: %s\n", EHDR_NAMEGAP, "Object File Type", str_ptr);
	
	// TODO: Architecture for ELF File
	printf("%-*s: %d\n", EHDR_NAMEGAP, "Target Architecture Index", ehdr.e_machine);

	// ELF Header Size
	printf("%-*s: %d (bytes)\n", EHDR_NAMEGAP, "ELF Header Size", ehdr.e_ehsize);
	// ELF Version
	printf("%-*s: %d\n", EHDR_NAMEGAP, "ELF Version", ehdr.e_version); 

	// ELF Entry Point Offset
	printf("%-*s: 0x%lx\n", EHDR_NAMEGAP, "Entry Point Offset", ehdr.e_entry);

	// Program Header Table Info.
	printf("%-*s: 0x%lx / %ld (bytes)\n", EHDR_NAMEGAP, "Program Header Table Offset", ehdr.e_phoff, ehdr.e_phoff);
	printf("%-*s: %d\n", EHDR_NAMEGAP, "  |-- Entry Count", ehdr.e_phnum);
	printf("%-*s: %d (bytes)\n", EHDR_NAMEGAP, "  |-- Entry Size", ehdr.e_phentsize);
	printf("%-*s: %d (bytes)\n", EHDR_NAMEGAP, "  |-- Total Size", ehdr.e_phentsize * ehdr.e_phnum);

	// Section Header Table Info.
	printf("%-*s: 0x%lx / %ld (bytes)\n", EHDR_NAMEGAP, "Section Header Table Offset", ehdr.e_shoff, ehdr.e_shoff);
	printf("%-*s: %d\n", EHDR_NAMEGAP, "  |-- Entry Count", ehdr.e_shnum);
	printf("%-*s: %d (bytes)\n", EHDR_NAMEGAP, "  |-- Entry Size", ehdr.e_shentsize);
	printf("%-*s: %d (bytes)\n", EHDR_NAMEGAP, "  |-- Total Size", ehdr.e_shentsize * ehdr.e_shnum);
}
