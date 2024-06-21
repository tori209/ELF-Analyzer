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
#include "util.h"

int ehdr64_read (int fd, Elf64_Ehdr * buf) {
	if (lseek(fd, 0, SEEK_SET) < 0) {  return -1;  }
	if (read(fd, buf, sizeof(Elf64_Ehdr)) < 0) {  return -1;  }
	return 0;
}

int shdr64_read (int fd, Elf64_Shdr * buf, int idx) {
	Elf64_Ehdr ehdr;
	ehdr64_read(fd, &ehdr);
	if (lseek(fd, ehdr.e_shoff + idx * ehdr.e_shentsize, SEEK_SET) < 0) {  return -1;  }
	if (read(fd, buf, ehdr.e_shentsize) < 0) {  return -1;  }
	return 0;
}

int ehdr64_print (int fd) {
	Elf64_Ehdr ehdr;
	Elf64_Shdr shdr;
	char * str_ptr;
	if (ehdr64_read(fd, &ehdr) < 0) {  return -1;  }
	if (shdr64_read(fd, &shdr, 0) < 0) {  return -1;  }

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
	// Too Much boring stuffs. skip.
	printf("%-*s: %d\n", EHDR_NAMEGAP, "Target Architecture Index", ehdr.e_machine);

	// ELF Header Size
	printf("%-*s: %d (bytes)\n", EHDR_NAMEGAP, "ELF Header Size", ehdr.e_ehsize);
	// ELF Version
	printf("%-*s: %d\n", EHDR_NAMEGAP, "ELF Version", ehdr.e_version); 

	// ELF Entry Point Offset
	printf("%-*s: 0x%lx\n", EHDR_NAMEGAP, "Entry Point Offset", ehdr.e_entry);

	// ELF Flags
	str_ptr = (char *)malloc(sizeof(char)*3*sizeof(Elf64_Word));
	bin_to_hex(&(ehdr.e_flags), str_ptr, sizeof(char)*3*sizeof(Elf64_Word));
	printf("%-*s: %s\n", EHDR_NAMEGAP, "Processor-Specific Flags", str_ptr);
	free(str_ptr);

	// Program Header Table Info.
	if (ehdr.e_phoff != 0) {
		printf("%-*s: 0x%lx / %ld (bytes)\n", EHDR_NAMEGAP, "Program Header Table Offset", ehdr.e_phoff, ehdr.e_phoff);
		printf("%-*s: %d (bytes)\n", EHDR_NAMEGAP, "  |-- Entry Size", ehdr.e_phentsize);
		if (ehdr.e_phnum == PN_XNUM) {
			printf("%-*s: %d\n", EHDR_NAMEGAP, "  |-- Entry Count", shdr.sh_info);
			printf("%-*s: %ld (bytes)\n", EHDR_NAMEGAP, "  |-- Total Size", (Elf64_Xword)ehdr.e_phentsize * shdr.sh_info);
		} else {
			printf("%-*s: %d\n", EHDR_NAMEGAP, "  |-- Entry Count", ehdr.e_phnum);
			printf("%-*s: %d (bytes)\n", EHDR_NAMEGAP, "  |-- Total Size", (Elf64_Word)ehdr.e_phentsize * ehdr.e_phnum);
		}
	} else {
		printf("%-*s: Not Exists\n", EHDR_NAMEGAP, "Program Header Table Offset");
	}

	// Section Header Table Info.
	if (ehdr.e_shoff != 0) {
		printf("%-*s: 0x%lx / %ld (bytes)\n", EHDR_NAMEGAP, "Section Header Table Offset", ehdr.e_shoff, ehdr.e_shoff);
		printf("%-*s: %d (bytes)\n", EHDR_NAMEGAP, "  |-- Entry Size", ehdr.e_shentsize);
		if (ehdr.e_shnum == 0) {
			printf("%-*s: %ld\n", EHDR_NAMEGAP, "  |-- Entry Count", shdr.sh_size);
			printf("%-*s: %ld (bytes)\n", EHDR_NAMEGAP, "  |-- Total Size", (Elf64_Xword) ehdr.e_shentsize * shdr.sh_size);
		} else {
			printf("%-*s: %d\n", EHDR_NAMEGAP, "  |-- Entry Count", ehdr.e_shnum);
			printf("%-*s: %d (bytes)\n", EHDR_NAMEGAP, "  |-- Total Size", (Elf64_Word) ehdr.e_shentsize * ehdr.e_shnum);
		}
	} else {
		printf("%-*s: Not Exists\n", EHDR_NAMEGAP, "Section Header Table Offset");
	}

	// String Table Offset
	printf("%-*s: %d\n", EHDR_NAMEGAP, "String Table Index", ehdr.e_shstrndx);
}

