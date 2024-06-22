#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <elf.h>

#include "util.h"
#include "const.h"
#include "elf64.h"

const char magic_str[5] = {0x7f, 'E', 'L', 'F', '\0'};
char e_ident[EI_NIDENT];
const char* osabi_strarr[256] = {};

void init () {
	for (int i = 0; i < 256; i++) {
		osabi_strarr[i] = "Unknown OSABI";
	}
	osabi_strarr[ELFOSABI_SYSV] = "UNIX System V ABI";
	osabi_strarr[ELFOSABI_HPUX] = "HP-UX";
	osabi_strarr[ELFOSABI_NETBSD] = "NetBSD";
	osabi_strarr[ELFOSABI_GNU] = "GNU/Linux";
	osabi_strarr[ELFOSABI_LINUX] = "GNU/Linux";
	osabi_strarr[ELFOSABI_SOLARIS] = "Solaris";
	osabi_strarr[ELFOSABI_AIX] = "IBM AIX";
	osabi_strarr[ELFOSABI_IRIX] = "SGI Irix";
	osabi_strarr[ELFOSABI_FREEBSD] = "FreeBSD";
	osabi_strarr[ELFOSABI_TRU64] = "Compaq TRU64 UNIX";
	osabi_strarr[ELFOSABI_MODESTO] = "Novell Modesto";
	osabi_strarr[ELFOSABI_OPENBSD] = "OpenBSD";
	osabi_strarr[ELFOSABI_ARM_AEABI] = "ARM EABI";
	osabi_strarr[ELFOSABI_ARM] = "ARM";
	osabi_strarr[ELFOSABI_STANDALONE] = "Standalone (embedded) application";
}

int elfid_parser (int fd) {
	int temp;
	char * str_ptr;

	if (read(fd, e_ident, EI_NIDENT) < 0) {
		fprintf(stderr, "ERROR: %s\n", strerror(errno));
		exit(1);
	}

	// Check whether given file is elf object file.
	temp = strncmp(e_ident, magic_str, 4);
	if (temp != 0) {
		fprintf(stderr, "ERROR: given file is not elf file.\n");
		exit(1);	
	} else if (temp < 0) {
		fprintf(stderr, "ERROR: %s\n", strerror(errno));
		exit(1);
	} else { 
		str_ptr = (char *)malloc(sizeof(char) * 3 * EI_NIDENT);
		bin_to_hex(e_ident, str_ptr, sizeof(char) * 3 * EI_NIDENT);
		printf("%-*s: %s\n", EHDR_NAMEGAP, "ELF Identification (Hex)", str_ptr);
		free (str_ptr);   
	}
	
    // Object File Class Type
	switch (e_ident[EI_CLASS]) {
		case ELFCLASSNONE:
			str_ptr = "Invalid File Class";
			break;
		case ELFCLASS32:
			str_ptr = "32bit Object File";
			break;
		case ELFCLASS64:
			str_ptr = "64bit Object File";
			break;
		default:
			str_ptr = "Unknown Class Object File";
	}

	printf("%-*s: %s\n", EHDR_NAMEGAP, "Object File Class", str_ptr);

	// Check Encoding Type
	switch (e_ident[EI_DATA]) {
		case ELFDATANONE:
			str_ptr = "Invalid Data Encoding";
			break;
		case ELFDATA2LSB:
			str_ptr = "Two's Complement, Little Endian";
			break;
		case ELFDATA2MSB:
			str_ptr = "Two's Complement, Big Endian";
			break;
		default:
			str_ptr = "Unknown Data Encoding";
			break;
	}
	printf("%-*s: %s\n", EHDR_NAMEGAP, "Data Encodinag Type", str_ptr);

	// Check OSABI
	printf("%-*s: %s\n", EHDR_NAMEGAP, "OS & ABI", osabi_strarr[e_ident[EI_OSABI]]);
	printf("%-*s: %d\n", EHDR_NAMEGAP, "ABI Version", e_ident[EI_ABIVERSION]);
}

int main(int argc, char* argv[]) {
	int fd;
	
	init();

	if (argc != 2) {
		fprintf(stderr, "Usage: %s [filename]\n", argv[0]);
		exit (1);
	}

	if ((fd = open (argv[1], O_RDONLY)) < 0) {
		fprintf(stderr, "ERROR: %s\n", strerror(errno));
		exit(1);
	}
	
	printf("\nParsing ELF Identification... ======================\n");
	elfid_parser(fd);

	printf("\nParsing ELF Header... ==============================\n");
	if (e_ident[EI_CLASS] == 1) {  }
	if (e_ident[EI_CLASS] == 2) { ehdr64_print(fd); }

	printf("\nParsing Section Header Table... ==============================\n");
	if (e_ident[EI_CLASS] == 1) {  }
	if (e_ident[EI_CLASS] == 2) { shdr64_print(fd); }

	close(fd);
	return 0;
}
