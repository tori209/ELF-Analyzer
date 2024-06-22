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
	off_t prev_lseek;

	if ((prev_lseek = lseek(fd, 0, SEEK_CUR)) < 0) {  return -1;  }
	if (lseek(fd, 0, SEEK_SET) < 0) {  return -1;  }
	if (read(fd, buf, sizeof(Elf64_Ehdr)) < 0) {  return -1;  }

	if ((is_little_endian() && (buf->e_ident[EI_DATA] == ELFDATA2MSB))
		|| ((!is_little_endian()) && (buf->e_ident[EI_DATA] == ELFDATA2LSB))) {
		convert_ordering(&buf->e_type, sizeof(Elf64_Half));
		convert_ordering(&buf->e_machine, sizeof(Elf64_Half));
		convert_ordering(&buf->e_version, sizeof(Elf64_Word));
		convert_ordering(&buf->e_entry, sizeof(Elf64_Addr));
		convert_ordering(&buf->e_phoff, sizeof(Elf64_Off));
		convert_ordering(&buf->e_shoff, sizeof(Elf64_Off));
		convert_ordering(&buf->e_flags, sizeof(Elf64_Word));
		convert_ordering(&buf->e_ehsize, sizeof(Elf64_Half));
		convert_ordering(&buf->e_phentsize, sizeof(Elf64_Half));
		convert_ordering(&buf->e_phnum, sizeof(Elf64_Half));
		convert_ordering(&buf->e_shentsize, sizeof(Elf64_Half));
		convert_ordering(&buf->e_shnum, sizeof(Elf64_Half));
		convert_ordering(&buf->e_shstrndx, sizeof(Elf64_Half));
	}

	if (lseek(fd, prev_lseek, SEEK_SET) < 0) {  return -1;  }
	return 0;
}

int shdr64_read (int fd, Elf64_Shdr * buf, Elf64_Half idx) {
	off_t prev_lseek;
	Elf64_Ehdr ehdr;
	
	if ((prev_lseek = lseek(fd, 0, SEEK_CUR)) < 0) {  return -1;  }
	if (ehdr64_read(fd, &ehdr) < 0) {  return -1;  }
	if (ehdr.e_shoff == 0) {  return -1;  } // Section Header Table Not Exist
	if (lseek(fd, ehdr.e_shoff + idx * ehdr.e_shentsize, SEEK_SET) < 0) {  return -1;  }
	if (read(fd, buf, ehdr.e_shentsize) < 0) {  return -1;  }

	if ((is_little_endian() && (ehdr.e_ident[EI_DATA] == ELFDATA2MSB))
		|| ((!is_little_endian()) && (ehdr.e_ident[EI_DATA] == ELFDATA2LSB))) {
		convert_ordering(&buf->sh_name, sizeof(Elf64_Word));
		convert_ordering(&buf->sh_type, sizeof(Elf64_Word));
		convert_ordering(&buf->sh_flags, sizeof(Elf64_Xword));
		convert_ordering(&buf->sh_addr, sizeof(Elf64_Addr));
		convert_ordering(&buf->sh_offset, sizeof(Elf64_Off));
		convert_ordering(&buf->sh_size, sizeof(Elf64_Xword));
		convert_ordering(&buf->sh_link, sizeof(Elf64_Word));
		convert_ordering(&buf->sh_info, sizeof(Elf64_Word));
		convert_ordering(&buf->sh_addralign, sizeof(Elf64_Xword));
		convert_ordering(&buf->sh_entsize, sizeof(Elf64_Xword));
	}

	if (lseek(fd, prev_lseek, SEEK_SET) < 0) {  return -1;  }
	return 0;
}

char * strtab64_read (int fd, int offset) {
	static char * strtab = NULL;
	static int curr_fd = -1;
	static Elf64_Word size = -1;

	if (curr_fd != fd) {
		Elf64_Ehdr ehdr;
		Elf64_Shdr shdr;
		off_t prev_lseek;

		if ((prev_lseek = lseek(fd, 0, SEEK_CUR)) < 0) {  return NULL;  }

		// Initialization
		if (strtab != NULL) {  free(strtab);  }
		if (ehdr64_read (fd, &ehdr) < 0)  {  curr_fd = -1; return NULL;  }
		if (shdr64_read (fd, &shdr, ehdr.e_shstrndx) < 0) {  curr_fd = -1; return NULL;  }
		if ((strtab = (char*)malloc(shdr.sh_size)) == NULL) {  curr_fd = -1; return NULL;  }
		
		// Memory Copy
		if (lseek(fd, shdr.sh_offset, SEEK_SET) < 0) {  free(strtab); curr_fd = -1; return NULL;  }
		if (read(fd, strtab, shdr.sh_size) < 0) {  free(strtab); curr_fd = -1; return NULL;  }
		
		size = shdr.sh_size;
		curr_fd = fd;
		if ((prev_lseek = lseek(fd, prev_lseek, SEEK_SET)) < 0) {  
			fprintf(stderr, "FATAL ERROR: lseek restoration failed\n");
			exit(1);
	  	}
	}
	if (offset >= size) {  return NULL;  }
	return &strtab[offset];
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

int shdr64_print(int fd) {
	Elf64_Ehdr ehdr;
	Elf64_Shdr shdr;
	char * str_ptr;
	if (ehdr64_read(fd, &ehdr) < 0) {  return -1;  }
	if (lseek(fd, (off_t)ehdr.e_shoff, SEEK_SET) < 0) {  return -1;  }

	if (ehdr.e_shnum == 0) {
		printf("Section Header Table Not Exist. Skip.\n");
		return 0;
	}

	for (Elf64_Half idx = 1; idx < ehdr.e_shnum; idx++) {
		if (read(fd, &shdr, ehdr.e_shentsize) < 0) {
			fprintf(stderr, "WARNING: Failed to read Section Header, index: %d. Skip.\n", idx);
			continue;
		}

		printf("\n==| Section %d |==================\n", idx-1);

		str_ptr = strtab64_read(fd, shdr.sh_name);
		if (str_ptr == NULL) {
			printf("%-*s: %d [Failed to read String Table]\n", SHDR_NAMEGAP, "Name Idx", shdr.sh_name);
		} else {
			printf("%-*s: %s\n", SHDR_NAMEGAP, "Name Idx", str_ptr);
		}
		// Section Type
		switch (shdr.sh_type) {
			case SHT_NULL:
				str_ptr="Unused Section Entry";
				break;
			case SHT_PROGBITS:
				str_ptr="Program Data";
				break;
			case SHT_SYMTAB:
				str_ptr="Symbol Table";
				break;
			case SHT_STRTAB:
				str_ptr="String Table";
				break;
			case SHT_RELA:
				str_ptr="Relocation Entries with addends";
				break;
			case SHT_HASH:
				str_ptr="Symbol Hash Table";
				break;
			case SHT_DYNAMIC:
				str_ptr="Dynamic Linking Information";
				break;
			case SHT_NOTE:
				str_ptr="Notes";
				break;
			case SHT_NOBITS:
				str_ptr="Program Space with no data (.bss)";
				break;
			case SHT_REL:
				str_ptr="Relocation Entries without addends";
				break;
			case SHT_SHLIB:
				str_ptr="Reserved Section";
				break;
			case SHT_DYNSYM:
				str_ptr="Dynamic Linker Symbol Table";
				break;
			case SHT_INIT_ARRAY:
				str_ptr="Array of Constructors";
				break;
			case SHT_FINI_ARRAY:
				str_ptr="Array of Destructors";
				break;
			case SHT_PREINIT_ARRAY:
				str_ptr="Array of Pre-constructors";
				break;
			case SHT_GROUP:
				str_ptr="Section Group";
				break;
			case SHT_SYMTAB_SHNDX:
				str_ptr="Extended Section Indices";
				break;
			default:
				str_ptr="Unknown";
		}
		printf("%-*s: %s\n", SHDR_NAMEGAP, "Section Type", str_ptr);
		printf("%-*s: 0x%lx / %ld\n", SHDR_NAMEGAP, "Section Offset", shdr.sh_offset, shdr.sh_offset);
		printf("%-*s: %ld (bytes)\n", SHDR_NAMEGAP, "Section Size", shdr.sh_size);
		printf("%-*s: %d \n", SHDR_NAMEGAP, "Section Link Value", shdr.sh_link);

		if ((str_ptr = (char*)malloc(sizeof(char)*3*sizeof(Elf64_Word))) == NULL) {
			printf("%-*s: [Internal Error: Memory Allocation Failed]\n", SHDR_NAMEGAP, "Section Info (Hex)");
		} else {
			bin_to_hex(&shdr.sh_info, str_ptr, sizeof(char)*3*sizeof(Elf64_Word));
			printf("%-*s: %s\n", SHDR_NAMEGAP, "Section Info (Hex)", str_ptr);
			free(str_ptr);
		} 
		
		if ((str_ptr = (char*)malloc(sizeof(char)*3*sizeof(Elf64_Xword))) == NULL) {
			printf("%-*s: [Internal Error: Memory Allocation Failed]\n", SHDR_NAMEGAP, "Attributes");
		} else {
			bin_to_hex(&shdr.sh_flags, str_ptr, sizeof(char)*3*sizeof(Elf64_Xword));
			printf("%-*s: %s\n", SHDR_NAMEGAP, "Attributes", str_ptr);
			free(str_ptr);
		} 
		if ((shdr.sh_flags & SHF_WRITE) == SHF_WRITE) {  printf("\tWritable\n");  }
		if ((shdr.sh_flags & SHF_ALLOC) == SHF_ALLOC) {  printf("\tMemory Loaded (Address: 0x%lx / Align: 0x%lx)\n", shdr.sh_addr, shdr.sh_addralign);  }
		if ((shdr.sh_flags & SHF_EXECINSTR) == SHF_EXECINSTR) {  printf("\tInstruction Exist\n");  }
		if ((shdr.sh_flags & SHF_MERGE) == SHF_MERGE) {  printf("\tCould be Merged\n");  }
		if ((shdr.sh_flags & SHF_STRINGS) == SHF_STRINGS) {  printf("\tString Exist\n");  }
		if ((shdr.sh_flags & SHF_INFO_LINK) == SHF_INFO_LINK) {  printf("\tLink to (idx: %d)\n", shdr.sh_link);  }
		if ((shdr.sh_flags & SHF_LINK_ORDER) == SHF_LINK_ORDER) {  printf("\tNeed to preserve Order\n");  }
		if ((shdr.sh_flags & SHF_OS_NONCONFORMING) == SHF_OS_NONCONFORMING) {  printf("\tNon-Standard OS Handling Needed\n");  }
		if ((shdr.sh_flags & SHF_GROUP) == SHF_GROUP) {  printf("\tMember of Group\n");  }
		if ((shdr.sh_flags & SHF_TLS) == SHF_TLS) {  printf("\tThread-local Data Exist\n");  }
		if ((shdr.sh_flags & SHF_COMPRESSED) == SHF_COMPRESSED) {  printf("\tCompressed Data Exist\n");  }
		
		// Section Entry Size (If Needed)
		if (shdr.sh_entsize != 0) {
			printf("%-*s: 0x%lx / %ld (bytes)\n", SHDR_NAMEGAP, "Fixed Entry Size", shdr.sh_entsize, shdr.sh_entsize);
		}
	}
}

