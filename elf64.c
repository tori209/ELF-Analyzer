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
	static Elf64_Ehdr ehdr;

	if (pread(fd, buf, sizeof(Elf64_Ehdr), 0) < 0) {  return -1;  }
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
	return 0;
}

int shdr64_read (int fd, Elf64_Shdr * buf, Elf64_Half idx) {
	off_t prev_lseek;
	static Elf64_Ehdr ehdr;
	static ino_t curr_ino = 0;
	struct stat st;

	if (fstat(fd, &st) < 0 || curr_ino != st.st_ino) {
		if (ehdr64_read(fd, &ehdr) < 0) {  return -1;  }
		curr_ino = st.st_ino;
	}
	if (ehdr.e_shoff == 0) {  return -1;  } // Section Header Table Not Exist
	if (idx >= ehdr.e_shnum) {  return -1;  } // Out of bound
	if (pread(fd, buf, ehdr.e_shentsize, ehdr.e_shoff + idx * ehdr.e_shentsize) < 0) {  return -1;  }

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
	return 0;
}

int phdr64_read (int fd, Elf64_Phdr * buf, Elf64_Half idx) {
	off_t prev_lseek;
	static Elf64_Ehdr ehdr;
	static ino_t curr_ino = 0;
	struct stat st;
	
	if (fstat(fd, &st) < 0 || st.st_ino != curr_ino) {
		if (ehdr64_read(fd, &ehdr) < 0) {  return -1;  }
		curr_ino = st.st_ino;
	}
	if (ehdr.e_phoff == 0) {  return -1;  }		// Program Header Table Not Exist
	if (idx >= ehdr.e_phnum) {  return -1;  }	// Out of Bound
	if (pread(fd, buf, ehdr.e_phentsize, ehdr.e_phoff + idx * ehdr.e_phentsize) < 0) {  return -1;  }
	
	if ((is_little_endian() && (ehdr.e_ident[EI_DATA] == ELFDATA2MSB))
		|| ((!is_little_endian()) && (ehdr.e_ident[EI_DATA] == ELFDATA2LSB))) {
		convert_ordering(&buf->p_type, sizeof(Elf64_Word));
		convert_ordering(&buf->p_flags, sizeof(Elf64_Word));
		convert_ordering(&buf->p_offset, sizeof(Elf64_Off));
		convert_ordering(&buf->p_vaddr, sizeof(Elf64_Addr));
		convert_ordering(&buf->p_paddr, sizeof(Elf64_Addr));
		convert_ordering(&buf->p_filesz, sizeof(Elf64_Xword));
		convert_ordering(&buf->p_memsz, sizeof(Elf64_Xword));
		convert_ordering(&buf->p_align, sizeof(Elf64_Xword));
	}
	return 0;
}

char * shstrtab64_read (int fd, int offset) {
	struct stat st;
	static char * strtab = NULL;
	static ino_t curr_ino = 0;
	static Elf64_Word size = -1;

	if (fstat(fd, &st) < 0 || st.st_ino != curr_ino) {
		Elf64_Ehdr ehdr;
		Elf64_Shdr shdr;

		if (ehdr64_read(fd, &ehdr) < 0) {  return NULL;  }

		// Initialization
		if (strtab != NULL) {  free(strtab);  }
		if (ehdr64_read (fd, &ehdr) < 0  
			|| shdr64_read (fd, &shdr, ehdr.e_shstrndx) < 0
			|| (strtab = (char*)malloc(shdr.sh_size)) == NULL)
		{  size = -1; curr_ino = 0; return NULL;  }
		
		// Memory Copy
		if (pread(fd, strtab, shdr.sh_size, shdr.sh_offset) < 0)
		{  free(strtab); size = -1; curr_ino = 0; return NULL;  }
		
		size = shdr.sh_size;
		curr_ino = st.st_ino;
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
	if (ehdr.e_shnum == 0) {
		printf("Section Header Table Not Exist. Skip.\n");
		return 0;
	}

	if (lseek(fd, (off_t)ehdr.e_shoff, SEEK_SET) < 0) {  return -1;  }

	for (Elf64_Half idx = 0; idx < ehdr.e_shnum; idx++) {
		if (read(fd, &shdr, ehdr.e_shentsize) < 0) {
			fprintf(stderr, "WARNING: Failed to read Section Header, index: %d. Skip.\n", idx);
			continue;
		}

		printf("\n==| Section %d |==================\n", idx);

		str_ptr = shstrtab64_read(fd, shdr.sh_name);
		if (str_ptr == NULL) {
			printf("%-*s: %d [Failed to read String Table]\n", SHDR_NAMEGAP, "Section Name", shdr.sh_name);
		} else {
			printf("%-*s: %s\n", SHDR_NAMEGAP, "Section Name", str_ptr);
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
#if defined(__gnu_linux__) || defined (__sun)
			case SHT_GNU_ATTRIBUTES:
				str_ptr="Object attributes (GNU-Specific)";
				break;
			case SHT_GNU_HASH:
				str_ptr="GNU-style hash table (GNU-Specific)";
				break;
			case SHT_GNU_LIBLIST:
				str_ptr="Prelink library list (GNU-Specific)";
				break;
			case SHT_CHECKSUM:
				str_ptr="Checksum for DSO content (GNU-Specific)";
				break;
			case SHT_SUNW_move:
				str_ptr="SHT_SUNW_move (Sun-Specific)";
				break;
			case SHT_SUNW_COMDAT:
				str_ptr="SHT_SUNW_COMDAT (Sun-Specific)";
				break;
			case SHT_SUNW_syminfo:
				str_ptr="SHT_SUNW_syminfo (Sun-Specific)";
				break;
			case SHT_GNU_verdef:
				str_ptr="Version definition section (GNU-Specific)";
				break;
			case SHT_GNU_verneed:
				str_ptr="Version needs section (GNU-Specific)";
				break;
			case SHT_GNU_versym:
				str_ptr="Version symbol table (GNU-Specific)";
				break;
#endif
			default:
#if defined(__gnu_linux__) || defined (__sun)
				if (SHT_LOSUNW <= shdr.sh_type && shdr.sh_type <= SHT_HISUNW) {
					str_ptr="Unknown Sun-Specific Type";
				} else
#endif
				if (SHT_LOOS <= shdr.sh_type && shdr.sh_type <= SHT_HIOS) {
					str_ptr="Unknown OS-Specific Type";
				} else if (SHT_LOPROC <= shdr.sh_type && shdr.sh_type <= SHT_HIPROC) {
					str_ptr="Unknown Processor-Specific Type";
				} else if (SHT_LOUSER <= shdr.sh_type && shdr.sh_type <= SHT_HIUSER) {
					str_ptr="Unknown User-Specific Type";
				} else {
					str_ptr="Unknown";
				}
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

int phdr64_print(int fd) {
	Elf64_Ehdr ehdr;
	Elf64_Phdr phdr;
	char * str_ptr;

	if (ehdr64_read(fd, &ehdr) < 0) {  return -1;  }
	if (ehdr.e_phnum == 0) {
		printf("Program Header Table Not Exist. Skip.\n");
		return 0;
	}

	for (Elf64_Half idx = 0; idx < ehdr.e_phnum; idx++) {
		if (phdr64_read(fd, &phdr, idx) < 0) {
			fprintf(stderr, "WARNING: Failed to read Program Header, index: %d. Skip.\n", idx);
			continue;
		}
		
		printf("\n==| Segment %d |==================\n", idx);
		// Program Header Type
		switch (phdr.p_type) {
			case PT_NULL:
				str_ptr = "Program header table entry unused";
				break;
			case PT_LOAD:
				str_ptr = "Loadable program segment";
				break;
			case PT_DYNAMIC:
				str_ptr = "Dynamic linking information";
				break;
			case PT_INTERP:
				str_ptr = "Program interpreter";
				break;
			case PT_NOTE:
				str_ptr = "Auxiliary information (Notes)";
				break;
			case PT_SHLIB:
				str_ptr = "Reserved (SHLIB)";
				break;
			case PT_PHDR:
				str_ptr = "Entry for header table itself";
				break;
			case PT_TLS:
				str_ptr = "Thread-local storage segment";
				break;
#if defined(__gnu_linux__) || defined (__sun)
			case PT_GNU_EH_FRAME:
				str_ptr = "GCC .eh_frame_hdr segment (GNU-Specific)";
				break;
			case PT_GNU_STACK:
				str_ptr = "Stack Excutability Information (GNU-Specific)";
				break;
			case PT_GNU_RELRO:
				str_ptr = "Read-only List after Relocation (GNU-Specific)";
				break;
			case PT_GNU_PROPERTY:
				str_ptr = "GNU Property (GNU-Specific)";
				break;
			case PT_SUNWBSS:
				str_ptr = "Sun Specific Segment [SUNWBSS] (Sun-Specific)";
				break;
			case PT_SUNWSTACK:
				str_ptr = "Stack Segment (Sun-Specific)";
				break;
#endif
			default:
#if defined(__gnu_linux__) || defined (__sun)
				if (PT_LOSUNW <= phdr.p_type && phdr.p_type <= PT_HISUNW) {
					str_ptr = "Unknown Sun-Specific Segment";
				} else
#endif
				if (PT_LOOS <= phdr.p_type && phdr.p_type <= PT_HIOS) {
					str_ptr = "Unknown OS-Specific Segment";
				} else if (PT_LOPROC <= phdr.p_type && phdr.p_type <= PT_HIPROC) {
					str_ptr = "Unknown Processor-Specific Segment";
				} else {
					str_ptr = "Undefined Program Header Type";
				}
		}
		printf("%-*s: %s\n", PHDR_NAMEGAP, "Segment Type", str_ptr);


		// Segment File Offset
		printf("%-*s: 0x%lx / %ld\n", PHDR_NAMEGAP, "File Offset", phdr.p_offset, phdr.p_offset);
		// Virtual & Physical Address
		printf("%-*s: 0x%lx / %ld\n", PHDR_NAMEGAP, "Virtual Memory Address", phdr.p_vaddr, phdr.p_vaddr);
		printf("%-*s: 0x%lx / %ld\n", PHDR_NAMEGAP, "Physical Address", phdr.p_paddr, phdr.p_paddr);
		// File Size & Memory Size
		printf("%-*s: 0x%lx / %ld\n", PHDR_NAMEGAP, "Size in File", phdr.p_filesz, phdr.p_filesz);
		printf("%-*s: 0x%lx / %ld\n", PHDR_NAMEGAP, "Size in Memory", phdr.p_memsz, phdr.p_memsz);
		// Flags
		str_ptr = (char *)malloc(sizeof(char) * 3 * sizeof(Elf64_Word));
		bin_to_hex(&phdr.p_flags, str_ptr, sizeof(char) * 3 * sizeof(Elf64_Word));
		printf("%-*s: %s ", PHDR_NAMEGAP, "Flags", str_ptr);
		free(str_ptr);

		str_ptr = (char *)malloc(sizeof(char) * 6);
		memset(str_ptr, '\0', 6);
		str_ptr[0] = '(';
		str_ptr[1] = ((phdr.p_flags & PF_R) == PF_R ? 'r' : '-');
		str_ptr[2] = ((phdr.p_flags & PF_W) == PF_W ? 'w' : '-');
		str_ptr[3] = ((phdr.p_flags & PF_X) == PF_X ? 'x' : '-');
		str_ptr[4] = ')';
		printf("%s\n", str_ptr);
		free(str_ptr);

		printf("%-*s: 0x%lx / %ld\n", PHDR_NAMEGAP, "Alignment Constraint", phdr.p_align, phdr.p_align);
	}
}

int symbol64_print(int fd) {
	char * str_ptr;
	char * strtab_ptr;
	Elf64_Shdr shdr, link_shdr;
	Elf64_Sym sym;

	for (Elf64_Half sh_idx = 1; shdr64_read(fd, &shdr, sh_idx) >= 0; sh_idx++) {
		if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM) {  continue;  }
		if (shdr.sh_entsize != sizeof(Elf64_Sym)) {
			fprintf(stderr, "WARNING: sh_entsize(0x%lx) != sizeof(Elf64_Sym; 0x%lx). Result May not correct.\n", shdr.sh_entsize, sizeof(Elf64_Sym));
		}
		// Section Name
		printf("\n==| Section %d |==================\n", sh_idx);
		str_ptr = shstrtab64_read(fd, shdr.sh_name);
		if (str_ptr == NULL) {
			printf("%-*s: %d [Failed to read String Table]\n", SHDR_NAMEGAP, "Section Name", shdr.sh_name);
		} else {
			printf("%-*s: %s\n", SHDR_NAMEGAP, "Section Name", str_ptr);
		}

		// Linked String Table Init
		if (shdr64_read(fd, &link_shdr, shdr.sh_link) < 0
			|| (strtab_ptr = (char*)malloc(sizeof(char) * link_shdr.sh_size)) < 0) {
			strtab_ptr = NULL;
			fprintf(stderr, "WARNING: Linked String Table Load Failed.\n");
		} else if (pread(fd, strtab_ptr, link_shdr.sh_size, link_shdr.sh_offset) < 0) {
			free(strtab_ptr);
			strtab_ptr = NULL;
			fprintf(stderr, "WARNING: Linked String Table Load Failed.\n");
		} else {  /* Nothing to do */  }

		// Print Symbol Info.
		for (Elf64_Half idx = 0; idx < shdr.sh_size / shdr.sh_entsize; idx++) {
			if (pread(fd, &sym, sizeof(Elf64_Sym),shdr.sh_offset + idx * sizeof(Elf64_Sym)) < 0) {
				fprintf(stderr, "WARNING: pread failed. index = %d\n", idx);
				continue;
			}
			printf("--| Symbol %d |-----------------\n", idx);
			
			// Symbol Name
			if (strtab_ptr == NULL) {
				printf("%-*s: %d [Trace Failed]\n", SYMS_NAMEGAP, "Symbol Name", sym.st_name);
			} else {
				printf("%-*s: %s\n", SYMS_NAMEGAP, "Symbol Name", &strtab_ptr[sym.st_name]);
			}

			// Symbol Value
			printf("%-*s: %ld\n", SYMS_NAMEGAP, "Symbol Value", sym.st_value);

			// Symbol Size
			printf("%-*s: 0x%lx / %ld (bytes)\n", SYMS_NAMEGAP, "Symbol Size", sym.st_size, sym.st_size);

			// Symbol Information
			if ((str_ptr = malloc(sizeof(char) * 3 * sizeof(sym.st_info))) < 0) {
				fprintf(stderr, "WARNING: malloc failed. skip. / %s\n", strerror(errno));
				continue;
			}
			bin_to_hex(&sym.st_name, str_ptr, sizeof(char) * 3 * sizeof(sym.st_info));
			printf("%-*s: %s\n", SYMS_NAMEGAP, "Symbol Information", str_ptr);
			free(str_ptr);

			// Symbol Other
			if ((str_ptr = malloc(sizeof(char) * 3 * sizeof(sym.st_other))) < 0) {
				fprintf(stderr, "WARNING: malloc failed. skip. / %s\n", strerror(errno));
				continue;
			}
			bin_to_hex(&sym.st_other, str_ptr, sizeof(char) * 3 * sizeof(sym.st_other));
			printf("%-*s: %s\n", SYMS_NAMEGAP, "Symbol Other", str_ptr);
			free(str_ptr);
			// Symbol Visibility
			switch (ELF64_ST_VISIBILITY(sym.st_other)) {
				case STV_DEFAULT:
					str_ptr="Public (Default)";
					break;
				case STV_INTERNAL:
					str_ptr="Processor-Specific Hidden Class";
					break;
				case STV_HIDDEN:
					str_ptr="Hidden";
					break;
				case STV_PROTECTED:
					str_ptr="Protected";
					break;
				default:
					str_ptr = "Unknown";
			}
			printf("%-*s: %s\n", SYMS_NAMEGAP, "  |-- Symbol Visibility", str_ptr);
			printf("%-*s: %d\n", SYMS_NAMEGAP, "Related Section Index", sym.st_shndx);
		}
		if (strtab_ptr != NULL) {  free(strtab_ptr);  }
	}
	return 0;
}

int relro64_print(int fd) {
	char * str_ptr;
	Elf64_Ehdr ehdr;
	Elf64_Shdr shdr;
	Elf64_Sym sym;
	Elf64_Rel rel;
	Elf64_Rela rela;

	if (ehdr64_read(fd, &ehdr) < 0) {  return -1;  }
	for (Elf64_Half sh_idx = 1; sh_idx < ehdr.e_shnum; sh_idx++) {
		if (shdr64_read(fd, &shdr, sh_idx) < 0) {
			fprintf(stderr, "WARNING: Section reading Failed. Skip. / Index = %d\n", sh_idx);
			continue;
		}
		if (shdr.sh_type != SHT_REL && shdr.sh_type != SHT_RELA) {  continue;  }
		if (shdr.sh_entsize != sizeof (rel) && shdr.sh_entsize != sizeof(rela)) {
			fprintf(stderr, "WARNING: entsize is not matched with ElfN_Rel / ElfN_Rela. Result may not correct.\n");
		}
		// Section Information
		printf("\n==| Section %d |==================\n", sh_idx);
		str_ptr = shstrtab64_read(fd, shdr.sh_name);
		if (str_ptr == NULL) {
			printf("%-*s: %d [Failed to read String Table]\n", SHDR_NAMEGAP, "Section Name", shdr.sh_name);
		} else {
			printf("%-*s: %s\n", SHDR_NAMEGAP, "Section Name", str_ptr);
		}

		// RELA Print
		for (Elf64_Half idx; (shdr.sh_type == SHT_RELA) && (idx < shdr.sh_size / shdr.sh_entsize); idx++) {
			if (pread(fd, &rela, sizeof(rela), shdr.sh_offset + sizeof(rela) * idx) < 0) {
				fprintf(stderr, "WARNING: pread failed. index = %d\n", idx);
				continue;
			}
			printf("--| Rela Entry %d |---------------\n", idx);
			printf("%-*s: %ld\n", RELRO_NAMEGAP, "Entry Offset", rela.r_offset);
			printf("%-*s: %ld\n", RELRO_NAMEGAP, "Related Symbol Index", ELF64_R_SYM(rela.r_info));
			printf("%-*s: %ld\n", RELRO_NAMEGAP, "Relocation Type", ELF64_R_TYPE(rela.r_info));
			printf("%-*s: 0x%lx / %ld\n", RELRO_NAMEGAP, "Addend", rela.r_addend, rela.r_addend);
		}

		// REL Print
		for (Elf64_Half idx; (shdr.sh_type == SHT_REL) && (idx < shdr.sh_size / shdr.sh_entsize); idx++) {
			if (pread(fd, &rela, sizeof(rel), shdr.sh_offset + sizeof(rel) * idx) < 0) {
				fprintf(stderr, "WARNING: pread failed. index = %d\n", idx);
				continue;
			}
			printf("--| Rel Entry %d |---------------\n", idx);
			printf("%-*s: %ld\n", RELRO_NAMEGAP, "Entry Offset", rel.r_offset);
			printf("%-*s: %ld\n", RELRO_NAMEGAP, "Related Symbol", ELF64_R_SYM(rel.r_info));
			printf("%-*s: %ld\n", RELRO_NAMEGAP, "Relocation Type", ELF64_R_TYPE(rel.r_info));
		}
	}
	return 0;
}
