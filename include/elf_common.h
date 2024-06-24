#include <elf.h>

int read_ident(int, char [EI_NIDENT]);
int is_elf(int fd);
int elfident_print(int);
