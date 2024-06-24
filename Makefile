TARGET=elf-parser
CC=gcc
INCLUDE_PATH:=include

CFLAGS:=-I$(INCLUDE_PATH)

build: main.c elf_common.c elf32.c elf64.c util.c
	$(CC) $(CFLAGS) -o $(TARGET) $^

clean:
	rm *.o
