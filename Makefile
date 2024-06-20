TARGET=elf-parser
CC=gcc
INCLUDE_PATH:=include

CFLAGS:=-I$(INCLUDE_PATH)

build: main.c elf32.c elf64.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c elf32.c elf64.c

clean:
	rm *.o
