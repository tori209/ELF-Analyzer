#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

int is_valid_fd (int fd) {
	return fcntl(fd, F_GETFD) != -1;
}

int is_same_file (int fd1, int fd2) {
	struct stat s1, s2;

	if (fd1 == fd2) {  return 0;  }
	if (!is_valid_fd(fd1) || !is_valid_fd(fd2)) {  return -1;  }  // Invalid fd.
	if (fstat(fd1, &s1) < 0 || fstat(fd2, &s2) < 0) {  return -1;  }  // stat failed.

	return s1.st_ino == s2.st_ino;
}

int is_little_endian () {
	int test = 1;
	char * c = (char *)&test;
	return *c;
}

int convert_ordering (void * target, int size) {
	char * ret;
	char * arr = target;

	if (size <= 1) return 0;
	if ((ret = malloc(size)) < 0) {  return -1;  }
	for (int idx = 0; idx < size; idx++) {
		ret[idx] = arr[size - 1 - idx];
	}
	if (memcpy(target, ret, size) == NULL) {
		free(ret);
		return -1;
	} else {
		free(ret);
		return 0;
	}
}

void bin_to_hex (void * hexarr, void * buffer, int len) {
	char * arr = (char *)hexarr;
	char * ret = (char *)buffer;
	const char hex_table[16] = "0123456789ABCDEF";
	char hex[3];
	int idx;
	for (idx = 0; idx * 3 < len; idx++) {
		hex[0] = hex_table[(arr[idx] >> 4) & 0xf];
		hex[1] = hex_table[arr[idx] & 0xf];
		hex[2] = ' ';
		strncpy((ret + 3*idx), hex, 3);
	}
	ret[3*idx-1] = '\0';
}
