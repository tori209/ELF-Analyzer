#include <string.h>
#include <stdlib.h>

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
