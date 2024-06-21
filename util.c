#include <string.h>

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
