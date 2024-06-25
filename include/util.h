#define ALIGN_UP(addr, align) (((addr) + (align) - 1) & ~((align) - 1))

int is_little_endian();
int convert_ordering (void *, int);
void bin_to_hex (void *, void *, int);
