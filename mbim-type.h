#ifndef _MBIM_TYPE_H__
#define _MBIM_TYPE_H__

struct mbim_string {
	uint32_t offset;
	uint32_t length;
};

struct mbim_enum {
	uint32_t key;
	char *skey;
	char *val;
};

#endif
