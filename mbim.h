#ifndef _MBIM_H__
#define _MBIM_H__

#include <stdint.h>
#include <sys/types.h>

#define MBIM_BUFFER_SIZE	1024

extern int return_code;
extern int verbose;

#include "mbim-type.h"
#include "mbim-enum.h"
#include "mbim-enums.h"
#include "mbim-msg.h"
#include "mbim-cid.h"
#include "mbim-dev.h"

struct mbim_handler {
	char *name;
	int argc;

	_mbim_cmd_request request;
	_mbim_cmd_response response;
};
extern struct mbim_handler *current_handler;

#endif
