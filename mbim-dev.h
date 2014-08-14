#ifndef _MBIM_DEV_H__
#define _MBIM_DEV_H__

extern uint8_t mbim_buffer[MBIM_BUFFER_SIZE];
extern int no_close;

int mbim_send(void);
void mbim_open(const char *path);

#endif
