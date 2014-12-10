/*
 * umbim
 * Copyright (C) 2014 John Crispin <blogic@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <alloca.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include <libubox/utils.h>
#include <libubox/uloop.h>

#include "mbim.h"

#include "data/mbim-service-basic-connect.h"

int return_code = -1;
int verbose;

struct mbim_handler *current_handler;
static uint8_t uuid_context_type_internet[16] = { 0x7E, 0x5E, 0x2A, 0x7E, 0x4E, 0x6F, 0x72, 0x72, 0x73, 0x6B, 0x65, 0x6E, 0x7E, 0x5E, 0x2A, 0x7E };
static int _argc;
static char **_argv;

static int
mbim_device_caps_response(void *buffer, int len)
{
	struct mbim_basic_connect_device_caps_r *caps = (struct mbim_basic_connect_device_caps_r *) buffer;
	char *deviceid, *firmwareinfo, *hardwareinfo;

	if (len < sizeof(struct mbim_basic_connect_device_caps_r)) {
		fprintf(stderr, "message not long enough\n");
		return -1;
	}

	deviceid = mbim_get_string(&caps->deviceid, buffer);
	firmwareinfo = mbim_get_string(&caps->firmwareinfo, buffer);
	hardwareinfo = mbim_get_string(&caps->hardwareinfo, buffer);

	printf("  devicetype: %04X - %s\n", le32toh(caps->devicetype),
		mbim_enum_string(mbim_device_type_values, le32toh(caps->devicetype)));
	printf("  cellularclass: %04X\n", le32toh(caps->cellularclass));
	printf("  voiceclass: %04X - %s\n", le32toh(caps->voiceclass),
		mbim_enum_string(mbim_voice_class_values, le32toh(caps->voiceclass)));
	printf("  simclass: %04X\n", le32toh(caps->simclass));
	printf("  dataclass: %04X\n", le32toh(caps->dataclass));
	printf("  smscaps: %04X\n", le32toh(caps->smscaps));
	printf("  controlcaps: %04X\n", le32toh(caps->controlcaps));
	printf("  maxsessions: %04X\n", le32toh(caps->maxsessions));
	printf("  deviceid: %s\n", deviceid);
	printf("  firmwareinfo: %s\n", firmwareinfo);
	printf("  hardwareinfo: %s\n", hardwareinfo);

	return 0;
}

static int
mbim_pin_state_response(void *buffer, int len)
{
	struct mbim_basic_connect_pin_r *pin = (struct mbim_basic_connect_pin_r *) buffer;

	if (len < sizeof(struct mbim_basic_connect_pin_r)) {
		fprintf(stderr, "message not long enough\n");
		return -1;
	}

	if (le32toh(pin->pinstate) != MBIM_PIN_STATE_UNLOCKED) {
		fprintf(stderr, "required pin: %d - %s\n",
			le32toh(pin->pintype), mbim_enum_string(mbim_pin_type_values, le32toh(pin->pintype)));
		fprintf(stderr, "remaining attempts: %d\n", le32toh(pin->remainingattempts));
		return le32toh(pin->pintype);
	}

	fprintf(stderr, "Pin Unlocked\n");

	return 0;
}

static int
mbim_registration_response(void *buffer, int len)
{
	struct mbim_basic_connect_register_state_r *state = (struct mbim_basic_connect_register_state_r *) buffer;
	char *provider_id, *provider_name, *roamingtext;

	if (len < sizeof(struct mbim_basic_connect_register_state_r)) {
		fprintf(stderr, "message not long enough\n");
		return -1;
	}

	provider_id = mbim_get_string(&state->providerid, buffer);
	provider_name = mbim_get_string(&state->providername, buffer);
	roamingtext = mbim_get_string(&state->roamingtext, buffer);

	printf("  nwerror: %04X - %s\n", le32toh(state->nwerror),
		mbim_enum_string(mbim_nw_error_values, le32toh(state->nwerror)));
	printf("  registerstate: %04X - %s\n", le32toh(state->registerstate),
		mbim_enum_string(mbim_register_state_values, le32toh(state->registerstate)));
	printf("  registermode: %04X - %s\n", le32toh(state->registermode),
		mbim_enum_string(mbim_register_mode_values, le32toh(state->registermode)));
	printf("  availabledataclasses: %04X - %s\n", le32toh(state->availabledataclasses),
		mbim_enum_string(mbim_data_class_values, le32toh(state->availabledataclasses)));
	printf("  currentcellularclass: %04X - %s\n", le32toh(state->currentcellularclass),
		mbim_enum_string(mbim_cellular_class_values, le32toh(state->currentcellularclass)));
	printf("  provider_id: %s\n", provider_id);
	printf("  provider_name: %s\n", provider_name);
	printf("  roamingtext: %s\n", roamingtext);

	if (le32toh(state->registerstate) == MBIM_REGISTER_STATE_HOME)
		return 0;

	return le32toh(state->registerstate);
}

static int
mbim_subscriber_response(void *buffer, int len)
{
	struct mbim_basic_connect_subscriber_ready_status_r *state = (struct mbim_basic_connect_subscriber_ready_status_r *) buffer;
	char *subscriberid, *simiccid;
	int nr;

	if (len < sizeof(struct mbim_basic_connect_subscriber_ready_status_r)) {
		fprintf(stderr, "message not long enough\n");
		return -1;
	}

	subscriberid = mbim_get_string(&state->subscriberid, buffer);
	simiccid = mbim_get_string(&state->simiccid, buffer);

	printf("  readystate: %04X - %s\n", le32toh(state->readystate),
		mbim_enum_string(mbim_subscriber_ready_state_values, le32toh(state->readystate)));
	printf("  simiccid: %s\n", simiccid);
	printf("  subscriberid: %s\n", subscriberid);
	if (le32toh(state->readyinfo) & MBIM_READY_INFO_FLAG_PROTECT_UNIQUE_ID)
		printf("  dont display subscriberID: 1\n");
	for (nr = 0; nr < le32toh(state->telephonenumberscount); nr++) {
		struct mbim_string *str = buffer + le32toh(state->telephonenumbers) + (nr * sizeof(struct mbim_string));
		char *number = mbim_get_string(str, buffer);
		printf("  number: %s\n", number);
	}

	if (MBIM_SUBSCRIBER_READY_STATE_INITIALIZED == le32toh(state->readystate))
		return 0;

	return le32toh(state->readystate);
}

static int
mbim_attach_response(void *buffer, int len)
{
	struct mbim_basic_connect_packet_service_r *ps = (struct mbim_basic_connect_packet_service_r *) buffer;

	if (len < sizeof(struct mbim_basic_connect_packet_service_r)) {
		fprintf(stderr, "message not long enough\n");
		return -1;
	}

	printf("  nwerror: %04X - %s\n", le32toh(ps->nwerror),
		mbim_enum_string(mbim_nw_error_values, le32toh(ps->nwerror)));
	printf("  packetservicestate: %04X - %s\n", le32toh(ps->packetservicestate),
		mbim_enum_string(mbim_packet_service_state_values, le32toh(ps->packetservicestate)));
	printf("  uplinkspeed: %"PRIu64"\n", (uint64_t) le64toh(ps->uplinkspeed));
	printf("  downlinkspeed: %"PRIu64"\n", (uint64_t) le64toh(ps->downlinkspeed));

	if (MBIM_PACKET_SERVICE_STATE_ATTACHED == le32toh(ps->packetservicestate))
		return 0;

	return le32toh(ps->packetservicestate);
}

static int
mbim_connect_response(void *buffer, int len)
{
	struct mbim_basic_connect_connect_r *c = (struct mbim_basic_connect_connect_r *) buffer;

	if (len < sizeof(struct mbim_basic_connect_connect_r)) {
		fprintf(stderr, "message not long enough\n");
		return -1;
	}

	printf("  sessionid: %d\n", le32toh(c->sessionid));
	printf("  activationstate: %04X - %s\n", le32toh(c->activationstate),
		mbim_enum_string(mbim_activation_state_values, le32toh(c->activationstate)));
	printf("  voicecallstate: %04X - %s\n", le32toh(c->voicecallstate),
		mbim_enum_string(mbim_voice_call_state_values, le32toh(c->voicecallstate)));
	printf("  nwerror: %04X - %s\n", le32toh(c->nwerror),
		mbim_enum_string(mbim_nw_error_values, le32toh(c->nwerror)));
	printf("  iptype: %04X - %s\n", le32toh(c->iptype),
		mbim_enum_string(mbim_context_ip_type_values, le32toh(c->iptype)));

	if (MBIM_ACTIVATION_STATE_ACTIVATED == le32toh(c->activationstate))
		return 0;

	return le32toh(c->activationstate);
}

static int
mbim_config_response(void *buffer, int len)
{
	struct mbim_basic_connect_ip_configuration_r *ip = (struct mbim_basic_connect_ip_configuration_r *) buffer;
	char ipv4[16];
	int i;

	if (len < sizeof(struct mbim_basic_connect_ip_configuration_r)) {
		fprintf(stderr, "message not long enough\n");
		return -1;
	}

	if (le32toh(ip->ipv4configurationavailable) & MBIM_IP_CONFIGURATION_AVAILABLE_FLAG_ADDRESS)
		for (i = 0; i < le32toh(ip->ipv4addresscount); i++) {
			mbim_get_ipv4(buffer, ipv4, ip->ipv4address + (i * 4));
			printf("  ipv4address: %s\n", ipv4);
		}
	if (le32toh(ip->ipv4configurationavailable) & MBIM_IP_CONFIGURATION_AVAILABLE_FLAG_DNS) {
		mbim_get_ipv4(buffer, ipv4, ip->ipv4gateway);
		printf("  ipv4gateway: %s\n", ipv4);
	}
	if (le32toh(ip->ipv4configurationavailable) & MBIM_IP_CONFIGURATION_AVAILABLE_FLAG_MTU)
		printf("  ipv4mtu: %d\n", le32toh(ip->ipv4mtu));
	if (le32toh(ip->ipv4configurationavailable) & MBIM_IP_CONFIGURATION_AVAILABLE_FLAG_DNS)
		for (i = 0; i < le32toh(ip->ipv4dnsservercount); i++) {
			mbim_get_ipv4(buffer, ipv4, ip->ipv4dnsserver + (i * 4));
			printf("  ipv4dnsserver: %s\n", ipv4);
		}

	printf("  ipv6configurationavailable: %04X\n", le32toh(ip->ipv6configurationavailable));

	return 0;
}

static int
mbim_device_caps_request(void)
{
	mbim_setup_command_msg(basic_connect, MBIM_MESSAGE_COMMAND_TYPE_QUERY, MBIM_CMD_BASIC_CONNECT_DEVICE_CAPS, 0);

	return mbim_send_command_msg();
}

static int
mbim_pin_state_request(void)
{
	mbim_setup_command_msg(basic_connect, MBIM_MESSAGE_COMMAND_TYPE_QUERY, MBIM_CMD_BASIC_CONNECT_PIN, 0);

	return mbim_send_command_msg();
}

static int
mbim_registration_request(void)
{
	mbim_setup_command_msg(basic_connect, MBIM_MESSAGE_COMMAND_TYPE_QUERY, MBIM_CMD_BASIC_CONNECT_REGISTER_STATE, 0);

	return mbim_send_command_msg();
}

static int
mbim_subscriber_request(void)
{
	mbim_setup_command_msg(basic_connect, MBIM_MESSAGE_COMMAND_TYPE_QUERY, MBIM_CMD_BASIC_CONNECT_SUBSCRIBER_READY_STATUS, 0);

	return mbim_send_command_msg();
}

static int
_mbim_attach_request(int action)
{
	struct mbim_basic_connect_packet_service_s *ps =
		(struct mbim_basic_connect_packet_service_s *) mbim_setup_command_msg(basic_connect,
			MBIM_MESSAGE_COMMAND_TYPE_SET, MBIM_CMD_BASIC_CONNECT_PACKET_SERVICE,
			sizeof(struct mbim_basic_connect_packet_service_s));

	ps->packetserviceaction = htole32(action);

	return mbim_send_command_msg();
}

static int
mbim_attach_request(void)
{
	return _mbim_attach_request(MBIM_PACKET_SERVICE_ACTION_ATTACH);
}

static int
mbim_detach_request(void)
{
	return _mbim_attach_request(MBIM_PACKET_SERVICE_ACTION_DETACH);
}

static int
mbim_connect_request(void)
{
	struct mbim_basic_connect_connect_s *c =
		(struct mbim_basic_connect_connect_s *) mbim_setup_command_msg(basic_connect,
			MBIM_MESSAGE_COMMAND_TYPE_SET, MBIM_CMD_BASIC_CONNECT_CONNECT,
			sizeof(struct mbim_basic_connect_connect_s));

	c->activationcommand = htole32(MBIM_ACTIVATION_COMMAND_ACTIVATE);
	c->iptype = htole32(MBIM_CONTEXT_IP_TYPE_DEFAULT);
	memcpy(c->contexttype, uuid_context_type_internet, 16);
	if (_argc > 0)
		mbim_encode_string(&c->accessstring, *_argv);
	if (_argc > 3) {
		if (!strcmp(_argv[1], "pap"))
			c->authprotocol = htole32(MBIM_AUTH_PROTOCOL_PAP);
		else if (!strcmp(_argv[1], "chap"))
			c->authprotocol = htole32(MBIM_AUTH_PROTOCOL_CHAP);
		else if (!strcmp(_argv[1], "mschapv2"))
			c->authprotocol = htole32(MBIM_AUTH_PROTOCOL_MSCHAPV2);

		if (c->authprotocol) {
			mbim_encode_string(&c->username, _argv[2]);
			mbim_encode_string(&c->password, _argv[3]);
		}
	}
	return mbim_send_command_msg();
}

static int
mbim_disconnect_request(void)
{
	struct mbim_basic_connect_connect_s *c =
		(struct mbim_basic_connect_connect_s *) mbim_setup_command_msg(basic_connect,
			MBIM_MESSAGE_COMMAND_TYPE_SET, MBIM_CMD_BASIC_CONNECT_CONNECT,
			sizeof(struct mbim_basic_connect_connect_s));

	c->activationcommand = htole32(MBIM_ACTIVATION_COMMAND_DEACTIVATE);
	memcpy(c->contexttype, uuid_context_type_internet, 16);

	no_close = 0;

	return mbim_send_command_msg();
}

static char*
mbim_pin_sanitize(char *pin)
{
	char *p;

	while (*pin && !isdigit(*pin))
		pin++;
	p = pin;
	if (!*p)
		return NULL;
	while (*pin && isdigit(*pin))
		pin++;
	if (*pin)
		*pin = '\0';

	return p;
}

static int
mbim_pin_unlock_request(void)
{
	struct mbim_basic_connect_pin_s *p =
		(struct mbim_basic_connect_pin_s *) mbim_setup_command_msg(basic_connect,
			MBIM_MESSAGE_COMMAND_TYPE_SET, MBIM_CMD_BASIC_CONNECT_PIN,
			sizeof(struct mbim_basic_connect_pin_s));
	char *pin = mbim_pin_sanitize(_argv[0]);

	if (!pin || !strlen(pin)) {
		fprintf(stderr, "failed to sanitize the pincode\n");
		return -1;
	}

	p->pintype = htole32(MBIM_PIN_TYPE_PIN1);
	p->pinoperation = htole32(MBIM_PIN_OPERATION_ENTER);
	mbim_encode_string(&p->pin, _argv[0]);

	return mbim_send_command_msg();
}

static int
mbim_config_request(void)
{
	mbim_setup_command_msg(basic_connect,
		MBIM_MESSAGE_COMMAND_TYPE_QUERY, MBIM_CMD_BASIC_CONNECT_IP_CONFIGURATION,
		sizeof(struct mbim_basic_connect_ip_configuration_q));

	return mbim_send_command_msg();
}

static struct mbim_handler handlers[] = {
	{ "caps", 0, mbim_device_caps_request, mbim_device_caps_response },
	{ "pinstate", 0, mbim_pin_state_request, mbim_pin_state_response },
	{ "unlock", 1, mbim_pin_unlock_request, mbim_pin_state_response },
	{ "registration", 0, mbim_registration_request, mbim_registration_response },
	{ "subscriber", 0, mbim_subscriber_request, mbim_subscriber_response },
	{ "attach", 0, mbim_attach_request, mbim_attach_response },
	{ "detach", 0, mbim_detach_request, mbim_attach_response },
	{ "connect", 0, mbim_connect_request, mbim_connect_response },
	{ "disconnect", 0, mbim_disconnect_request, mbim_connect_response },
	{ "config", 0, mbim_config_request, mbim_config_response },
};

static int
usage(void)
{
	fprintf(stderr, "Usage: mbim <caps|pinstate|unlock|connect|disconnect> [options]\n"
		"Options:\n"
		"    -d <device>	the device (/dev/cdc-wdmX)\n"
		"    -t <transaction>	the transaction id\n"
		"    -n 		no close\n\n"
		"    -v 		verbose\n\n");
	return 1;
}

int
main(int argc, char **argv)
{
	char *cmd, *device = NULL;
	int no_open = 0, ch, i;

	while ((ch = getopt(argc, argv, "nvd:t:")) != -1) {
		switch (ch) {
		case 'v':
			verbose = 1;
			break;
		case 'n':
			no_close = 1;
			break;
		case 'd':
			device = optarg;
			break;
		case 't':
			no_open = 1;
			transaction_id = atoi(optarg);
			break;
		default:
			return usage();
		}
	}

	if (!device || optind == argc)
		return usage();

	cmd = argv[optind];
	optind++;

	_argc = argc - optind;
	_argv = &argv[optind];

	for (i = 0; i < ARRAY_SIZE(handlers); i++)
		if (!strcmp(cmd, handlers[i].name))
			current_handler = &handlers[i];

	if (!current_handler || (optind + current_handler->argc > argc))
		return usage();

	uloop_init();

	mbim_open(device);
	if (!no_open)
		mbim_send_open_msg();
	else if (current_handler->request() < 0)
		return -1;

	uloop_run();
	uloop_done();

	return return_code;
}
