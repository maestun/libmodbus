/*
 * Copyright © 2001-2011 Stéphane Raimbault <stephane.raimbault@gmail.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#ifndef MODBUS_UDP_PRIVATE_H
#define MODBUS_UDP_PRIVATE_H

#define _MODBUS_UDP_HEADER_LENGTH      7
#define _MODBUS_UDP_PRESET_REQ_LENGTH 12
#define _MODBUS_UDP_PRESET_RSP_LENGTH  8

#define _MODBUS_UDP_CHECKSUM_LENGTH    0

/* In both structures, the transaction ID must be placed on first position
   to have a quick access not dependant of the UDP backend */
typedef struct _modbus_udp {
    /* Extract from MODBUS Messaging on UDP/IP Implementation Guide V1.0b
       (page 23/46):
       The transaction identifier is used to associate the future response
       with the request. This identifier is unique on each UDP connection. */
    uint16_t t_id;
    /* UDP port */
    int port;
    /* IP address */
    char ip[16];
	/* input buffer */
	int _u;
	uint8_t buffer[MODBUS_UDP_MAX_ADU_LENGTH];
} modbus_udp_t;

#endif /* MODBUS_UDP_PRIVATE_H */
