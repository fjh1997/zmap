/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef ZMAP_SOCKET_H
#define ZMAP_SOCKET_H

#include <stdint.h>

#include "../lib/includes.h"

#if defined(PFRING) && defined(NETMAP)
#error "PFRING and NETMAP are mutually exclusive, only define one of them"
#endif

#ifdef PFRING
#include <pfring_zc.h>
#endif

#ifdef _WIN32
typedef enum {
	WIN_SEND_BACKEND_NONE = 0,
	WIN_SEND_BACKEND_NPCAP = 1,
	WIN_SEND_BACKEND_XDP = 2,
	WIN_SEND_BACKEND_RAWIP = 3,
} win_send_backend_t;

struct win_xdp_ctx;
#endif

typedef union {
#ifdef PFRING
	struct {
		pfring_zc_queue *queue;
		pfring_zc_pkt_buff **buffers;
		int idx;
	} pf;
#elif defined(NETMAP)
	struct {
		uint32_t tx_ring_idx;
		int tx_ring_fd;
	} nm;
#elif defined(_WIN32)
	struct {
		win_send_backend_t backend;
		struct win_xdp_ctx *xdp;
		struct pcap *pc;             /* Npcap handle for sending */
		SOCKET raw_sock;             /* Raw IPv4 socket for --iplayer */
		pcap_send_queue *npcap_queue;   /* pre-allocated batch send queue */
		u_int *npcap_queue_offsets;     /* per-packet byte-offset tracker */
	} win;
#else
	int sock;
#endif
} sock_t;

sock_t get_dryrun_socket(void);
sock_t get_socket(uint32_t id);

#endif /* ZMAP_SOCKET_H */
