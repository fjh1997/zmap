/*
 * ZMap Windows socket implementation.
 *
 * Backend preference order:
 *   1) XDP for Windows AF_XDP backend (if available)
 *   2) Npcap backend (fallback)
 *
 * Licensed under the Apache License, Version 2.0
 */

#include "socket.h"
#include "xdp-win.h"
#include "send.h"

#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "../lib/includes.h"
#include "../lib/logger.h"

#include "state.h"

#include <pcap.h>

static int str_eq_icase(const char *a, const char *b)
{
	return a && b && _stricmp(a, b) == 0;
}

sock_t get_socket(UNUSED uint32_t id)
{
	sock_t s;
	memset(&s, 0, sizeof(s));
	s.win.raw_sock = INVALID_SOCKET;

	const char *backend_pref = getenv("ZMAP_WIN_BACKEND");
	int prefer_auto = (!backend_pref || str_eq_icase(backend_pref, "auto"));
	int prefer_xdp = str_eq_icase(backend_pref, "xdp");
	int prefer_npcap = str_eq_icase(backend_pref, "npcap");
	int prefer_rawip = str_eq_icase(backend_pref, "rawip");
	int try_xdp = prefer_auto || prefer_xdp;
	int force_xdp = prefer_xdp;

	if (backend_pref && !prefer_auto && !prefer_xdp && !prefer_npcap &&
	    !prefer_rawip) {
		log_warn("send",
			 "unknown ZMAP_WIN_BACKEND value '%s'; expected auto|xdp|npcap|rawip",
			 backend_pref);
	}

	/* --iplayer mode requires an IP-layer sender backend on Windows. */
	if (zconf.send_ip_pkts || prefer_rawip) {
		SOCKET raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
		if (raw_sock == INVALID_SOCKET) {
			log_fatal("send",
				  "unable to open raw IPv4 socket for --iplayer "
				  "(error=%d). Run as Administrator.",
				  WSAGetLastError());
		}
		int one = 1;
		if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, (char *)&one,
			       sizeof(one)) == SOCKET_ERROR) {
			int err = WSAGetLastError();
			closesocket(raw_sock);
			log_fatal("send",
				  "setsockopt(IP_HDRINCL) failed for --iplayer "
				  "(error=%d)",
				  err);
		}
		s.win.backend = WIN_SEND_BACKEND_RAWIP;
		s.win.xdp = NULL;
		s.win.pc = NULL;
		s.win.raw_sock = raw_sock;
		log_info("send", "Windows send backend: RAWIP (--iplayer)");
		return s;
	}

	if (try_xdp) {
		win_xdp_ctx_t *xdp_ctx = NULL;
		if (xdp_win_open(zconf.iface, id, &xdp_ctx)) {
			s.win.backend = WIN_SEND_BACKEND_XDP;
			s.win.xdp = xdp_ctx;
			s.win.pc = NULL;
			log_info("send",
				 "Windows send backend: XDP(queue=%u, %s, L2 frames)",
				 id,
				 xdp_win_is_native_bind(xdp_ctx) ? "native" : "generic");
			return s;
		}

		/* Common home/VM adapters only expose queue 0. */
		if (id != 0 && xdp_win_open(zconf.iface, 0, &xdp_ctx)) {
			s.win.backend = WIN_SEND_BACKEND_XDP;
			s.win.xdp = xdp_ctx;
			s.win.pc = NULL;
			log_info("send",
				 "Windows send backend: XDP(queue=0 fallback from queue=%u, %s, L2 frames)",
				 id,
				 xdp_win_is_native_bind(xdp_ctx) ? "native" : "generic");
			return s;
		}

		if (force_xdp) {
			log_fatal("send",
				  "XDP backend requested but unavailable: %s",
				  xdp_win_last_error());
		}
		log_info("send", "XDP not available (%s); using Npcap backend",
			 xdp_win_last_error());
	}

	char errbuf[PCAP_ERRBUF_SIZE];

	/* Npcap fallback path. */
	pcap_t *pc = pcap_open_live(zconf.iface, 65535,
				    1, /* promiscuous */
				    100, /* timeout ms */
				    errbuf);
	if (!pc) {
		log_fatal("send",
			  "couldn't open device %s for sending. "
			  "Are you running as Administrator? Is Npcap installed? "
			  "Error: %s",
			  zconf.iface, errbuf);
	}

	s.win.backend = WIN_SEND_BACKEND_NPCAP;
	s.win.xdp = NULL;
	s.win.pc = pc;

	/* Pre-allocate the Npcap send queue and offset tracker once.
	 * Reusing them across batches avoids per-batch malloc/free overhead.
	 * Queue is sized for the maximum possible batch (zconf.batch packets,
	 * each up to MAX_PACKET_SIZE bytes plus a pcap_pkthdr). */
	u_int max_queue_bytes =
	    (u_int)zconf.batch *
	    (u_int)(sizeof(struct pcap_pkthdr) + MAX_PACKET_SIZE);
	s.win.npcap_queue = pcap_sendqueue_alloc(max_queue_bytes);
	if (!s.win.npcap_queue) {
		log_fatal("send",
			  "failed to pre-allocate Npcap send queue (%u bytes)",
			  max_queue_bytes);
	}
	s.win.npcap_queue_offsets =
	    (u_int *)malloc(sizeof(u_int) * (size_t)zconf.batch);
	if (!s.win.npcap_queue_offsets) {
		log_fatal("send",
			  "failed to pre-allocate Npcap queue offset array");
	}

	log_info("send", "Windows send backend: Npcap");
	return s;
}
