/*
 * ZMap Windows send implementation.
 *
 * Uses XDP (AF_XDP driver backend) when available, and falls back to Npcap.
 * For Npcap it prefers pcap_sendqueue_transmit() batching and falls back to
 * per-packet pcap_sendpacket().
 *
 * Licensed under the Apache License, Version 2.0
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>

#include <pcap.h>

#include "../lib/includes.h"
#include "../lib/logger.h"
#include "./send.h"
#include "state.h"
#include "xdp-win.h"

int send_run_init(sock_t s)
{
	/* In dryrun mode we intentionally skip opening a pcap socket. */
	if (zconf.dryrun) {
		return EXIT_SUCCESS;
	}

	if (s.win.backend == WIN_SEND_BACKEND_XDP) {
		if (!s.win.xdp) {
			log_error("send", "send_run_init: XDP context is NULL");
			return EXIT_FAILURE;
		}
		return EXIT_SUCCESS;
	}

	if (s.win.backend == WIN_SEND_BACKEND_RAWIP) {
		if (s.win.raw_sock == INVALID_SOCKET) {
			log_error("send", "send_run_init: RAWIP socket is invalid");
			return EXIT_FAILURE;
		}
		return EXIT_SUCCESS;
	}

	if (s.win.backend == WIN_SEND_BACKEND_NPCAP) {
		if (!s.win.pc) {
			log_error("send", "send_run_init: pcap handle is NULL");
			return EXIT_FAILURE;
		}
		return EXIT_SUCCESS;
	}

	log_error("send", "send_run_init: invalid Windows send backend (%d)",
		  s.win.backend);
	return EXIT_FAILURE;
}

void send_run_cleanup(sock_t s)
{
	if (s.win.backend == WIN_SEND_BACKEND_XDP && s.win.xdp) {
		xdp_win_close(s.win.xdp);
		return;
	}
	if (s.win.backend == WIN_SEND_BACKEND_RAWIP &&
	    s.win.raw_sock != INVALID_SOCKET) {
		closesocket(s.win.raw_sock);
		return;
	}
	if (s.win.backend == WIN_SEND_BACKEND_NPCAP && s.win.pc) {
		if (s.win.npcap_queue) {
			pcap_sendqueue_destroy(s.win.npcap_queue);
		}
		free(s.win.npcap_queue_offsets);
		pcap_close(s.win.pc);
		return;
	}
}

static int send_batch_rawip(sock_t sock, batch_t *batch, int retries)
{
	int total_packets_sent = 0;
	int logged_send_error = 0;
	for (int i = 0; i < batch->len; i++) {
		uint8_t *pkt = batch->packets[i].buf;
		uint32_t pkt_len = batch->packets[i].len;

		if (!zconf.send_ip_pkts) {
			if (pkt_len <= sizeof(struct ether_header)) {
				continue;
			}
			pkt += sizeof(struct ether_header);
			pkt_len -= sizeof(struct ether_header);
		}

		if (pkt_len < sizeof(struct ip)) {
			continue;
		}
		struct ip *iph = (struct ip *)pkt;
		struct sockaddr_in dst;
		memset(&dst, 0, sizeof(dst));
		dst.sin_family = AF_INET;
		dst.sin_addr.s_addr = iph->ip_dst.s_addr;

		int sent_ok = 0;
		for (int attempt = 0; attempt < retries; attempt++) {
			int rc = sendto(sock.win.raw_sock, (const char *)pkt,
					(int)pkt_len, 0,
					(const struct sockaddr *)&dst,
					(int)sizeof(dst));
			if (rc == (int)pkt_len) {
				sent_ok = 1;
				break;
			}
			if (!logged_send_error) {
				log_warn("send",
					 "RAWIP sendto failed: rc=%d err=%d pkt_len=%u",
					 rc, WSAGetLastError(), pkt_len);
				logged_send_error = 1;
			}
		}
		if (sent_ok) {
			total_packets_sent++;
		}
	}
	return total_packets_sent;
}

static int send_batch_packets(sock_t sock, batch_t *batch, int retries)
{
	int total_packets_sent = 0;

	for (int i = 0; i < batch->len; ++i) {
		uint8_t *pkt_buf = batch->packets[i].buf;
		uint32_t pkt_len = batch->packets[i].len;

		int success = 0;
		for (int attempt = 0; attempt < retries; attempt++) {
			if (pcap_sendpacket(sock.win.pc, pkt_buf, pkt_len) == 0) {
				success = 1;
				break;
			}
			log_debug("send",
				  "pcap_sendpacket failed (attempt %d/%d): %s",
				  attempt + 1, retries,
				  pcap_geterr(sock.win.pc));
		}
		if (success) {
			total_packets_sent++;
		} else {
			log_error("send",
				  "pcap_sendpacket failed after %d retries: %s",
				  retries, pcap_geterr(sock.win.pc));
		}
	}
	return total_packets_sent;
}

static int send_batch_queue(sock_t sock, batch_t *batch, int retries)
{
	/* Use the pre-allocated queue and offset array from the socket context.
	 * Reset queue->len to 0 to reuse the already-allocated buffer. */
	pcap_send_queue *queue = sock.win.npcap_queue;
	u_int *queue_offsets = sock.win.npcap_queue_offsets;
	if (!queue || !queue_offsets) {
		log_debug("send", "pre-allocated Npcap queue unavailable; falling back");
		return -1;
	}
	queue->len = 0;

	struct pcap_pkthdr pkt_hdr;
	memset(&pkt_hdr, 0, sizeof(pkt_hdr));

	for (int i = 0; i < batch->len; ++i) {
		pkt_hdr.caplen = batch->packets[i].len;
		pkt_hdr.len = batch->packets[i].len;
		if (pcap_sendqueue_queue(queue, &pkt_hdr, batch->packets[i].buf) ==
		    -1) {
			log_debug("send",
				  "pcap_sendqueue_queue failed; falling back");
			return -1;
		}
		queue_offsets[i] = queue->len;
	}

	u_int sent_bytes = 0;
	for (int attempt = 0; attempt < retries; ++attempt) {
		sent_bytes = pcap_sendqueue_transmit(sock.win.pc, queue, 0);
		if (sent_bytes == queue->len) {
			return batch->len;
		}
		/* Do not re-submit after a partial send; it would duplicate traffic. */
		if (sent_bytes > 0) {
			break;
		}
		log_debug("send",
			  "pcap_sendqueue_transmit failed (attempt %d/%d): %s",
			  attempt + 1, retries, pcap_geterr(sock.win.pc));
	}

	if (sent_bytes == 0) {
		log_debug("send",
			  "pcap_sendqueue_transmit sent 0 bytes after retries");
		return -1;
	}

	int sent_packets = 0;
	while (sent_packets < batch->len &&
	       queue_offsets[sent_packets] <= sent_bytes) {
		sent_packets++;
	}
	log_warn("send",
		 "pcap_sendqueue_transmit partial send: %u/%u bytes (%d/%d packets)",
		 sent_bytes, queue->len, sent_packets, batch->len);
	return sent_packets;
}

int send_batch(sock_t sock, batch_t *batch, int retries)
{
	if (batch->len == 0) {
		return EXIT_SUCCESS;
	}

	if (sock.win.backend == WIN_SEND_BACKEND_XDP) {
		return xdp_win_send_batch(sock.win.xdp, batch, retries);
	}
	if (sock.win.backend == WIN_SEND_BACKEND_RAWIP) {
		return send_batch_rawip(sock, batch, retries);
	}
	if (sock.win.backend != WIN_SEND_BACKEND_NPCAP) {
		log_error("send", "invalid Windows send backend (%d)",
			  sock.win.backend);
		return -1;
	}

	int rc = send_batch_queue(sock, batch, retries);
	if (rc >= 0) {
		return rc;
	}
	return send_batch_packets(sock, batch, retries);
}
