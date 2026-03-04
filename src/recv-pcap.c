/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "recv.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#ifndef _WIN32
#include <unistd.h>
#endif
#include <pthread.h>
#include <assert.h>

#include "../lib/includes.h"
#include "../lib/logger.h"

#include <pcap.h>
#include <pcap/pcap.h>
#if defined(__linux__) && __linux__
#include <pcap/sll.h>
#endif

#include "recv-internal.h"
#include "state.h"
#ifdef _WIN32
#include "xdp-win.h"
#endif

#include "probe_modules/probe_modules.h"

#define PCAP_PROMISC 1
#define PCAP_TIMEOUT_MS 100
#define PCAP_WIN_DEFAULT_BUF_BYTES (64 * 1024 * 1024)

static pcap_t *pc = NULL;
static int pcap_nonblock_enabled = 1;
static int pcap_idle_sleep_ms = 1;
#ifdef _WIN32
#define XDP_MAX_QUEUES 16
static win_xdp_ctx_t *xdp_rx_ctx[XDP_MAX_QUEUES];
static int xdp_rx_ctx_count = 0;
static int use_xdp_rx = 0;
#endif

static int env_get_int(const char *name, int default_value)
{
	const char *value = getenv(name);
	if (!value || !*value) {
		return default_value;
	}
	char *end = NULL;
	long parsed = strtol(value, &end, 10);
	if (!end || *end != '\0') {
		return default_value;
	}
	if (parsed < INT_MIN || parsed > INT_MAX) {
		return default_value;
	}
	return (int)parsed;
}

static int get_capture_timeout_ms(void)
{
	int timeout_ms = PCAP_TIMEOUT_MS;
#ifdef _WIN32
	timeout_ms = env_get_int("ZMAP_WIN_PCAP_TIMEOUT_MS", PCAP_TIMEOUT_MS);
	if (timeout_ms < 1) {
		timeout_ms = 1;
	}
#endif
	return timeout_ms;
}

#ifdef _WIN32
static int str_eq_icase(const char *a, const char *b)
{
	return a && b && _stricmp(a, b) == 0;
}

static int should_use_xdp_rx(void)
{
	const char *rx_backend = getenv("ZMAP_WIN_RX_BACKEND");
	return rx_backend && rx_backend[0] != '\0' &&
	       str_eq_icase(rx_backend, "xdp");
}
#endif

static int bpf_append(char *dst, size_t dst_len, const char *src)
{
	size_t cur = strlen(dst);
	size_t add = strlen(src);
	if (cur + add >= dst_len) {
		return 0;
	}
	memcpy(dst + cur, src, add + 1);
	return 1;
}

static int bpf_appendf(char *dst, size_t dst_len, const char *fmt, ...)
{
	char tmp[128];
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);
	if (n < 0 || (size_t)n >= sizeof(tmp)) {
		return 0;
	}
	return bpf_append(dst, dst_len, tmp);
}

static int append_dst_source_ip_filter(char *bpftmp, size_t bpftmp_len)
{
	if (zconf.number_source_ips == 0) {
		return 1;
	}

	// Keep generated BPF bounded when users provide large source IP ranges.
	uint32_t n = zconf.number_source_ips;
	if (n > 8) {
		n = 8;
		log_debug("recv",
			  "limiting dst-host BPF clause to first %u source IPs",
			  n);
	}

	if (bpftmp[0] != '\0' && !bpf_append(bpftmp, bpftmp_len, " and ")) {
		return 0;
	}
	if (!bpf_append(bpftmp, bpftmp_len, "(")) {
		return 0;
	}
	for (uint32_t i = 0; i < n; i++) {
		struct in_addr src_addr = {.s_addr = zconf.source_ip_addresses[i]};
		const char *src_ip = inet_ntoa(src_addr);
		if (!src_ip || src_ip[0] == '\0') {
			return 0;
		}
		if (i > 0 && !bpf_append(bpftmp, bpftmp_len, " or ")) {
			return 0;
		}
		if (!bpf_appendf(bpftmp, bpftmp_len, "dst host %s", src_ip)) {
			return 0;
		}
	}
	if (!bpf_append(bpftmp, bpftmp_len, ")")) {
		return 0;
	}
	return 1;
}

static pcap_t *open_pcap_handle(const char *iface, int snaplen)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *h = pcap_create(iface, errbuf);
	if (!h) {
		log_debug("recv", "pcap_create failed on %s: %s", iface, errbuf);
		return NULL;
	}

	// Keep behavior close to the old pcap_open_live path, but allow tuning.
	pcap_set_snaplen(h, snaplen);
	pcap_set_promisc(h, PCAP_PROMISC);
	pcap_set_timeout(h, get_capture_timeout_ms());

#ifdef _WIN32
	// Immediate mode reduces delivery latency on Npcap at the cost of more CPU.
	int immediate = env_get_int("ZMAP_WIN_PCAP_IMMEDIATE", 1);
	if (immediate != 0) {
		pcap_set_immediate_mode(h, 1);
	}
	// Larger kernel buffer helps absorb short receive bursts.
	int buf_bytes = env_get_int("ZMAP_WIN_PCAP_BUFFER_BYTES",
				    PCAP_WIN_DEFAULT_BUF_BYTES);
	if (buf_bytes > 0) {
		pcap_set_buffer_size(h, buf_bytes);
	}
#endif

	int rc = pcap_activate(h);
	if (rc < 0) {
		log_debug("recv", "pcap_activate failed on %s: %s", iface,
			  pcap_geterr(h));
		pcap_close(h);
		return NULL;
	}
	if (rc > 0) {
		log_warn("recv", "pcap_activate warning on %s: %s", iface,
			 pcap_statustostr(rc));
	}
	return h;
}

void packet_cb(u_char __attribute__((__unused__)) * user,
	       const struct pcap_pkthdr *p, const u_char *bytes)
{
	struct timespec ts;
	if (!p) {
		return;
	}
	if (zrecv.filter_success >= zconf.max_results) {
		// Libpcap can process multiple packets per pcap_dispatch;
		// we need to throw out results once we've
		// gotten our --max-results worth.
		return;
	}

	// length of entire packet captured by libpcap
	uint32_t buflen = (uint32_t)p->caplen;
	ts.tv_sec = p->ts.tv_sec;
	ts.tv_nsec = p->ts.tv_usec * 1000;
	handle_packet(buflen, bytes, ts);
}

#ifdef _WIN32
static void xdp_packet_cb(uint32_t buflen, const uint8_t *bytes,
			  struct timespec ts, void *user)
{
	(void)user;
	if (!bytes || buflen <= sizeof(struct ether_header)) {
		return;
	}

	const struct ether_header *eth = (const struct ether_header *)bytes;
	if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
		return;
	}

	const uint8_t *ip_ptr = bytes + sizeof(struct ether_header);
	uint32_t ip_len = buflen - (uint32_t)sizeof(struct ether_header);
	if (ip_len < sizeof(struct ip)) {
		return;
	}
	const struct ip *iph = (const struct ip *)ip_ptr;
	if (iph->ip_v != 4) {
		return;
	}

	// Keep XDP RX behavior close to pcap filter: only packets to our source IPs.
	if (zconf.number_source_ips > 0) {
		int dst_match = 0;
		for (uint32_t i = 0; i < zconf.number_source_ips; i++) {
			if (iph->ip_dst.s_addr == zconf.source_ip_addresses[i]) {
				dst_match = 1;
				break;
			}
		}
		if (!dst_match) {
			return;
		}
		// Drop packets whose source IP is also one of our own scan IPs
		// (loopback / NDIS Generic XDP artifacts of our own outbound packets).
		for (uint32_t i = 0; i < zconf.number_source_ips; i++) {
			if (iph->ip_src.s_addr == zconf.source_ip_addresses[i]) {
				return;
			}
		}
	}

	uint8_t ip_hl = (uint8_t)(iph->ip_hl * 4);
	if (ip_hl < sizeof(struct ip) || ip_len < ip_hl) {
		return;
	}
	const uint8_t *l4 = ip_ptr + ip_hl;
	uint32_t l4_len = ip_len - ip_hl;
	if (iph->ip_p == IPPROTO_TCP) {
		if (l4_len < sizeof(struct tcphdr)) {
			return;
		}
		const struct tcphdr *tcp = (const struct tcphdr *)l4;
		uint16_t dport = ntohs(tcp->th_dport);
		if (dport < zconf.source_port_first ||
		    dport > zconf.source_port_last) {
			return;
		}
	} else if (iph->ip_p == IPPROTO_UDP) {
		if (l4_len < sizeof(struct udphdr)) {
			return;
		}
		const struct udphdr *udp = (const struct udphdr *)l4;
		uint16_t dport = ntohs(udp->uh_dport);
		if (dport < zconf.source_port_first ||
		    dport > zconf.source_port_last) {
			return;
		}
	}

	handle_packet(buflen, bytes, ts);
}
#endif

#define BPFLEN 1024

void recv_init(void)
{
	char bpftmp[BPFLEN];
	char errbuf[PCAP_ERRBUF_SIZE];
	int timeout_ms = get_capture_timeout_ms();
#ifdef _WIN32
	int use_dsthost_filter = env_get_int("ZMAP_WIN_PCAP_DSTHOST_FILTER", 0);
#else
	int use_dsthost_filter = 1;
#endif

#ifdef _WIN32
	use_xdp_rx = 0;
	memset(xdp_rx_ctx, 0, sizeof(xdp_rx_ctx));
	xdp_rx_ctx_count = 0;
	if (should_use_xdp_rx()) {
		uint32_t rx_queue = (uint32_t)env_get_int("ZMAP_WIN_XDP_RX_QUEUE", 0);
		int multi = (rx_queue == 0) &&
			    (env_get_int("ZMAP_WIN_XDP_RX_MULTI", 1) != 0);
		if (multi) {
			// Try to open one XSK per RSS queue until bind fails.
			for (uint32_t q = 0; q < XDP_MAX_QUEUES; q++) {
				win_xdp_ctx_t *ctx = NULL;
				if (!xdp_win_open_rx(zconf.iface, q, &ctx)) {
					break;
				}
				xdp_rx_ctx[xdp_rx_ctx_count++] = ctx;
			}
		} else {
			win_xdp_ctx_t *ctx = NULL;
			if (xdp_win_open_rx(zconf.iface, rx_queue, &ctx) ||
			    (rx_queue != 0 &&
			     xdp_win_open_rx(zconf.iface, 0, &ctx))) {
				xdp_rx_ctx[xdp_rx_ctx_count++] = ctx;
			}
		}
		if (xdp_rx_ctx_count > 0) {
			use_xdp_rx = 1;
			pc = NULL;
			zconf.data_link_size = sizeof(struct ether_header);
			pcap_nonblock_enabled = 1;
			pcap_idle_sleep_ms =
			    env_get_int("ZMAP_WIN_PCAP_IDLE_SLEEP_MS", 1);
			if (pcap_idle_sleep_ms < 0) {
				pcap_idle_sleep_ms = 0;
			}
			log_info("recv",
				 "Windows receive backend: XDP(%d queue(s), %s)",
				 xdp_rx_ctx_count,
				 xdp_win_is_native_bind(xdp_rx_ctx[0]) ? "native" : "generic");
			return;
		}
		log_info("recv", "XDP RX not available (%s); using Npcap backend",
			 xdp_win_last_error());
	}
#endif

	pc = open_pcap_handle(zconf.iface, zconf.probe_module->pcap_snaplen);
	if (!pc) {
		pc = pcap_open_live(zconf.iface, zconf.probe_module->pcap_snaplen,
				    PCAP_PROMISC, timeout_ms, errbuf);
	}
	if (pc == NULL) {
		log_fatal("recv", "could not open device %s: %s", zconf.iface,
			  errbuf);
	}
	switch (pcap_datalink(pc)) {
	case DLT_NULL:
		// utun on macOS
		log_debug("recv", "BSD loopback encapsulation");
		zconf.data_link_size = 4;
		break;
	case DLT_EN10MB:
		log_debug("recv", "Data link layer Ethernet");
		zconf.data_link_size = sizeof(struct ether_header);
		break;
	case DLT_RAW:
		log_info("recv", "Data link RAW");
		zconf.data_link_size = 0;
		break;
#if defined __linux__ && __linux__
	case DLT_LINUX_SLL:
		log_info("recv", "Data link cooked socket");
		zconf.data_link_size = SLL_HDR_LEN;
		break;
#endif
	default:
		log_error("recv", "unknown data link layer: %u", pcap_datalink(pc));
	}

	struct bpf_program bpf;

	if (!zconf.send_ip_pkts) {
		snprintf(bpftmp, sizeof(bpftmp) - 1,
			 "not ether src %02x:%02x:%02x:%02x:%02x:%02x",
			 zconf.hw_mac[0], zconf.hw_mac[1], zconf.hw_mac[2],
			 zconf.hw_mac[3], zconf.hw_mac[4], zconf.hw_mac[5]);
		assert(strlen(zconf.probe_module->pcap_filter) + 10 <
		       (BPFLEN - strlen(bpftmp)));
	} else {
		bpftmp[0] = 0;
	}
	if (zconf.probe_module->pcap_filter) {
		if (!zconf.send_ip_pkts) {
			strcat(bpftmp, " and (");
		} else {
			strcat(bpftmp, "(");
		}
		strcat(bpftmp, zconf.probe_module->pcap_filter);
		strcat(bpftmp, ")");
	}
	char bpftmp_base[BPFLEN];
	memcpy(bpftmp_base, bpftmp, sizeof(bpftmp_base));
	if (use_dsthost_filter) {
		if (!append_dst_source_ip_filter(bpftmp, sizeof(bpftmp))) {
			log_warn("recv",
				 "BPF expression too long while appending dst-host filter; using base filter");
			memcpy(bpftmp, bpftmp_base, sizeof(bpftmp));
		}
	} else {
		log_debug("recv",
			  "Windows high-visibility mode: dst-host BPF clause disabled");
	}
	if (strcmp(bpftmp, "")) {
		if (pcap_compile(pc, &bpf, bpftmp, 1, 0) < 0) {
			log_fatal("recv", "couldn't compile filter: %s", bpftmp);
		}
		if (pcap_setfilter(pc, &bpf) < 0) {
			log_fatal("recv", "couldn't install filter");
		}
		pcap_freecode(&bpf);
	}
	// set pcap_dispatch to not hang if it never receives any packets
	// this could occur if you ever scan a small number of hosts as
	// documented in issue #74.
#ifdef _WIN32
	pcap_nonblock_enabled = env_get_int("ZMAP_WIN_PCAP_NONBLOCK", 0) != 0;
	pcap_idle_sleep_ms = env_get_int("ZMAP_WIN_PCAP_IDLE_SLEEP_MS", 1);
	if (pcap_idle_sleep_ms < 0) {
		pcap_idle_sleep_ms = 0;
	}
#else
	pcap_nonblock_enabled = 1;
	pcap_idle_sleep_ms = 1;
#endif
	if (pcap_setnonblock(pc, pcap_nonblock_enabled ? 1 : 0, errbuf) == -1) {
		log_fatal("recv", "pcap_setnonblock error:%s", errbuf);
	}
#ifdef PCAP_D_IN
#ifdef _WIN32
	int pcap_direction = env_get_int("ZMAP_WIN_PCAP_DIRECTION", 0);
	if (pcap_direction == 1) {
		if (pcap_setdirection(pc, PCAP_D_IN) != 0) {
			log_debug("recv",
				  "pcap_setdirection(PCAP_D_IN) not supported: %s",
				  pcap_geterr(pc));
		}
	}
#else
	// Keep Linux/macOS behavior unchanged.
	if (pcap_setdirection(pc, PCAP_D_IN) != 0) {
		log_debug("recv", "pcap_setdirection(PCAP_D_IN) not supported: %s",
			  pcap_geterr(pc));
	}
#endif
#endif
}

void recv_packets(void)
{
	zrecv.pcap_dispatch_calls++;
#ifdef _WIN32
	if (use_xdp_rx && xdp_rx_ctx_count > 0) {
		uint32_t wait_ms =
		    (pcap_idle_sleep_ms > 0) ? (uint32_t)pcap_idle_sleep_ms : 0;
		int total = 0;
		for (int i = 0; i < xdp_rx_ctx_count; i++) {
			// Only block-wait on the last socket; others poll non-blocking
			// to avoid accumulating wait_ms × n_queues of latency.
			uint32_t w =
			    (i == xdp_rx_ctx_count - 1) ? wait_ms : 0;
			int ret = xdp_win_recv(xdp_rx_ctx[i], w, xdp_packet_cb,
					       NULL);
			if (ret < 0) {
				log_fatal("recv", "xdp_win_recv error");
			} else {
				total += ret;
			}
		}
		if (total == 0) {
			zrecv.pcap_dispatch_zero++;
		} else {
			zrecv.pcap_dispatch_packets += (uint64_t)total;
		}
		return;
	}
#endif
	int ret = pcap_dispatch(pc, -1, packet_cb, NULL);
	if (ret == -1) {
		log_fatal("recv", "pcap_dispatch error");
	} else if (ret == 0) {
		zrecv.pcap_dispatch_zero++;
		if (pcap_nonblock_enabled) {
#ifdef _WIN32
			if (pcap_idle_sleep_ms > 0) {
				Sleep((DWORD)pcap_idle_sleep_ms);
			}
#else
			usleep(1000);
#endif
		}
	} else {
		zrecv.pcap_dispatch_packets += (uint64_t)ret;
	}
}

void recv_cleanup(void)
{
#ifdef _WIN32
	for (int i = 0; i < xdp_rx_ctx_count; i++) {
		if (xdp_rx_ctx[i]) {
			xdp_win_close(xdp_rx_ctx[i]);
			xdp_rx_ctx[i] = NULL;
		}
	}
	xdp_rx_ctx_count = 0;
	use_xdp_rx = 0;
#endif
	if (pc) {
		pcap_close(pc);
		pc = NULL;
	}
}

int recv_update_stats(void)
{
#ifdef _WIN32
	if (use_xdp_rx && xdp_rx_ctx_count > 0) {
		zrecv.pcap_recv = zrecv.packets_seen;
		zrecv.pcap_drop = 0;
		zrecv.pcap_ifdrop = 0;
		return EXIT_SUCCESS;
	}
#endif
	if (!pc) {
		return EXIT_FAILURE;
	}
	struct pcap_stat pcst;
	if (pcap_stats(pc, &pcst)) {
		log_error("recv", "unable to retrieve pcap statistics: %s",
			  pcap_geterr(pc));
		return EXIT_FAILURE;
	} else {
		zrecv.pcap_recv = pcst.ps_recv;
		zrecv.pcap_drop = pcst.ps_drop;
		zrecv.pcap_ifdrop = pcst.ps_ifdrop;
	}
	return EXIT_SUCCESS;
}
