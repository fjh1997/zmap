/*
 * Windows compatibility layer for ZMap
 *
 * Licensed under the Apache License, Version 2.0
 */

#ifndef ZMAP_COMPAT_WIN_H
#define ZMAP_COMPAT_WIN_H

#ifdef _WIN32

/* Must include winsock2 before windows.h */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdint.h>
#include <io.h>
#include <process.h>
#include <pcap/pcap.h>

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#endif

/* Define BYTE_ORDER for Windows (always little-endian on x86/x64) */
#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN 1234
#endif
#ifndef BIG_ENDIAN
#define BIG_ENDIAN 4321
#endif
#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#endif

/* ---- Missing POSIX type definitions ---- */

#ifndef IFNAMSIZ
#define IFNAMSIZ 256  /* Windows NPF device paths are ~50+ chars */
#endif

/* Missing POSIX types on Windows */
#ifndef _IN_ADDR_T_DEFINED
#define _IN_ADDR_T_DEFINED
typedef uint32_t in_addr_t;
#endif

typedef unsigned int uint;

/* syslog-style log levels (used in state.c) */
#ifndef LOG_EMERG
#define LOG_EMERG 0
#define LOG_ALERT 1
#define LOG_CRIT 2
#define LOG_ERR 3
#define LOG_WARNING 4
#define LOG_NOTICE 5
#define LOG_INFO 6
#define LOG_DEBUG 7
#endif

/* IP default TTL */
#ifndef IPDEFTTL
#define IPDEFTTL 64
#endif

/* IPPROTO_IPIP - IP-in-IP encapsulation */
#ifndef IPPROTO_IPIP
#define IPPROTO_IPIP 4
#endif

#ifndef IF_NAMESIZE
#define IF_NAMESIZE IFNAMSIZ
#endif

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN ETH_ALEN
#endif

#ifndef IFHWADDRLEN
#define IFHWADDRLEN 6
#endif

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP 0x0800
#endif

#ifndef ETH_P_ALL
#define ETH_P_ALL 0x0003
#endif

/* ---- Ethernet header ---- */

struct ether_header {
	uint8_t ether_dhost[ETH_ALEN];
	uint8_t ether_shost[ETH_ALEN];
	uint16_t ether_type;
};

/* ---- IP header (BSD-style) ---- */

struct ip {
#if BYTE_ORDER == LITTLE_ENDIAN
	uint8_t ip_hl : 4;
	uint8_t ip_v : 4;
#else
	uint8_t ip_v : 4;
	uint8_t ip_hl : 4;
#endif
	uint8_t ip_tos;
	uint16_t ip_len;
	uint16_t ip_id;
	uint16_t ip_off;
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
	uint8_t ip_ttl;
	uint8_t ip_p;
	uint16_t ip_sum;
	struct in_addr ip_src, ip_dst;
};

/* ---- TCP header (BSD-style) ---- */

struct tcphdr {
	uint16_t th_sport;
	uint16_t th_dport;
	uint32_t th_seq;
	uint32_t th_ack;
#if BYTE_ORDER == LITTLE_ENDIAN
	uint8_t th_x2 : 4;
	uint8_t th_off : 4;
#else
	uint8_t th_off : 4;
	uint8_t th_x2 : 4;
#endif
	uint8_t th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
	uint16_t th_win;
	uint16_t th_sum;
	uint16_t th_urp;
};

/* TCP option constants (from Linux netinet/tcp.h) */
#ifndef TCPOPT_EOL
#define TCPOPT_EOL 0
#endif
#ifndef TCPOPT_NOP
#define TCPOPT_NOP 1
#endif
#ifndef TCPOPT_MAXSEG
#define TCPOPT_MAXSEG 2
#endif
#ifndef TCPOLEN_MAXSEG
#define TCPOLEN_MAXSEG 4
#endif
#ifndef TCPOPT_WINDOW
#define TCPOPT_WINDOW 3
#endif
#ifndef TCPOLEN_WINDOW
#define TCPOLEN_WINDOW 3
#endif
#ifndef TCPOPT_SACK_PERMITTED
#define TCPOPT_SACK_PERMITTED 4
#endif
#ifndef TCPOLEN_SACK_PERMITTED
#define TCPOLEN_SACK_PERMITTED 2
#endif
#ifndef TCPOPT_TIMESTAMP
#define TCPOPT_TIMESTAMP 8
#endif
#ifndef TCPOLEN_TIMESTAMP
#define TCPOLEN_TIMESTAMP 10
#endif

/* ICMP minimum length */
#ifndef ICMP_MINLEN
#define ICMP_MINLEN 8
#endif

/* ---- UDP header ---- */

struct udphdr {
	uint16_t uh_sport;
	uint16_t uh_dport;
	uint16_t uh_ulen;
	uint16_t uh_sum;
};

/* ---- ICMP header ---- */

#ifndef ICMP_ECHOREPLY
#define ICMP_ECHOREPLY 0
#endif
#ifndef ICMP_DEST_UNREACH
#define ICMP_DEST_UNREACH 3
#endif
#ifndef ICMP_UNREACH
#define ICMP_UNREACH ICMP_DEST_UNREACH
#endif
#ifndef ICMP_SOURCE_QUENCH
#define ICMP_SOURCE_QUENCH 4
#endif
#ifndef ICMP_SOURCEQUENCH
#define ICMP_SOURCEQUENCH ICMP_SOURCE_QUENCH
#endif
#ifndef ICMP_REDIRECT
#define ICMP_REDIRECT 5
#endif
#ifndef ICMP_ECHO
#define ICMP_ECHO 8
#endif
#ifndef ICMP_TIME_EXCEEDED
#define ICMP_TIME_EXCEEDED 11
#endif
#ifndef ICMP_TIMXCEED
#define ICMP_TIMXCEED ICMP_TIME_EXCEEDED
#endif
#ifndef ICMP_PARAMETERPROB
#define ICMP_PARAMETERPROB 12
#endif
#ifndef ICMP_TIMESTAMP
#define ICMP_TIMESTAMP 13
#endif
#ifndef ICMP_TIMESTAMPREPLY
#define ICMP_TIMESTAMPREPLY 14
#endif

/* ICMP unreach codes */
#ifndef ICMP_UNREACH_NET
#define ICMP_UNREACH_NET 0
#endif
#ifndef ICMP_UNREACH_HOST
#define ICMP_UNREACH_HOST 1
#endif
#ifndef ICMP_UNREACH_PROTOCOL
#define ICMP_UNREACH_PROTOCOL 2
#endif
#ifndef ICMP_UNREACH_PORT
#define ICMP_UNREACH_PORT 3
#endif
#ifndef ICMP_UNREACH_NEEDFRAG
#define ICMP_UNREACH_NEEDFRAG 4
#endif
#ifndef ICMP_UNREACH_SRCFAIL
#define ICMP_UNREACH_SRCFAIL 5
#endif
#ifndef ICMP_UNREACH_NET_UNKNOWN
#define ICMP_UNREACH_NET_UNKNOWN 6
#endif
#ifndef ICMP_UNREACH_HOST_UNKNOWN
#define ICMP_UNREACH_HOST_UNKNOWN 7
#endif
#ifndef ICMP_UNREACH_ISOLATED
#define ICMP_UNREACH_ISOLATED 8
#endif
#ifndef ICMP_UNREACH_NET_PROHIB
#define ICMP_UNREACH_NET_PROHIB 9
#endif
#ifndef ICMP_UNREACH_HOST_PROHIB
#define ICMP_UNREACH_HOST_PROHIB 10
#endif
#ifndef ICMP_UNREACH_TOSNET
#define ICMP_UNREACH_TOSNET 11
#endif
#ifndef ICMP_UNREACH_TOSHOST
#define ICMP_UNREACH_TOSHOST 12
#endif
#ifndef ICMP_UNREACH_FILTER_PROHIB
#define ICMP_UNREACH_FILTER_PROHIB 13
#endif
#ifndef ICMP_UNREACH_PRECEDENCE_CUTOFF
#define ICMP_UNREACH_PRECEDENCE_CUTOFF 15
#endif

struct icmp {
	uint8_t icmp_type;
	uint8_t icmp_code;
	uint16_t icmp_cksum;
	union {
		struct {
			uint16_t id;
			uint16_t sequence;
		} echo;
		uint32_t gateway;
		struct {
			uint16_t _unused_field;
			uint16_t mtu;
		} frag;
	} icmp_hun;
#define icmp_id icmp_hun.echo.id
#define icmp_seq icmp_hun.echo.sequence
#define icmp_void icmp_hun.gateway
#define icmp_pmvoid icmp_hun.frag.__unused
#define icmp_nextmtu icmp_hun.frag.mtu
	union {
		struct {
			uint32_t ts_otime;
			uint32_t ts_rtime;
			uint32_t ts_ttime;
		} ts;
		struct ip ip;
		uint8_t data[1];
	} icmp_dun;
#define icmp_otime icmp_dun.ts.ts_otime
#define icmp_rtime icmp_dun.ts.ts_rtime
#define icmp_ttime icmp_dun.ts.ts_ttime
#define icmp_ip icmp_dun.ip
#define icmp_data icmp_dun.data
};

/* ---- POSIX function replacements ---- */

/* sleep/usleep/nanosleep are provided by MinGW natively */

/* struct timespec is already provided by MSYS2/MinGW headers */
/* nanosleep is already provided by MinGW via pthread_time.h */

/* gettimeofday */
#ifndef _TIMEVAL_DEFINED
#define _TIMEVAL_DEFINED
/* winsock2.h already defines timeval */
#endif

static inline int gettimeofday_compat(struct timeval *tv, void *tz)
{
	(void)tz;
	if (tv) {
		FILETIME ft;
		GetSystemTimeAsFileTime(&ft);
		uint64_t time =
		    ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
		/* Convert from 100-ns intervals since 1601 to Unix epoch */
		time -= 116444736000000000ULL;
		tv->tv_sec = (long)(time / 10000000ULL);
		tv->tv_usec = (long)((time % 10000000ULL) / 10);
	}
	return 0;
}

/* Only redefine gettimeofday if not already provided by MinGW */
#ifndef gettimeofday
#define gettimeofday gettimeofday_compat
#endif

/* MinGW provides fileno, isatty, getpid natively - no redefinition needed */

/* strndup - not available in MinGW */
static inline char *strndup(const char *s, size_t n)
{
	size_t len = strlen(s);
	if (len > n) len = n;
	char *result = (char *)malloc(len + 1);
	if (!result) return NULL;
	memcpy(result, s, len);
	result[len] = '\0';
	return result;
}

/* strsep - not available in MinGW */
static inline char *strsep(char **stringp, const char *delim)
{
	char *start = *stringp;
	char *p;
	if (start == NULL) return NULL;
	p = strpbrk(start, delim);
	if (p) {
		*p = '\0';
		*stringp = p + 1;
	} else {
		*stringp = NULL;
	}
	return start;
}

/* getline - not available in MinGW */
static inline ssize_t getline(char **lineptr, size_t *n, FILE *stream)
{
	if (!lineptr || !n || !stream) return -1;
	size_t pos = 0;
	int c;
	if (!*lineptr) {
		*n = 128;
		*lineptr = (char *)malloc(*n);
		if (!*lineptr) return -1;
	}
	while ((c = fgetc(stream)) != EOF) {
		if (pos + 1 >= *n) {
			*n *= 2;
			char *tmp = (char *)realloc(*lineptr, *n);
			if (!tmp) return -1;
			*lineptr = tmp;
		}
		(*lineptr)[pos++] = (char)c;
		if (c == '\n') break;
	}
	if (pos == 0 && c == EOF) return -1;
	(*lineptr)[pos] = '\0';
	return (ssize_t)pos;
}

/* strerror for winsock errors */
static inline const char *winsock_strerror(int err)
{
	static char buf[256];
	FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		       NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		       buf, sizeof(buf), NULL);
	return buf;
}

/* ---- Signals ---- */
/* MSYS2/MinGW signal.h provides SIGUSR1/SIGUSR2 */

/* ---- Networking helpers ---- */

/* inet_ntoa/inet_aton are available in ws2tcpip */
/* inet_aton is NOT available on Windows, provide a wrapper using inet_pton */
static inline int inet_aton(const char *cp, struct in_addr *inp)
{
	return inet_pton(AF_INET, cp, inp) == 1 ? 1 : 0;
}

/* MAC_ADDR_LEN */
#define MAC_ADDR_LEN ETHER_ADDR_LEN

/* UNUSED attribute */
#ifndef UNUSED
#define UNUSED __attribute__((unused))
#endif

/* ---- Windows-specific initialization ---- */

static inline int zmap_win_init(void)
{
	WSADATA wsa;
	return WSAStartup(MAKEWORD(2, 2), &wsa);
}

static inline void zmap_win_cleanup(void)
{
	WSACleanup();
}

#endif /* _WIN32 */

#endif /* ZMAP_COMPAT_WIN_H */
