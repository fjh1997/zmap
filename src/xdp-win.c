/*
 * Windows XDP (AF_XDP) send backend for ZMap.
 *
 * Licensed under the Apache License, Version 2.0
 */

#ifdef _WIN32

#include "xdp-win.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <iphlpapi.h>

#include "../lib/logger.h"
#include "state.h"

#ifndef GAA_FLAG_INCLUDE_ALL_INTERFACES
#define GAA_FLAG_INCLUDE_ALL_INTERFACES 0x0100
#endif

#define XDP_API_VERSION_2 2U

typedef enum _XSK_BIND_FLAGS {
	XSK_BIND_FLAG_NONE = 0x0,
	XSK_BIND_FLAG_RX = 0x1,
	XSK_BIND_FLAG_TX = 0x2,
	XSK_BIND_FLAG_GENERIC = 0x4,
	XSK_BIND_FLAG_NATIVE = 0x8,
} XSK_BIND_FLAGS;

typedef enum _XDP_CREATE_PROGRAM_FLAGS {
	XDP_CREATE_PROGRAM_FLAG_NONE = 0x0,
	XDP_CREATE_PROGRAM_FLAG_GENERIC = 0x1,
	XDP_CREATE_PROGRAM_FLAG_NATIVE = 0x2,
	XDP_CREATE_PROGRAM_FLAG_ALL_QUEUES = 0x4,
} XDP_CREATE_PROGRAM_FLAGS;

typedef enum _XDP_HOOK_LAYER {
	XDP_HOOK_L2 = 0,
} XDP_HOOK_LAYER;

typedef enum _XDP_HOOK_DATAPATH_DIRECTION {
	XDP_HOOK_RX = 0,
	XDP_HOOK_TX = 1,
} XDP_HOOK_DATAPATH_DIRECTION;

typedef enum _XDP_HOOK_SUBLAYER {
	XDP_HOOK_INSPECT = 0,
	XDP_HOOK_INJECT = 1,
} XDP_HOOK_SUBLAYER;

typedef struct _XDP_HOOK_ID {
	XDP_HOOK_LAYER Layer;
	XDP_HOOK_DATAPATH_DIRECTION Direction;
	XDP_HOOK_SUBLAYER SubLayer;
} XDP_HOOK_ID;

typedef enum _XDP_MATCH_TYPE {
	XDP_MATCH_ALL = 0,
	XDP_MATCH_UDP,
	XDP_MATCH_UDP_DST,
	XDP_MATCH_IPV4_DST_MASK,
	XDP_MATCH_IPV6_DST_MASK,
	XDP_MATCH_QUIC_FLOW_SRC_CID,
	XDP_MATCH_QUIC_FLOW_DST_CID,
	XDP_MATCH_IPV4_UDP_TUPLE,
	XDP_MATCH_IPV6_UDP_TUPLE,
	XDP_MATCH_UDP_PORT_SET,
	XDP_MATCH_IPV4_UDP_PORT_SET,
	XDP_MATCH_IPV6_UDP_PORT_SET,
	XDP_MATCH_IPV4_TCP_PORT_SET,
	XDP_MATCH_IPV6_TCP_PORT_SET,
	XDP_MATCH_TCP_DST,
	XDP_MATCH_TCP_QUIC_FLOW_SRC_CID,
	XDP_MATCH_TCP_QUIC_FLOW_DST_CID,
	XDP_MATCH_TCP_CONTROL_DST,
	XDP_MATCH_IP_NEXT_HEADER,
	XDP_MATCH_INNER_IPV4_DST_MASK_UDP,
	XDP_MATCH_INNER_IPV6_DST_MASK_UDP,
	XDP_MATCH_ICMPV4_ECHO_REPLY_IP_DST,
	XDP_MATCH_ICMPV6_ECHO_REPLY_IP_DST,
} XDP_MATCH_TYPE;

typedef union _XDP_INET_ADDR {
	IN_ADDR Ipv4;
	IN6_ADDR Ipv6;
} XDP_INET_ADDR;

typedef struct _XDP_IP_ADDRESS_MASK {
	XDP_INET_ADDR Mask;
	XDP_INET_ADDR Address;
} XDP_IP_ADDRESS_MASK;

typedef struct _XDP_TUPLE {
	XDP_INET_ADDR SourceAddress;
	XDP_INET_ADDR DestinationAddress;
	UINT16 SourcePort;
	UINT16 DestinationPort;
} XDP_TUPLE;

#define XDP_QUIC_MAX_CID_LENGTH 20
typedef struct _XDP_QUIC_FLOW {
	UINT16 UdpPort;
	UCHAR CidLength;
	UCHAR CidOffset;
	UCHAR CidData[XDP_QUIC_MAX_CID_LENGTH];
} XDP_QUIC_FLOW;

#define XDP_PORT_SET_BUFFER_SIZE ((UINT16_MAX + 1U) / 8U)
typedef struct _XDP_PORT_SET {
	const UINT8 *PortSet;
	VOID *Reserved;
} XDP_PORT_SET;

typedef struct _XDP_IP_PORT_SET {
	XDP_INET_ADDR Address;
	XDP_PORT_SET PortSet;
} XDP_IP_PORT_SET;

typedef union _XDP_MATCH_PATTERN {
	UINT16 Port;
	XDP_IP_ADDRESS_MASK IpMask;
	XDP_TUPLE Tuple;
	XDP_QUIC_FLOW QuicFlow;
	XDP_PORT_SET PortSet;
	XDP_IP_PORT_SET IpPortSet;
	UINT8 NextHeader;
} XDP_MATCH_PATTERN;

typedef enum _XDP_RULE_ACTION {
	XDP_PROGRAM_ACTION_DROP,
	XDP_PROGRAM_ACTION_PASS,
	XDP_PROGRAM_ACTION_REDIRECT,
	XDP_PROGRAM_ACTION_L2FWD,
	XDP_PROGRAM_ACTION_EBPF,
} XDP_RULE_ACTION;

typedef enum _XDP_REDIRECT_TARGET_TYPE {
	XDP_REDIRECT_TARGET_TYPE_XSK,
} XDP_REDIRECT_TARGET_TYPE;

typedef struct _XDP_REDIRECT_PARAMS {
	XDP_REDIRECT_TARGET_TYPE TargetType;
	HANDLE Target;
} XDP_REDIRECT_PARAMS;

typedef struct _XDP_EBPF_PARAMS {
	HANDLE Target;
} XDP_EBPF_PARAMS;

typedef struct _XDP_RULE {
	XDP_MATCH_TYPE Match;
	XDP_MATCH_PATTERN Pattern;
	XDP_RULE_ACTION Action;
	union {
		XDP_REDIRECT_PARAMS Redirect;
		XDP_EBPF_PARAMS Ebpf;
	};
} XDP_RULE;

typedef enum _XSK_NOTIFY_FLAGS {
	XSK_NOTIFY_FLAG_NONE = 0x0,
	XSK_NOTIFY_FLAG_POKE_RX = 0x1,
	XSK_NOTIFY_FLAG_POKE_TX = 0x2,
	XSK_NOTIFY_FLAG_WAIT_RX = 0x4,
	XSK_NOTIFY_FLAG_WAIT_TX = 0x8,
} XSK_NOTIFY_FLAGS;

typedef enum _XSK_NOTIFY_RESULT_FLAGS {
	XSK_NOTIFY_RESULT_FLAG_NONE = 0x0,
	XSK_NOTIFY_RESULT_FLAG_RX_AVAILABLE = 0x1,
	XSK_NOTIFY_RESULT_FLAG_TX_COMP_AVAILABLE = 0x2,
} XSK_NOTIFY_RESULT_FLAGS;

typedef struct _XSK_UMEM_REG {
	UINT64 TotalSize;
	UINT32 ChunkSize;
	UINT32 Headroom;
	VOID *Address;
} XSK_UMEM_REG;

typedef struct _XSK_RING_INFO {
	BYTE *Ring;
	UINT32 DescriptorsOffset;
	UINT32 ProducerIndexOffset;
	UINT32 ConsumerIndexOffset;
	UINT32 FlagsOffset;
	UINT32 Size;
	UINT32 ElementStride;
	UINT32 Reserved;
} XSK_RING_INFO;

typedef struct _XSK_RING_INFO_SET {
	XSK_RING_INFO Fill;
	XSK_RING_INFO Completion;
	XSK_RING_INFO Rx;
	XSK_RING_INFO Tx;
} XSK_RING_INFO_SET;

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4201)
#endif
typedef union _XSK_BUFFER_ADDRESS {
	struct {
		UINT64 BaseAddress : 48;
		UINT64 Offset : 16;
	};
	UINT64 AddressAndOffset;
} XSK_BUFFER_ADDRESS;
#ifdef _MSC_VER
#pragma warning(pop)
#endif

typedef struct _XSK_BUFFER_DESCRIPTOR {
	XSK_BUFFER_ADDRESS Address;
	UINT32 Length;
	UINT32 Reserved;
} XSK_BUFFER_DESCRIPTOR;

#define XSK_SOCKOPT_UMEM_REG 1
#define XSK_SOCKOPT_RX_RING_SIZE 2
#define XSK_SOCKOPT_RX_FILL_RING_SIZE 3
#define XSK_SOCKOPT_TX_RING_SIZE 4
#define XSK_SOCKOPT_TX_COMPLETION_RING_SIZE 5
#define XSK_SOCKOPT_RING_INFO 6

typedef struct _XSK_RING {
	volatile UINT32 *SharedProducer;
	volatile UINT32 *SharedConsumer;
	volatile UINT32 *SharedFlags;
	UCHAR *SharedElements;
	UINT32 Mask;
	UINT32 Size;
	UINT32 ElementStride;
	UINT32 CachedProducer;
	UINT32 CachedConsumer;
} XSK_RING;

typedef struct _XDP_API_TABLE XDP_API_TABLE;

typedef HRESULT (*XDP_OPEN_API_FN)(UINT32 XdpApiVersion,
				   const XDP_API_TABLE **XdpApiTable);
typedef VOID (*XDP_CLOSE_API_FN)(const XDP_API_TABLE *XdpApiTable);
typedef HRESULT (*XDP_CREATE_PROGRAM_FN)(
    UINT32 InterfaceIndex, const XDP_HOOK_ID *HookId, UINT32 QueueId,
    XDP_CREATE_PROGRAM_FLAGS Flags, const XDP_RULE *Rules, UINT32 RuleCount,
    HANDLE *Program);
typedef HRESULT (*XDP_INTERFACE_OPEN_FN)(UINT32 InterfaceIndex,
					 HANDLE *InterfaceHandle);
typedef HRESULT (*XSK_CREATE_FN)(HANDLE *Socket);
typedef HRESULT (*XSK_BIND_FN)(HANDLE Socket, UINT32 IfIndex, UINT32 QueueId,
			       XSK_BIND_FLAGS Flags);
typedef HRESULT (*XSK_ACTIVATE_FN)(HANDLE Socket, UINT32 Flags);
typedef HRESULT (*XSK_NOTIFY_SOCKET_FN)(HANDLE Socket, XSK_NOTIFY_FLAGS Flags,
					UINT32 WaitTimeoutMilliseconds,
					XSK_NOTIFY_RESULT_FLAGS *Result);
typedef HRESULT (*XSK_SET_SOCKOPT_FN)(HANDLE Socket, UINT32 OptionName,
				      const VOID *OptionValue,
				      UINT32 OptionLength);
typedef HRESULT (*XSK_GET_SOCKOPT_FN)(HANDLE Socket, UINT32 OptionName,
				      VOID *OptionValue,
				      UINT32 *OptionLength);

struct _XDP_API_TABLE {
	XDP_OPEN_API_FN XdpOpenApi;
	XDP_CLOSE_API_FN XdpCloseApi;
	VOID *XdpGetRoutine;
	XDP_CREATE_PROGRAM_FN XdpCreateProgram;
	XDP_INTERFACE_OPEN_FN XdpInterfaceOpen;
	XSK_CREATE_FN XskCreate;
	XSK_BIND_FN XskBind;
	XSK_ACTIVATE_FN XskActivate;
	XSK_NOTIFY_SOCKET_FN XskNotifySocket;
	VOID *XskNotifyAsync;
	VOID *XskGetNotifyAsyncResult;
	XSK_SET_SOCKOPT_FN XskSetSockopt;
	XSK_GET_SOCKOPT_FN XskGetSockopt;
	VOID *XskIoctl;
};

typedef struct xdp_api_loader {
	HMODULE module;
	const XDP_API_TABLE *table;
	LONG refs;
} xdp_api_loader_t;

static xdp_api_loader_t g_xdp_api = {0};
static char g_xdp_error[256] = "XDP backend not initialized";

struct win_xdp_ctx {
	HANDLE socket;
	uint32_t if_index;
	uint32_t queue_id;
	uint32_t ring_size;
	uint32_t chunk_size;
	uint32_t headroom;
	uint8_t *umem;
	uint64_t umem_size;
	uint64_t *free_stack;
	uint32_t free_top;
	HANDLE rx_program;
	int tx_enabled;
	int rx_enabled;
	int native_bind;
	XSK_RING tx_ring;
	XSK_RING comp_ring;
	XSK_RING rx_ring;
	XSK_RING fill_ring;
};

#define XSK_ADDR_BASE_BITS 48U
#define XSK_ADDR_OFFSET_BITS 16U
#define XSK_ADDR_OFFSET_SHIFT XSK_ADDR_BASE_BITS
#define XSK_ADDR_BASE_MASK ((UINT64_C(1) << XSK_ADDR_BASE_BITS) - 1U)

static inline uint64_t xsk_addr_make(uint64_t base, uint16_t offset)
{
	return (base & XSK_ADDR_BASE_MASK) |
	       ((uint64_t)offset << XSK_ADDR_OFFSET_SHIFT);
}

static inline uint64_t xsk_addr_base(uint64_t addr)
{
	return addr & XSK_ADDR_BASE_MASK;
}

static uint32_t min_u32(uint32_t a, uint32_t b)
{
	return (a < b) ? a : b;
}

static void xdp_set_errorf(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(g_xdp_error, sizeof(g_xdp_error), fmt, ap);
	va_end(ap);
}

static uint32_t xdp_next_power_of_two(uint32_t n)
{
	if (n <= 1) {
		return 1;
	}
	n--;
	n |= n >> 1;
	n |= n >> 2;
	n |= n >> 4;
	n |= n >> 8;
	n |= n >> 16;
	return n + 1;
}

static uint32_t xdp_choose_ring_size(void)
{
	uint32_t ring_size = (uint32_t)zconf.batch * 32U;
	if (ring_size < 1024U) {
		ring_size = 1024U;
	}
	if (ring_size > 16384U) {
		ring_size = 16384U;
	}
	return xdp_next_power_of_two(ring_size);
}

static inline uint32_t ring_read_acquire(volatile uint32_t *p)
{
	uint32_t v = *p;
	MemoryBarrier();
	return v;
}

static inline void ring_write_release(volatile uint32_t *p, uint32_t v)
{
	MemoryBarrier();
	*p = v;
}

static void ring_initialize(XSK_RING *ring, const XSK_RING_INFO *info)
{
	memset(ring, 0, sizeof(*ring));
	ring->SharedProducer =
	    (volatile uint32_t *)(info->Ring + info->ProducerIndexOffset);
	ring->SharedConsumer =
	    (volatile uint32_t *)(info->Ring + info->ConsumerIndexOffset);
	ring->SharedFlags =
	    (volatile uint32_t *)(info->Ring + info->FlagsOffset);
	ring->SharedElements = info->Ring + info->DescriptorsOffset;
	ring->Mask = info->Size - 1U;
	ring->Size = info->Size;
	ring->ElementStride = info->ElementStride;
	ring->CachedProducer = ring_read_acquire(ring->SharedProducer);
	ring->CachedConsumer = ring_read_acquire(ring->SharedConsumer);
}

static void *ring_get_element(const XSK_RING *ring, uint32_t index)
{
	return ring->SharedElements +
	       (size_t)(index & ring->Mask) * (size_t)ring->ElementStride;
}

static uint32_t ring_consumer_reserve(XSK_RING *ring, uint32_t max_count,
				      uint32_t *index)
{
	uint32_t consumer = *ring->SharedConsumer;
	uint32_t available;

	*index = consumer;
	available = ring->CachedProducer - consumer;
	if (available >= max_count) {
		return max_count;
	}
	ring->CachedProducer = ring_read_acquire(ring->SharedProducer);
	available = ring->CachedProducer - consumer;
	return available < max_count ? available : max_count;
}

static void ring_consumer_release(XSK_RING *ring, uint32_t count)
{
	ring_write_release(ring->SharedConsumer, *ring->SharedConsumer + count);
}

static uint32_t ring_producer_reserve(XSK_RING *ring, uint32_t max_count,
				      uint32_t *index)
{
	uint32_t producer = *ring->SharedProducer;
	uint32_t available;

	*index = producer;
	available = ring->Size - (producer - ring->CachedConsumer);
	if (available >= max_count) {
		return max_count;
	}
	ring->CachedConsumer = ring_read_acquire(ring->SharedConsumer);
	available = ring->Size - (producer - ring->CachedConsumer);
	return available < max_count ? available : max_count;
}

static void ring_producer_submit(XSK_RING *ring, uint32_t count)
{
	ring_write_release(ring->SharedProducer, *ring->SharedProducer + count);
}

static int xdp_api_acquire(void)
{
	if (InterlockedIncrement(&g_xdp_api.refs) > 1) {
		return 1;
	}

	g_xdp_api.module = LoadLibraryA("xdpapi.dll");
	if (!g_xdp_api.module) {
		xdp_set_errorf("LoadLibrary(xdpapi.dll) failed (err=%lu)",
			       (unsigned long)GetLastError());
		goto fail;
	}

	FARPROC open_proc = GetProcAddress(g_xdp_api.module, "XdpOpenApi");
	if (!open_proc) {
		xdp_set_errorf("GetProcAddress(XdpOpenApi) failed (err=%lu)",
			       (unsigned long)GetLastError());
		goto fail;
	}
	XDP_OPEN_API_FN open_api = NULL;
	memcpy(&open_api, &open_proc, sizeof(open_api));

	HRESULT hr = open_api(XDP_API_VERSION_2, &g_xdp_api.table);
	if (FAILED(hr) || !g_xdp_api.table) {
		xdp_set_errorf("XdpOpenApi(v2) failed (hr=0x%08lx)",
			       (unsigned long)hr);
		goto fail;
	}

	if (!g_xdp_api.table->XskCreate || !g_xdp_api.table->XskBind ||
	    !g_xdp_api.table->XskActivate || !g_xdp_api.table->XskSetSockopt ||
	    !g_xdp_api.table->XskGetSockopt ||
	    !g_xdp_api.table->XskNotifySocket ||
	    !g_xdp_api.table->XdpCloseApi) {
		xdp_set_errorf("XDP API table missing required AF_XDP routines");
		goto fail;
	}

	return 1;

fail:
	if (g_xdp_api.table && g_xdp_api.table->XdpCloseApi) {
		g_xdp_api.table->XdpCloseApi(g_xdp_api.table);
	}
	g_xdp_api.table = NULL;
	if (g_xdp_api.module) {
		FreeLibrary(g_xdp_api.module);
		g_xdp_api.module = NULL;
	}
	InterlockedDecrement(&g_xdp_api.refs);
	return 0;
}

static void xdp_api_release(void)
{
	LONG refs = InterlockedDecrement(&g_xdp_api.refs);
	if (refs > 0) {
		return;
	}
	if (refs < 0) {
		g_xdp_api.refs = 0;
		return;
	}
	if (g_xdp_api.table && g_xdp_api.table->XdpCloseApi) {
		g_xdp_api.table->XdpCloseApi(g_xdp_api.table);
	}
	g_xdp_api.table = NULL;
	if (g_xdp_api.module) {
		FreeLibrary(g_xdp_api.module);
		g_xdp_api.module = NULL;
	}
}

static int iface_extract_npf_guid(const char *iface, char *guid,
				  size_t guid_len)
{
	const char *prefix = "\\Device\\NPF_";
	size_t prefix_len = strlen(prefix);
	if (!iface || _strnicmp(iface, prefix, prefix_len) != 0) {
		return 0;
	}
	const char *suffix = iface + prefix_len;
	if (*suffix == '\0') {
		return 0;
	}
	size_t n = strlen(suffix);
	if (n + 1 > guid_len) {
		return 0;
	}
	memcpy(guid, suffix, n + 1);
	return 1;
}

static void utf8_from_wide(const wchar_t *ws, char *out, size_t out_len)
{
	if (!out || out_len == 0) {
		return;
	}
	out[0] = '\0';
	if (!ws) {
		return;
	}
	int rc = WideCharToMultiByte(CP_UTF8, 0, ws, -1, out, (int)out_len, NULL,
				     NULL);
	if (rc <= 0) {
		out[0] = '\0';
	}
}

static int iface_name_to_index(const char *iface, uint32_t *if_index_out)
{
	if (!iface || !if_index_out) {
		return 0;
	}

	char npf_guid[128] = {0};
	int has_npf_guid = iface_extract_npf_guid(iface, npf_guid, sizeof(npf_guid));

	ULONG buf_len = 0;
	ULONG ret = GetAdaptersAddresses(
	    AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES, NULL, NULL, &buf_len);
	if (ret != ERROR_BUFFER_OVERFLOW || buf_len == 0) {
		xdp_set_errorf("GetAdaptersAddresses size query failed (err=%lu)",
			       (unsigned long)ret);
		return 0;
	}

	IP_ADAPTER_ADDRESSES *addrs = (IP_ADAPTER_ADDRESSES *)malloc(buf_len);
	if (!addrs) {
		xdp_set_errorf("malloc failed while resolving interface");
		return 0;
	}

	ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES,
				   NULL, addrs, &buf_len);
	if (ret != NO_ERROR) {
		free(addrs);
		xdp_set_errorf("GetAdaptersAddresses failed (err=%lu)",
			       (unsigned long)ret);
		return 0;
	}

	for (IP_ADAPTER_ADDRESSES *a = addrs; a; a = a->Next) {
		uint32_t idx = (a->IfIndex != 0) ? a->IfIndex : a->Ipv6IfIndex;
		if (idx == 0) {
			continue;
		}

		if (has_npf_guid && a->AdapterName &&
		    _stricmp(a->AdapterName, npf_guid) == 0) {
			*if_index_out = idx;
			free(addrs);
			return 1;
		}

		if (a->AdapterName && _stricmp(a->AdapterName, iface) == 0) {
			*if_index_out = idx;
			free(addrs);
			return 1;
		}

		char friendly[512];
		utf8_from_wide(a->FriendlyName, friendly, sizeof(friendly));
		if (friendly[0] != '\0' && _stricmp(friendly, iface) == 0) {
			*if_index_out = idx;
			free(addrs);
			return 1;
		}
	}
	free(addrs);

	ULONG idx = if_nametoindex(iface);
	if (idx != 0) {
		*if_index_out = (uint32_t)idx;
		return 1;
	}

	char *end = NULL;
	unsigned long parsed = strtoul(iface, &end, 10);
	if (end && *end == '\0' && parsed > 0 && parsed <= UINT32_MAX) {
		*if_index_out = (uint32_t)parsed;
		return 1;
	}

	xdp_set_errorf("could not resolve interface '%s' to ifindex", iface);
	return 0;
}

static uint32_t xdp_reap_completions(win_xdp_ctx_t *ctx, uint32_t max_count)
{
	uint32_t comp_idx = 0;
	uint32_t got =
	    ring_consumer_reserve(&ctx->comp_ring, max_count, &comp_idx);
	for (uint32_t i = 0; i < got; i++) {
		uint64_t *addr = (uint64_t *)ring_get_element(&ctx->comp_ring,
							       comp_idx + i);
		if (ctx->free_top < ctx->ring_size) {
			ctx->free_stack[ctx->free_top++] = xsk_addr_base(*addr);
		}
	}
	if (got > 0) {
		ring_consumer_release(&ctx->comp_ring, got);
	}
	return got;
}

static void xdp_notify_tx(win_xdp_ctx_t *ctx, uint32_t wait_ms)
{
	XSK_NOTIFY_RESULT_FLAGS result = XSK_NOTIFY_RESULT_FLAG_NONE;
	HRESULT hr = g_xdp_api.table->XskNotifySocket(
	    ctx->socket,
	    (XSK_NOTIFY_FLAGS)(XSK_NOTIFY_FLAG_POKE_TX |
			       (wait_ms ? XSK_NOTIFY_FLAG_WAIT_TX : 0)),
	    wait_ms, &result);
	if (FAILED(hr)) {
		log_debug("send", "XskNotifySocket failed: 0x%08lx",
			  (unsigned long)hr);
	}
}

static void xdp_notify_rx(win_xdp_ctx_t *ctx, uint32_t wait_ms)
{
	XSK_NOTIFY_RESULT_FLAGS result = XSK_NOTIFY_RESULT_FLAG_NONE;
	HRESULT hr = g_xdp_api.table->XskNotifySocket(
	    ctx->socket,
	    (XSK_NOTIFY_FLAGS)(XSK_NOTIFY_FLAG_POKE_RX |
			       (wait_ms ? XSK_NOTIFY_FLAG_WAIT_RX : 0)),
	    wait_ms, &result);
	if (FAILED(hr)) {
		log_debug("recv", "XskNotifySocket(RX) failed: 0x%08lx",
			  (unsigned long)hr);
	}
}

static uint32_t xdp_post_fill_addrs(win_xdp_ctx_t *ctx, uint32_t max_count)
{
	if (!ctx || !ctx->rx_enabled || max_count == 0) {
		return 0;
	}
	uint32_t fill_idx = 0;
	uint32_t reserved =
	    ring_producer_reserve(&ctx->fill_ring, max_count, &fill_idx);
	if (reserved == 0) {
		return 0;
	}
	uint32_t posted = min_u32(reserved, ctx->free_top);
	for (uint32_t i = 0; i < posted; i++) {
		uint64_t *fill_addr =
		    (uint64_t *)ring_get_element(&ctx->fill_ring, fill_idx + i);
		*fill_addr = ctx->free_stack[--ctx->free_top];
	}
	if (posted > 0) {
		ring_producer_submit(&ctx->fill_ring, posted);
	}
	return posted;
}

static void xdp_now_timespec(struct timespec *ts)
{
	if (!ts) {
		return;
	}
	FILETIME ft;
	ULARGE_INTEGER ticks;
	const uint64_t UNIX_EPOCH_IN_FILETIME = 116444736000000000ULL;
	uint64_t unix_100ns = 0;

	GetSystemTimeAsFileTime(&ft);
	ticks.LowPart = ft.dwLowDateTime;
	ticks.HighPart = ft.dwHighDateTime;
	if (ticks.QuadPart > UNIX_EPOCH_IN_FILETIME) {
		unix_100ns = ticks.QuadPart - UNIX_EPOCH_IN_FILETIME;
	}
	ts->tv_sec = (time_t)(unix_100ns / 10000000ULL);
	ts->tv_nsec = (long)((unix_100ns % 10000000ULL) * 100ULL);
}

static int xdp_attach_rx_program(win_xdp_ctx_t *ctx)
{
	if (!ctx || !ctx->rx_enabled) {
		xdp_set_errorf("xdp_attach_rx_program: invalid RX context");
		return 0;
	}
	if (!g_xdp_api.table || !g_xdp_api.table->XdpCreateProgram) {
		xdp_set_errorf("XDP API missing XdpCreateProgram");
		return 0;
	}

	XDP_HOOK_ID hook = {
		.Layer = XDP_HOOK_L2,
		.Direction = XDP_HOOK_RX,
		.SubLayer = XDP_HOOK_INSPECT,
	};

	uint32_t rule_count = (zconf.number_source_ips > 0)
				  ? zconf.number_source_ips
				  : 1;

	XDP_RULE *rules = calloc(rule_count, sizeof(*rules));
	if (!rules) {
		xdp_set_errorf("calloc failed for XDP RX rules");
		return 0;
	}

	for (uint32_t i = 0; i < rule_count; i++) {
		rules[i].Action = XDP_PROGRAM_ACTION_REDIRECT;
		rules[i].Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSK;
		rules[i].Redirect.Target = ctx->socket;
	}

	if (zconf.number_source_ips == 0) {
		rules[0].Match = XDP_MATCH_ALL;
	} else {
		for (uint32_t i = 0; i < rule_count; i++) {
			rules[i].Match = XDP_MATCH_IPV4_DST_MASK;
			rules[i].Pattern.IpMask.Mask.Ipv4.s_addr = UINT32_MAX;
			rules[i].Pattern.IpMask.Address.Ipv4.s_addr =
			    zconf.source_ip_addresses[i];
		}
	}

	HRESULT hr_native = E_FAIL;
	HRESULT hr_generic = E_FAIL;
	HRESULT hr_default = E_FAIL;
	HRESULT hr_native_all = E_FAIL;
	HRESULT hr_generic_all = E_FAIL;
	HRESULT hr_default_all = E_FAIL;

	hr_native = g_xdp_api.table->XdpCreateProgram(
	    ctx->if_index, &hook, ctx->queue_id, XDP_CREATE_PROGRAM_FLAG_NATIVE,
	    rules, rule_count, &ctx->rx_program);
	if (FAILED(hr_native)) {
		hr_generic = g_xdp_api.table->XdpCreateProgram(
		    ctx->if_index, &hook, ctx->queue_id,
		    XDP_CREATE_PROGRAM_FLAG_GENERIC, rules, rule_count,
		    &ctx->rx_program);
		if (FAILED(hr_generic)) {
			hr_default = g_xdp_api.table->XdpCreateProgram(
			    ctx->if_index, &hook, ctx->queue_id,
			    XDP_CREATE_PROGRAM_FLAG_NONE, rules, rule_count,
			    &ctx->rx_program);
		}
	}

	if (!ctx->rx_program &&
	    (FAILED(hr_native) && FAILED(hr_generic) && FAILED(hr_default))) {
		XDP_RULE catch_all = {0};
		catch_all.Match = XDP_MATCH_ALL;
		catch_all.Action = XDP_PROGRAM_ACTION_REDIRECT;
		catch_all.Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSK;
		catch_all.Redirect.Target = ctx->socket;

		hr_native_all = g_xdp_api.table->XdpCreateProgram(
		    ctx->if_index, &hook, ctx->queue_id,
		    XDP_CREATE_PROGRAM_FLAG_NATIVE, &catch_all, 1,
		    &ctx->rx_program);
		if (FAILED(hr_native_all)) {
			hr_generic_all = g_xdp_api.table->XdpCreateProgram(
			    ctx->if_index, &hook, ctx->queue_id,
			    XDP_CREATE_PROGRAM_FLAG_GENERIC, &catch_all, 1,
			    &ctx->rx_program);
			if (FAILED(hr_generic_all)) {
				hr_default_all = g_xdp_api.table->XdpCreateProgram(
				    ctx->if_index, &hook, ctx->queue_id,
				    XDP_CREATE_PROGRAM_FLAG_NONE, &catch_all, 1,
				    &ctx->rx_program);
			}
		}
		if (ctx->rx_program &&
		    (SUCCEEDED(hr_native_all) || SUCCEEDED(hr_generic_all) ||
		     SUCCEEDED(hr_default_all))) {
			log_warn(
			    "recv",
			    "XDP RX source-ip redirect rules unsupported; using catch-all XDP redirect rule");
		}
	}

	free(rules);

	if (!ctx->rx_program ||
	    ((FAILED(hr_native) && FAILED(hr_generic) && FAILED(hr_default)) &&
	     (FAILED(hr_native_all) && FAILED(hr_generic_all) &&
	      FAILED(hr_default_all)))) {
		xdp_set_errorf(
		    "XdpCreateProgram RX redirect failed (srcip native=0x%08lx, generic=0x%08lx, default=0x%08lx; all native=0x%08lx, generic=0x%08lx, default=0x%08lx)",
		    (unsigned long)hr_native, (unsigned long)hr_generic,
		    (unsigned long)hr_default, (unsigned long)hr_native_all,
		    (unsigned long)hr_generic_all,
		    (unsigned long)hr_default_all);
		ctx->rx_program = NULL;
		return 0;
	}
	return 1;
}

int xdp_win_open(const char *iface_name, uint32_t queue_id,
		 win_xdp_ctx_t **ctx_out)
{
	if (!ctx_out) {
		xdp_set_errorf("xdp_win_open: ctx_out is NULL");
		return 0;
	}
	*ctx_out = NULL;

	if (!xdp_api_acquire()) {
		return 0;
	}

	win_xdp_ctx_t *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		xdp_set_errorf("calloc failed for XDP context");
		goto fail;
	}

	if (!iface_name || iface_name[0] == '\0') {
		xdp_set_errorf("XDP requires non-empty interface name");
		goto fail;
	}

	if (!iface_name_to_index(iface_name, &ctx->if_index)) {
		goto fail;
	}
	ctx->queue_id = queue_id;
	ctx->ring_size = xdp_choose_ring_size();
	ctx->chunk_size = MAX_PACKET_SIZE;
	ctx->headroom = 0;
	ctx->umem_size = (uint64_t)ctx->ring_size * (uint64_t)ctx->chunk_size;

	HRESULT hr = g_xdp_api.table->XskCreate(&ctx->socket);
	if (FAILED(hr) || !ctx->socket || ctx->socket == INVALID_HANDLE_VALUE) {
		xdp_set_errorf("XskCreate failed (hr=0x%08lx)",
			       (unsigned long)hr);
		goto fail;
	}

	ctx->umem = (uint8_t *)VirtualAlloc(NULL, (SIZE_T)ctx->umem_size,
					    MEM_COMMIT | MEM_RESERVE,
					    PAGE_READWRITE);
	if (!ctx->umem) {
		xdp_set_errorf("VirtualAlloc UMEM failed (err=%lu)",
			       (unsigned long)GetLastError());
		goto fail;
	}

	ctx->free_stack =
	    (uint64_t *)malloc(sizeof(uint64_t) * (size_t)ctx->ring_size);
	if (!ctx->free_stack) {
		xdp_set_errorf("malloc free_stack failed");
		goto fail;
	}

	XSK_UMEM_REG umem = {0};
	umem.TotalSize = ctx->umem_size;
	umem.ChunkSize = ctx->chunk_size;
	umem.Headroom = ctx->headroom;
	umem.Address = ctx->umem;

	hr = g_xdp_api.table->XskSetSockopt(ctx->socket, XSK_SOCKOPT_UMEM_REG,
					    &umem, sizeof(umem));
	if (FAILED(hr)) {
		xdp_set_errorf("XSK_SOCKOPT_UMEM_REG failed (hr=0x%08lx)",
			       (unsigned long)hr);
		goto fail;
	}

	hr = g_xdp_api.table->XskSetSockopt(
	    ctx->socket, XSK_SOCKOPT_TX_RING_SIZE, &ctx->ring_size,
	    sizeof(ctx->ring_size));
	if (FAILED(hr)) {
		xdp_set_errorf("XSK_SOCKOPT_TX_RING_SIZE failed (hr=0x%08lx)",
			       (unsigned long)hr);
		goto fail;
	}

	hr = g_xdp_api.table->XskSetSockopt(
	    ctx->socket, XSK_SOCKOPT_TX_COMPLETION_RING_SIZE, &ctx->ring_size,
	    sizeof(ctx->ring_size));
	if (FAILED(hr)) {
		xdp_set_errorf(
		    "XSK_SOCKOPT_TX_COMPLETION_RING_SIZE failed (hr=0x%08lx)",
		    (unsigned long)hr);
		goto fail;
	}

	hr = g_xdp_api.table->XskBind(
	    ctx->socket, ctx->if_index, ctx->queue_id,
	    (XSK_BIND_FLAGS)(XSK_BIND_FLAG_TX | XSK_BIND_FLAG_NATIVE));
	if (FAILED(hr)) {
		HRESULT hr_generic = g_xdp_api.table->XskBind(
		    ctx->socket, ctx->if_index, ctx->queue_id,
		    (XSK_BIND_FLAGS)(XSK_BIND_FLAG_TX | XSK_BIND_FLAG_GENERIC));
		if (FAILED(hr_generic)) {
			HRESULT hr_default = g_xdp_api.table->XskBind(
			    ctx->socket, ctx->if_index, ctx->queue_id,
			    XSK_BIND_FLAG_TX);
			if (FAILED(hr_default)) {
				xdp_set_errorf(
				    "XskBind(ifindex=%u, queue=%u) failed (native=0x%08lx, generic=0x%08lx, default=0x%08lx)",
				    ctx->if_index, ctx->queue_id,
				    (unsigned long)hr, (unsigned long)hr_generic,
				    (unsigned long)hr_default);
				goto fail;
			}
		}
		ctx->native_bind = 0;
	} else {
		ctx->native_bind = 1;
	}

	hr = g_xdp_api.table->XskActivate(ctx->socket, 0);
	if (FAILED(hr)) {
		xdp_set_errorf("XskActivate failed (hr=0x%08lx)",
			       (unsigned long)hr);
		goto fail;
	}

	XSK_RING_INFO_SET ring_info;
	memset(&ring_info, 0, sizeof(ring_info));
	uint32_t ring_info_len = sizeof(ring_info);
	hr = g_xdp_api.table->XskGetSockopt(ctx->socket, XSK_SOCKOPT_RING_INFO,
					    &ring_info, &ring_info_len);
	if (FAILED(hr) || ring_info_len != sizeof(ring_info)) {
		xdp_set_errorf("XSK_SOCKOPT_RING_INFO failed (hr=0x%08lx)",
			       (unsigned long)hr);
		goto fail;
	}
	if (ring_info.Tx.Size == 0 || ring_info.Completion.Size == 0) {
		xdp_set_errorf("XDP returned empty TX/completion ring");
		goto fail;
	}

	ring_initialize(&ctx->tx_ring, &ring_info.Tx);
	ring_initialize(&ctx->comp_ring, &ring_info.Completion);
	ctx->ring_size = min_u32(ctx->tx_ring.Size, ctx->comp_ring.Size);
	ctx->tx_enabled = 1;
	ctx->rx_enabled = 0;
	for (uint32_t i = 0; i < ctx->ring_size; i++) {
		ctx->free_stack[i] = (uint64_t)i * (uint64_t)ctx->chunk_size;
	}
	ctx->free_top = ctx->ring_size;

	*ctx_out = ctx;
	return 1;

fail:
	if (ctx) {
		if (ctx->socket && ctx->socket != INVALID_HANDLE_VALUE) {
			CloseHandle(ctx->socket);
		}
		if (ctx->umem) {
			VirtualFree(ctx->umem, 0, MEM_RELEASE);
		}
		free(ctx->free_stack);
		free(ctx);
	}
	xdp_api_release();
	return 0;
}

int xdp_win_open_rx(const char *iface_name, uint32_t queue_id,
		    win_xdp_ctx_t **ctx_out)
{
	if (!ctx_out) {
		xdp_set_errorf("xdp_win_open_rx: ctx_out is NULL");
		return 0;
	}
	*ctx_out = NULL;

	if (!xdp_api_acquire()) {
		return 0;
	}

	win_xdp_ctx_t *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		xdp_set_errorf("calloc failed for XDP RX context");
		goto fail;
	}

	if (!iface_name || iface_name[0] == '\0') {
		xdp_set_errorf("XDP RX requires non-empty interface name");
		goto fail;
	}

	if (!iface_name_to_index(iface_name, &ctx->if_index)) {
		goto fail;
	}
	ctx->queue_id = queue_id;
	ctx->ring_size = xdp_choose_ring_size();
	ctx->chunk_size = MAX_PACKET_SIZE;
	ctx->headroom = 0;
	ctx->umem_size = (uint64_t)ctx->ring_size * (uint64_t)ctx->chunk_size;

	HRESULT hr = g_xdp_api.table->XskCreate(&ctx->socket);
	if (FAILED(hr) || !ctx->socket || ctx->socket == INVALID_HANDLE_VALUE) {
		xdp_set_errorf("XskCreate(RX) failed (hr=0x%08lx)",
			       (unsigned long)hr);
		goto fail;
	}

	ctx->umem = (uint8_t *)VirtualAlloc(NULL, (SIZE_T)ctx->umem_size,
					    MEM_COMMIT | MEM_RESERVE,
					    PAGE_READWRITE);
	if (!ctx->umem) {
		xdp_set_errorf("VirtualAlloc UMEM (RX) failed (err=%lu)",
			       (unsigned long)GetLastError());
		goto fail;
	}

	ctx->free_stack =
	    (uint64_t *)malloc(sizeof(uint64_t) * (size_t)ctx->ring_size);
	if (!ctx->free_stack) {
		xdp_set_errorf("malloc free_stack (RX) failed");
		goto fail;
	}

	XSK_UMEM_REG umem = {0};
	umem.TotalSize = ctx->umem_size;
	umem.ChunkSize = ctx->chunk_size;
	umem.Headroom = ctx->headroom;
	umem.Address = ctx->umem;
	hr = g_xdp_api.table->XskSetSockopt(ctx->socket, XSK_SOCKOPT_UMEM_REG,
					    &umem, sizeof(umem));
	if (FAILED(hr)) {
		xdp_set_errorf("XSK_SOCKOPT_UMEM_REG (RX) failed (hr=0x%08lx)",
			       (unsigned long)hr);
		goto fail;
	}

	hr = g_xdp_api.table->XskSetSockopt(
	    ctx->socket, XSK_SOCKOPT_RX_RING_SIZE, &ctx->ring_size,
	    sizeof(ctx->ring_size));
	if (FAILED(hr)) {
		xdp_set_errorf("XSK_SOCKOPT_RX_RING_SIZE failed (hr=0x%08lx)",
			       (unsigned long)hr);
		goto fail;
	}

	hr = g_xdp_api.table->XskSetSockopt(
	    ctx->socket, XSK_SOCKOPT_RX_FILL_RING_SIZE, &ctx->ring_size,
	    sizeof(ctx->ring_size));
	if (FAILED(hr)) {
		xdp_set_errorf(
		    "XSK_SOCKOPT_RX_FILL_RING_SIZE failed (hr=0x%08lx)",
		    (unsigned long)hr);
		goto fail;
	}

	hr = g_xdp_api.table->XskBind(
	    ctx->socket, ctx->if_index, ctx->queue_id,
	    (XSK_BIND_FLAGS)(XSK_BIND_FLAG_RX | XSK_BIND_FLAG_NATIVE));
	if (FAILED(hr)) {
		HRESULT hr_generic = g_xdp_api.table->XskBind(
		    ctx->socket, ctx->if_index, ctx->queue_id,
		    (XSK_BIND_FLAGS)(XSK_BIND_FLAG_RX | XSK_BIND_FLAG_GENERIC));
		if (FAILED(hr_generic)) {
			HRESULT hr_default = g_xdp_api.table->XskBind(
			    ctx->socket, ctx->if_index, ctx->queue_id,
			    XSK_BIND_FLAG_RX);
			if (FAILED(hr_default)) {
				xdp_set_errorf(
				    "XskBind RX(ifindex=%u, queue=%u) failed (native=0x%08lx, generic=0x%08lx, default=0x%08lx)",
				    ctx->if_index, ctx->queue_id,
				    (unsigned long)hr, (unsigned long)hr_generic,
				    (unsigned long)hr_default);
				goto fail;
			}
		}
		ctx->native_bind = 0;
	} else {
		ctx->native_bind = 1;
	}

	hr = g_xdp_api.table->XskActivate(ctx->socket, 0);
	if (FAILED(hr)) {
		xdp_set_errorf("XskActivate(RX) failed (hr=0x%08lx)",
			       (unsigned long)hr);
		goto fail;
	}

	XSK_RING_INFO_SET ring_info;
	memset(&ring_info, 0, sizeof(ring_info));
	uint32_t ring_info_len = sizeof(ring_info);
	hr = g_xdp_api.table->XskGetSockopt(ctx->socket, XSK_SOCKOPT_RING_INFO,
					    &ring_info, &ring_info_len);
	if (FAILED(hr) || ring_info_len != sizeof(ring_info)) {
		xdp_set_errorf("XSK_SOCKOPT_RING_INFO (RX) failed (hr=0x%08lx)",
			       (unsigned long)hr);
		goto fail;
	}
	if (ring_info.Rx.Size == 0 || ring_info.Fill.Size == 0) {
		xdp_set_errorf("XDP returned empty RX/fill ring");
		goto fail;
	}

	ring_initialize(&ctx->rx_ring, &ring_info.Rx);
	ring_initialize(&ctx->fill_ring, &ring_info.Fill);
	ctx->ring_size = min_u32(ctx->rx_ring.Size, ctx->fill_ring.Size);
	ctx->tx_enabled = 0;
	ctx->rx_enabled = 1;
	for (uint32_t i = 0; i < ctx->ring_size; i++) {
		ctx->free_stack[i] = (uint64_t)i * (uint64_t)ctx->chunk_size;
	}
	ctx->free_top = ctx->ring_size;
	if (!xdp_attach_rx_program(ctx)) {
		goto fail;
	}
	(void)xdp_post_fill_addrs(ctx, ctx->ring_size);
	xdp_notify_rx(ctx, 0);

	*ctx_out = ctx;
	return 1;

fail:
	if (ctx) {
		if (ctx->rx_program && ctx->rx_program != INVALID_HANDLE_VALUE) {
			CloseHandle(ctx->rx_program);
		}
		if (ctx->socket && ctx->socket != INVALID_HANDLE_VALUE) {
			CloseHandle(ctx->socket);
		}
		if (ctx->umem) {
			VirtualFree(ctx->umem, 0, MEM_RELEASE);
		}
		free(ctx->free_stack);
		free(ctx);
	}
	xdp_api_release();
	return 0;
}

int xdp_win_is_native_bind(const win_xdp_ctx_t *ctx)
{
	return ctx ? ctx->native_bind : 0;
}

void xdp_win_close(win_xdp_ctx_t *ctx)
{
	if (!ctx) {
		return;
	}
	if (ctx->rx_program && ctx->rx_program != INVALID_HANDLE_VALUE) {
		CloseHandle(ctx->rx_program);
	}
	if (ctx->socket && ctx->socket != INVALID_HANDLE_VALUE) {
		CloseHandle(ctx->socket);
	}
	if (ctx->umem) {
		VirtualFree(ctx->umem, 0, MEM_RELEASE);
	}
	free(ctx->free_stack);
	free(ctx);
	xdp_api_release();
}

int xdp_win_send_batch(win_xdp_ctx_t *ctx, batch_t *batch, int retries)
{
	if (!ctx || !batch || batch->len == 0) {
		return EXIT_SUCCESS;
	}
	if (!ctx->tx_enabled) {
		log_error("send", "xdp_win_send_batch called on non-TX context");
		return 0;
	}
	if (retries < 1) {
		retries = 1;
	}

	for (int i = 0; i < batch->len; i++) {
		if (batch->packets[i].len == 0 ||
		    batch->packets[i].len > (ctx->chunk_size - ctx->headroom)) {
			log_error("send",
				  "xdp packet length invalid at idx=%d (len=%u, max=%u)",
				  i, batch->packets[i].len,
				  (ctx->chunk_size - ctx->headroom));
			return 0;
		}
	}

	int total_sent = 0;
	int next_to_send = 0;

	for (int attempt = 0; attempt < retries && next_to_send < batch->len;
	     attempt++) {
		xdp_reap_completions(ctx, ctx->ring_size);

		while (next_to_send < batch->len) {
			uint32_t tx_idx = 0;
			uint32_t tx_reserved = ring_producer_reserve(
			    &ctx->tx_ring, (uint32_t)(batch->len - next_to_send),
			    &tx_idx);

			if (tx_reserved == 0 || ctx->free_top == 0) {
				break;
			}

			uint32_t to_submit = min_u32(tx_reserved, ctx->free_top);
			for (uint32_t i = 0; i < to_submit; i++) {
				uint64_t base = ctx->free_stack[--ctx->free_top];
				uint32_t pkt_idx = (uint32_t)next_to_send + i;
				uint8_t *dst = ctx->umem + base + ctx->headroom;
				memcpy(dst, batch->packets[pkt_idx].buf,
				       batch->packets[pkt_idx].len);

				XSK_BUFFER_DESCRIPTOR *tx_desc =
				    (XSK_BUFFER_DESCRIPTOR *)ring_get_element(
					&ctx->tx_ring, tx_idx + i);
				tx_desc->Address.AddressAndOffset =
				    xsk_addr_make(base, (uint16_t)ctx->headroom);
				tx_desc->Length = batch->packets[pkt_idx].len;
				tx_desc->Reserved = 0;
			}

			ring_producer_submit(&ctx->tx_ring, to_submit);
			next_to_send += (int)to_submit;
			total_sent += (int)to_submit;
			xdp_notify_tx(ctx, 0);
		}

		if (next_to_send < batch->len) {
			/* Wait briefly for TX completions, then retry remaining. */
			xdp_notify_tx(ctx, 1);
			xdp_reap_completions(ctx, ctx->ring_size);
		}
	}

	if (total_sent < batch->len) {
		log_warn("send",
			 "xdp partial batch send: %d/%d packets (retries=%d)",
			 total_sent, batch->len, retries);
	}

	xdp_reap_completions(ctx, ctx->ring_size);
	return total_sent;
}

int xdp_win_recv(win_xdp_ctx_t *ctx, uint32_t wait_ms, xdp_win_rx_cb_t cb,
		 void *user)
{
	if (!ctx || !ctx->rx_enabled || !cb) {
		return -1;
	}

	(void)xdp_post_fill_addrs(ctx, ctx->ring_size);

	uint32_t rx_idx = 0;
	uint32_t got =
	    ring_consumer_reserve(&ctx->rx_ring, ctx->ring_size, &rx_idx);
	if (got == 0) {
		xdp_notify_rx(ctx, wait_ms);
		got = ring_consumer_reserve(&ctx->rx_ring, ctx->ring_size, &rx_idx);
		if (got == 0) {
			return 0;
		}
	}

	struct timespec ts;
	for (uint32_t i = 0; i < got; i++) {
		XSK_BUFFER_DESCRIPTOR *rx_desc =
		    (XSK_BUFFER_DESCRIPTOR *)ring_get_element(&ctx->rx_ring,
							      rx_idx + i);
		uint64_t addr = rx_desc->Address.AddressAndOffset;
		uint64_t base = xsk_addr_base(addr);
		uint64_t offset = addr >> XSK_ADDR_OFFSET_SHIFT;
		uint64_t end = base + offset + rx_desc->Length;
		if (ctx->free_top < ctx->ring_size) {
			ctx->free_stack[ctx->free_top++] = base;
		}
		if (rx_desc->Length == 0 || end > ctx->umem_size) {
			continue;
		}
		xdp_now_timespec(&ts);
		cb(rx_desc->Length,
		   ctx->umem + (size_t)base + (size_t)offset, ts, user);
	}

	ring_consumer_release(&ctx->rx_ring, got);
	if (xdp_post_fill_addrs(ctx, got) > 0) {
		xdp_notify_rx(ctx, 0);
	}
	return (int)got;
}

const char *xdp_win_last_error(void)
{
	return g_xdp_error;
}

#endif /* _WIN32 */
