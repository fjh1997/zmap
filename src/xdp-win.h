/*
 * Windows XDP (AF_XDP) send backend for ZMap.
 *
 * Licensed under the Apache License, Version 2.0
 */

#ifndef ZMAP_XDP_WIN_H
#define ZMAP_XDP_WIN_H

#ifdef _WIN32

#include <stdint.h>
#include <time.h>

#include "../lib/includes.h"
#include "send.h"

typedef struct win_xdp_ctx win_xdp_ctx_t;
typedef void (*xdp_win_rx_cb_t)(uint32_t buflen, const uint8_t *bytes,
				struct timespec ts, void *user);

int xdp_win_open(const char *iface_name, uint32_t queue_id,
		 win_xdp_ctx_t **ctx_out);
int xdp_win_open_rx(const char *iface_name, uint32_t queue_id,
		    win_xdp_ctx_t **ctx_out);
void xdp_win_close(win_xdp_ctx_t *ctx);
int xdp_win_send_batch(win_xdp_ctx_t *ctx, batch_t *batch, int retries);
int xdp_win_recv(win_xdp_ctx_t *ctx, uint32_t wait_ms, xdp_win_rx_cb_t cb,
		 void *user);
/* Returns 1 if the XSK socket was bound in Native mode, 0 if Generic/default */
int xdp_win_is_native_bind(const win_xdp_ctx_t *ctx);
const char *xdp_win_last_error(void);

#endif /* _WIN32 */

#endif /* ZMAP_XDP_WIN_H */
