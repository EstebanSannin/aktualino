/*
 * aktualino_net — minimal HTTPS client to the device gateway (SPEC §5, §7).
 *
 * Phase 0 provides a streaming GET: bytes are handed to a caller callback as
 * they arrive (so a firmware image is hashed/written to flash on the fly, never
 * buffered whole — SPEC §7.4). The mTLS fields (client cert/key + pinned server
 * CA) are plumbed through now so Phase 1 can authenticate to the gateway
 * (mTLS-only, SPEC §3) without reshaping this API. When the cert/key are NULL
 * the request is plain server-auth TLS (used against the Phase-0 dumb server).
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Called for each received body chunk. Return ESP_OK to continue; any other
 * value aborts the transfer and is returned from aktualino_net_get_stream().
 */
typedef esp_err_t (*aktualino_net_data_cb)(const void *data, size_t len,
                                           void *user);

typedef struct {
    const char *url;                 /* full https:// URL */
    /* mTLS / TLS trust (all PEM, NUL-terminated; NULL to omit). */
    const char *cacert_pem;          /* server CA to pin; NULL => cert bundle */
    const char *client_cert_pem;     /* mTLS client cert (SPEC §3) */
    const char *client_key_pem;      /* mTLS client private key */
    bool skip_server_cn_check;       /* dev only: don't match server cert CN */
    int timeout_ms;                  /* per-request timeout (0 => 10s default) */
} aktualino_net_get_cfg_t;

/*
 * Streaming HTTPS GET. Feeds every body byte to `cb(user)`. On return,
 * `*out_status` (nullable) holds the HTTP status and `*out_len` (nullable) the
 * number of body bytes delivered.
 *
 * A 3xx with Location IS followed here (up to a small bound): the gateway 302s
 * a binary target to a presigned object-storage URL (SPEC §7.4). The redirect
 * leg validates against the compiled public-CA bundle and drops the pinned
 * gateway CA + mTLS client cert; integrity is still enforced by the caller's
 * sha256 + length check on the streamed bytes.
 */
esp_err_t aktualino_net_get_stream(const aktualino_net_get_cfg_t *cfg,
                                   aktualino_net_data_cb cb, void *user,
                                   int *out_status, size_t *out_len);

/*
 * Buffered request (Phase 1: provisioning POST + ECU register POST + manifest
 * PUT). Sends `body` (may be NULL) with the given method and headers, and
 * collects the whole response body into a freshly malloc()'d NUL-terminated
 * buffer handed back via *resp_out (caller frees). Responses here are small
 * JSON, so buffering is fine (unlike the streamed firmware download above).
 *
 * mTLS fields behave as in aktualino_net_get_cfg_t: pass client_cert/key + a
 * pinned cacert for the gateway calls; leave them NULL for the plain-HTTP
 * provisioning call. When cacert_pem is NULL on an https:// URL (e.g. the
 * Torizon OAuth2 token endpoint / device registration), the server is verified
 * against the compiled public-CA bundle.
 */
typedef struct {
    const char *url;                 /* full http(s):// URL */
    const char *method;              /* "GET" | "POST" | "PUT" */
    const char *cacert_pem;          /* server CA to pin; NULL for plain HTTP */
    const char *client_cert_pem;     /* mTLS client cert (NULL to omit) */
    const char *client_key_pem;      /* mTLS client private key */
    bool skip_server_cn_check;       /* dev only */
    int timeout_ms;                  /* 0 => 15s default */
    const char *content_type;        /* e.g. "application/json"; NULL to omit */
    const char *authorization;       /* full value, e.g. "Bearer xyz"; NULL to omit */
    const char *body;                /* request body (NULL for none) */
    size_t body_len;                 /* length of body */
} aktualino_net_req_cfg_t;

esp_err_t aktualino_net_request(const aktualino_net_req_cfg_t *cfg,
                                char **resp_out, size_t *resp_len,
                                int *out_status);

#ifdef __cplusplus
}
#endif
