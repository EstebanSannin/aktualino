#include "aktualino_net.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>   /* strcasecmp */

#include "esp_log.h"
#include "esp_http_client.h"
#if defined(CONFIG_MBEDTLS_CERTIFICATE_BUNDLE)
#include "esp_crt_bundle.h"
#endif

static const char *TAG = "akt_net";

#define AKT_NET_RX_CHUNK 1024
#define AKT_NET_DEFAULT_TIMEOUT_MS 10000
/* Torizon serves a binary target as a 302 to object storage; that S3 URL is
 * itself stable, but bound the chain so a misbehaving gateway can't loop us. */
#define AKT_NET_MAX_REDIRECTS 4

static bool status_is_redirect(int s)
{
    return s == 301 || s == 302 || s == 303 || s == 307 || s == 308;
}

/* The manual open()/fetch_headers()/read() flow does not retain arbitrary
 * response headers, so esp_http_client_get_header(client,"Location",…) comes
 * back empty on a 3xx. Capture the Location as headers stream past via the
 * event callback instead. user_data points at this ctx (heap-owned copy). */
typedef struct {
    char *location;
} akt_redirect_ctx_t;

static esp_err_t akt_redirect_evt(esp_http_client_event_t *evt)
{
    if (evt->event_id == HTTP_EVENT_ON_HEADER && evt->header_key &&
        strcasecmp(evt->header_key, "Location") == 0) {
        akt_redirect_ctx_t *ctx = (akt_redirect_ctx_t *)evt->user_data;
        if (ctx) {
            free(ctx->location);
            ctx->location = evt->header_value ? strdup(evt->header_value) : NULL;
        }
    }
    return ESP_OK;
}

/* Stream the open client's body into cb(), returning bytes delivered in *total.
 * Extracted so the initial (mTLS, pinned-CA) leg and any redirect (bundle-CA)
 * leg share one read loop. */
static esp_err_t stream_body(esp_http_client_handle_t client,
                             aktualino_net_data_cb cb, void *user,
                             size_t *total_out)
{
    char *buf = malloc(AKT_NET_RX_CHUNK);
    if (!buf) {
        return ESP_ERR_NO_MEM;
    }
    size_t total = 0;
    esp_err_t result = ESP_OK;
    while (!esp_http_client_is_complete_data_received(client)) {
        int r = esp_http_client_read(client, buf, AKT_NET_RX_CHUNK);
        if (r < 0) {
            ESP_LOGE(TAG, "read error after %zu bytes", total);
            result = ESP_FAIL;
            break;
        }
        if (r == 0) {
            /* No more data (or socket closed) — loop guard above ends it. */
            break;
        }
        result = cb(buf, (size_t)r, user);
        if (result != ESP_OK) {
            ESP_LOGW(TAG, "callback aborted transfer at %zu bytes", total);
            break;
        }
        total += (size_t)r;
    }
    free(buf);
    *total_out = total;
    return result;
}

esp_err_t aktualino_net_get_stream(const aktualino_net_get_cfg_t *cfg,
                                   aktualino_net_data_cb cb, void *user,
                                   int *out_status, size_t *out_len)
{
    if (out_status) {
        *out_status = 0;
    }
    if (out_len) {
        *out_len = 0;
    }
    if (!cfg || !cfg->url || !cb) {
        return ESP_ERR_INVALID_ARG;
    }

    akt_redirect_ctx_t rctx = { .location = NULL };

    esp_http_client_config_t hcfg = {
        .url = cfg->url,
        .timeout_ms = cfg->timeout_ms > 0 ? cfg->timeout_ms
                                          : AKT_NET_DEFAULT_TIMEOUT_MS,
        .cert_pem = cfg->cacert_pem,
        .client_cert_pem = cfg->client_cert_pem,
        .client_key_pem = cfg->client_key_pem,
        .skip_cert_common_name_check = cfg->skip_server_cn_check,
        .crt_bundle_attach = NULL,
        .keep_alive_enable = true,
        .event_handler = akt_redirect_evt,
        .user_data = &rctx,
    };
    if (!cfg->cacert_pem) {
        /* No pinned CA supplied: fall back to the compiled cert bundle if the
         * build enabled it. (Phase 0 dumb server passes its self-signed CA.) */
#if defined(CONFIG_MBEDTLS_CERTIFICATE_BUNDLE)
        hcfg.crt_bundle_attach = esp_crt_bundle_attach;
#endif
    }

    esp_http_client_handle_t client = esp_http_client_init(&hcfg);
    if (!client) {
        ESP_LOGE(TAG, "esp_http_client_init failed");
        return ESP_FAIL;
    }

    /* Follow redirects manually: the open()/fetch_headers()/read() streaming
     * flow does NOT auto-follow (that lives in esp_http_client_perform()). The
     * gateway 302s the target to a presigned object-storage URL on a different
     * host with a PUBLIC CA — so the redirect leg drops the pinned gateway CA
     * and the mTLS client cert and validates against the compiled bundle. This
     * is safe: the streamed bytes are sha256 + length verified by the caller
     * against the two-repo-verified Director/Image target, so integrity does
     * not depend on transport trust for the (already-authorised) redirect. */
    char *redirect_url = NULL;   /* owned copy of the current Location, or NULL */
    int status = 0;
    int hops = 0;

    for (;;) {
        free(rctx.location);       /* fresh capture per leg */
        rctx.location = NULL;

        esp_err_t err = esp_http_client_open(client, 0);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "connect/open failed: %s", esp_err_to_name(err));
            esp_http_client_cleanup(client);
            free(redirect_url);
            free(rctx.location);
            return err;
        }

        int64_t content_len = esp_http_client_fetch_headers(client);
        status = esp_http_client_get_status_code(client);
        if (redirect_url) {
            ESP_LOGI(TAG, "GET (redirect) %.72s… -> HTTP %d (content-length=%lld)",
                     redirect_url, status, (long long)content_len);
        } else {
            ESP_LOGI(TAG, "GET %s -> HTTP %d (content-length=%lld)",
                     cfg->url, status, (long long)content_len);
        }

        if (!status_is_redirect(status)) {
            break;
        }
        if (hops++ >= AKT_NET_MAX_REDIRECTS) {
            ESP_LOGE(TAG, "too many redirects (%d) — abort", hops);
            esp_http_client_close(client);
            esp_http_client_cleanup(client);
            free(redirect_url);
            free(rctx.location);
            if (out_status) {
                *out_status = status;
            }
            return ESP_FAIL;
        }

        if (!rctx.location || !rctx.location[0]) {
            ESP_LOGE(TAG, "HTTP %d redirect without Location — abort", status);
            esp_http_client_close(client);
            esp_http_client_cleanup(client);
            free(redirect_url);
            free(rctx.location);
            if (out_status) {
                *out_status = status;
            }
            return ESP_FAIL;
        }
        char *newurl = strdup(rctx.location);  /* copy before we cleanup client */
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        free(redirect_url);
        redirect_url = newurl;
        if (!redirect_url) {
            free(rctx.location);
            return ESP_ERR_NO_MEM;
        }
        ESP_LOGI(TAG, "following HTTP %d redirect to %.60s… (bundle-CA leg)",
                 status, redirect_url);

        /* Fresh client for the redirect target: public-CA bundle, no pinned CA,
         * no mTLS client cert (object storage authenticates via the presigned
         * query string, not TLS client auth). */
        esp_http_client_config_t rcfg = {
            .url = redirect_url,
            .timeout_ms = cfg->timeout_ms > 0 ? cfg->timeout_ms
                                              : AKT_NET_DEFAULT_TIMEOUT_MS,
            .keep_alive_enable = true,
            .event_handler = akt_redirect_evt,
            .user_data = &rctx,
            /* The presigned object-storage URL carries a ~1.5 KB query string
             * (AWS SigV4). The default 512-byte TX buffer can't hold the GET
             * request line, so esp_http_client returns "Out of buffer" on open.
             * Size both buffers up to fit the full request/response headers. */
            .buffer_size = 2048,
            .buffer_size_tx = 4096,
#if defined(CONFIG_MBEDTLS_CERTIFICATE_BUNDLE)
            .crt_bundle_attach = esp_crt_bundle_attach,
#endif
        };
        client = esp_http_client_init(&rcfg);
        if (!client) {
            ESP_LOGE(TAG, "redirect client init failed");
            free(redirect_url);
            free(rctx.location);
            return ESP_FAIL;
        }
    }

    if (out_status) {
        *out_status = status;
    }

    size_t total = 0;
    esp_err_t result = stream_body(client, cb, user, &total);

    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    free(redirect_url);
    free(rctx.location);

    if (out_len) {
        *out_len = total;
    }
    return result;
}

/* ------------------------------------------------------------------ *
 * Buffered request (POST/PUT/GET with body + collected response).
 * ------------------------------------------------------------------ */
static esp_http_client_method_t method_from_str(const char *m)
{
    if (m && strcmp(m, "POST") == 0) return HTTP_METHOD_POST;
    if (m && strcmp(m, "PUT") == 0)  return HTTP_METHOD_PUT;
    return HTTP_METHOD_GET;
}

esp_err_t aktualino_net_request(const aktualino_net_req_cfg_t *cfg,
                                char **resp_out, size_t *resp_len,
                                int *out_status)
{
    if (resp_out) *resp_out = NULL;
    if (resp_len) *resp_len = 0;
    if (out_status) *out_status = 0;
    if (!cfg || !cfg->url) return ESP_ERR_INVALID_ARG;

    esp_http_client_config_t hcfg = {
        .url = cfg->url,
        .method = method_from_str(cfg->method),
        .timeout_ms = cfg->timeout_ms > 0 ? cfg->timeout_ms : 15000,
        .cert_pem = cfg->cacert_pem,
        .client_cert_pem = cfg->client_cert_pem,
        .client_key_pem = cfg->client_key_pem,
        .skip_cert_common_name_check = cfg->skip_server_cn_check,
        .keep_alive_enable = false,
        .crt_bundle_attach = NULL,
        /* The Torizon Authorization: Bearer header is a ~1.4 KB JWT, which
         * overflows the default 512-byte request-header buffer; size it up. */
        .buffer_size_tx = 3072,
    };
    /* No pinned CA on an https:// URL (e.g. the Torizon OAuth2 token endpoint or
     * the /accounts/devices registration): verify against the compiled public-CA
     * bundle. Pinned-CA mTLS calls (cacert_pem set) ignore this. */
    if (!cfg->cacert_pem) {
        hcfg.crt_bundle_attach = esp_crt_bundle_attach;
    }

    esp_http_client_handle_t client = esp_http_client_init(&hcfg);
    if (!client) {
        ESP_LOGE(TAG, "http_client_init failed");
        return ESP_FAIL;
    }

    if (cfg->content_type) {
        esp_http_client_set_header(client, "Content-Type", cfg->content_type);
    }
    if (cfg->authorization) {
        esp_http_client_set_header(client, "Authorization", cfg->authorization);
    }

    esp_err_t err = esp_http_client_open(client, cfg->body ? cfg->body_len : 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "connect/open failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return err;
    }

    if (cfg->body && cfg->body_len > 0) {
        int written = 0;
        while ((size_t)written < cfg->body_len) {
            int w = esp_http_client_write(client, cfg->body + written,
                                          cfg->body_len - written);
            if (w < 0) {
                ESP_LOGE(TAG, "body write failed");
                esp_http_client_close(client);
                esp_http_client_cleanup(client);
                return ESP_FAIL;
            }
            written += w;
        }
    }

    int64_t content_len = esp_http_client_fetch_headers(client);
    int status = esp_http_client_get_status_code(client);
    if (out_status) *out_status = status;
    ESP_LOGI(TAG, "%s %s -> HTTP %d (content-length=%lld)",
             cfg->method ? cfg->method : "GET", cfg->url, status,
             (long long)content_len);

    /* Collect the response body into a growable buffer. */
    size_t cap = (content_len > 0) ? (size_t)content_len + 1 : 1024;
    char *buf = malloc(cap);
    if (!buf) {
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return ESP_ERR_NO_MEM;
    }
    size_t total = 0;
    esp_err_t result = ESP_OK;
    for (;;) {
        if (total + 1 >= cap) {
            size_t ncap = cap * 2;
            char *nb = realloc(buf, ncap);
            if (!nb) { result = ESP_ERR_NO_MEM; break; }
            buf = nb; cap = ncap;
        }
        int r = esp_http_client_read(client, buf + total, cap - total - 1);
        if (r < 0) { result = ESP_FAIL; break; }
        if (r == 0) {
            if (esp_http_client_is_complete_data_received(client)) break;
            if (content_len >= 0) break;      /* known length, all read */
            break;                            /* socket closed */
        }
        total += (size_t)r;
    }
    buf[total] = '\0';

    esp_http_client_close(client);
    esp_http_client_cleanup(client);

    if (result != ESP_OK) { free(buf); return result; }
    if (resp_out) { *resp_out = buf; } else { free(buf); }
    if (resp_len) *resp_len = total;
    return ESP_OK;
}
