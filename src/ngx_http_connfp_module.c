/* SPDX-License-Identifier: BSD-2-Clause */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "connfp.h"

#if (NGX_LINUX)
#include <netinet/tcp.h>
#endif

typedef struct { ngx_flag_t save_syn; } connfp_srv_conf;
typedef struct { ngx_sockaddr_t sockaddr; socklen_t socklen; } connfp_endpoint;
typedef struct { ngx_array_t endpoints; } connfp_main_conf;
typedef struct {
    unsigned tls_seen:1;
    unsigned syn_seen:1;
    char tls[CONNFP_TLS_SIZE];
    char syn[CONNFP_SYN_SIZE];
} connfp_connection;

static ngx_int_t connfp_variables(ngx_conf_t *cf);
static ngx_int_t connfp_configure(ngx_conf_t *cf);
static ngx_int_t connfp_sockets(ngx_cycle_t *cycle);
static ngx_int_t connfp_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void *connfp_create_main(ngx_conf_t *cf);
static void *connfp_create_srv(ngx_conf_t *cf);
static char *connfp_merge_srv(ngx_conf_t *cf, void *parent, void *child);
static void connfp_message(int write_p, int version, int content_type,
    const void *buf, size_t len, SSL *ssl, void *arg);

static ngx_command_t connfp_commands[] = {
    { ngx_string("tcp_save_syn"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot, NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(connfp_srv_conf, save_syn), NULL },
    ngx_null_command
};
static ngx_http_module_t connfp_context = {
    connfp_variables, connfp_configure,
    connfp_create_main, NULL,
    connfp_create_srv, connfp_merge_srv,
    NULL, NULL
};
ngx_module_t ngx_http_connfp_module = {
    NGX_MODULE_V1, &connfp_context, connfp_commands, NGX_HTTP_MODULE,
    NULL, connfp_sockets, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};

static void *connfp_create_main(ngx_conf_t *cf)
{
    connfp_main_conf *conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (conf == NULL || ngx_array_init(&conf->endpoints, cf->pool, 4,
                                     sizeof(connfp_endpoint)) != NGX_OK) return NULL;
    return conf;
}
static void *connfp_create_srv(ngx_conf_t *cf)
{
    connfp_srv_conf *conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (conf) conf->save_syn = NGX_CONF_UNSET;
    return conf;
}
static char *connfp_merge_srv(ngx_conf_t *cf, void *parent, void *child)
{
    connfp_srv_conf *prev = parent, *conf = child;
    (void)cf;
    ngx_conf_merge_value(conf->save_syn, prev->save_syn, 0);
    return NGX_CONF_OK;
}

static ngx_int_t connfp_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t *v;
    ngx_uint_t i;
    static ngx_str_t names[] = {
        ngx_string("connfp_tls"), ngx_string("connfp_syn"),
        ngx_string("http_ssl_ja4"), ngx_string("http_ssl_ja4t"),
        ngx_string("connfp_registry")
    };
    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        /* Exact variables take precedence over the generic $http_* prefix. */
        v = ngx_http_add_variable(cf, &names[i], 0);
        if (v == NULL) return NGX_ERROR;
        v->get_handler = connfp_variable;
        v->data = i == 4 ? 2 : i % 2;
    }
    return NGX_OK;
}

static ngx_int_t connfp_configure(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_core_srv_conf_t **servers;
    ngx_http_ssl_srv_conf_t *ssl;
    ngx_http_conf_port_t *ports;
    ngx_http_conf_addr_t *addrs;
    connfp_srv_conf *scf;
    connfp_main_conf *mcf;
    connfp_endpoint *endpoint;
    ngx_uint_t i, j, k;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_connfp_module);
    servers = cmcf->servers.elts;
    for (i = 0; i < cmcf->servers.nelts; ++i) {
        ssl = servers[i]->ctx->srv_conf[ngx_http_ssl_module.ctx_index];
        if (ssl->ssl.ctx) {
            /* nginx's ClientHello callback still performs SNI/certificate selection.
             * The independent message callback sees reassembled handshake bytes. */
            SSL_CTX_set_msg_callback(ssl->ssl.ctx, connfp_message);
            SSL_CTX_set_msg_callback_arg(ssl->ssl.ctx, NULL);
        }
    }
    if (cmcf->ports == NULL) return NGX_OK;
    ports = cmcf->ports->elts;
    for (i = 0; i < cmcf->ports->nelts; ++i) {
        if (ports[i].type != SOCK_STREAM
            || (ports[i].family != AF_INET
#if (NGX_HAVE_INET6)
                && ports[i].family != AF_INET6
#endif
               )) continue;
        addrs = ports[i].addrs.elts;
        for (j = 0; j < ports[i].addrs.nelts; ++j) {
            servers = addrs[j].servers.elts;
            for (k = 0; k < addrs[j].servers.nelts; ++k) {
                scf = servers[k]->ctx->srv_conf[ngx_http_connfp_module.ctx_index];
                if (!scf->save_syn) continue;
                endpoint = ngx_array_push(&mcf->endpoints);
                if (endpoint == NULL) return NGX_ERROR;
                ngx_memzero(endpoint, sizeof(*endpoint));
                endpoint->socklen = addrs[j].opt.socklen;
                ngx_memcpy(&endpoint->sockaddr, addrs[j].opt.sockaddr,
                           endpoint->socklen);
                break;
            }
        }
    }
    return NGX_OK;
}

static ngx_int_t connfp_sockets(ngx_cycle_t *cycle)
{
#if (NGX_LINUX) && defined(TCP_SAVE_SYN) && defined(TCP_SAVED_SYN)
    ngx_http_conf_ctx_t *ctx;
    connfp_main_conf *mcf;
    connfp_endpoint *endpoints;
    ngx_listening_t *ls;
    ngx_http_port_t *port;
    ngx_http_in_addr_t *addr;
#if (NGX_HAVE_INET6)
    ngx_http_in6_addr_t *addr6;
#endif
    ngx_sockaddr_t sockaddr;
    ngx_uint_t i, j, k;
    int enabled;

    ctx = (ngx_http_conf_ctx_t *)ngx_get_conf(cycle->conf_ctx, ngx_http_module);
    if (ctx == NULL) return NGX_OK;
    mcf = ctx->main_conf[ngx_http_connfp_module.ctx_index];
    endpoints = mcf->endpoints.elts;
    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; ++i) {
        if (ls[i].handler != ngx_http_init_connection || ls[i].type != SOCK_STREAM
            || ls[i].fd == (ngx_socket_t)-1
            || (ls[i].sockaddr->sa_family != AF_INET
#if (NGX_HAVE_INET6)
                && ls[i].sockaddr->sa_family != AF_INET6
#endif
               )) continue;
        port = ls[i].servers;
        enabled = 0;
        /* nginx may fold several addresses into one wildcard listening socket.
         * Match its runtime address table, including non-default virtual hosts. */
        for (j = 0; j < port->naddrs; ++j) {
            ngx_memzero(&sockaddr, sizeof(sockaddr));
            ngx_memcpy(&sockaddr, ls[i].sockaddr, ls[i].socklen);
            if (sockaddr.sockaddr.sa_family == AF_INET) {
                addr = port->addrs;
                sockaddr.sockaddr_in.sin_addr.s_addr = addr[j].addr;
#if (NGX_HAVE_INET6)
            } else {
                addr6 = port->addrs;
                sockaddr.sockaddr_in6.sin6_addr = addr6[j].addr6;
#endif
            }
            for (k = 0; k < mcf->endpoints.nelts; ++k) {
                if (ngx_cmp_sockaddr(&sockaddr.sockaddr, ls[i].socklen,
                                    &endpoints[k].sockaddr.sockaddr,
                                    endpoints[k].socklen, 1) == NGX_OK) enabled = 1;
            }
        }
        /* Also clear the flag on inherited sockets after a configuration reload. */
        if (setsockopt(ls[i].fd, IPPROTO_TCP, TCP_SAVE_SYN, &enabled,
                       sizeof(enabled)) == -1 && enabled) {
            ngx_log_error(NGX_LOG_WARN, cycle->log, ngx_socket_errno,
                          "connfp: TCP_SAVE_SYN unavailable on %V", &ls[i].addr_text);
        }
    }
#else
    ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                  "connfp: TCP SYN capture is not supported by this build");
#endif
    return NGX_OK;
}

/* A pool cleanup identifies our per-connection cache without changing nginx's
 * connection ABI. It owns no separate resources and needs no cleanup work. */
static void connfp_cleanup(void *data) { (void)data; }
static connfp_connection *connfp_cache(ngx_connection_t *c)
{
    ngx_pool_cleanup_t *cln;
    for (cln = c->pool->cleanup; cln; cln = cln->next) {
        if (cln->handler == connfp_cleanup) return cln->data;
    }
    cln = ngx_pool_cleanup_add(c->pool, sizeof(connfp_connection));
    if (cln == NULL) return NULL;
    ngx_memzero(cln->data, sizeof(connfp_connection));
    cln->handler = connfp_cleanup;
    return cln->data;
}
static void connfp_message(int write_p, int version, int content_type,
    const void *buf, size_t len, SSL *ssl, void *arg)
{
    ngx_connection_t *c;
    connfp_connection *fp;
    (void)version; (void)arg;
    if (write_p || content_type != SSL3_RT_HANDSHAKE || len < 1
        || ((const u_char *)buf)[0] != SSL3_MT_CLIENT_HELLO) return;
    c = ngx_ssl_get_connection(ssl);
    if (c == NULL || c->pool == NULL) return;
    fp = connfp_cache(c);
    if (fp == NULL || fp->tls_seen) return;
    /* Keep the original ClientHello across HelloRetryRequest and keepalive. */
    fp->tls_seen = 1;
    if (!connfp_tls(buf, len, fp->tls)) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "connfp: invalid or unavailable ClientHello fingerprint");
    }
}
static ngx_int_t connfp_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_connection_t *c = r->connection;
    connfp_connection *fp;
    char *value;
#if (NGX_LINUX) && defined(TCP_SAVED_SYN)
    u_char packet[4096];
    socklen_t len = sizeof(packet);
#endif
    if (data == 2) {
        v->data = (u_char *)"1"; v->len = 1;
        v->valid = 1; v->not_found = 0; v->no_cacheable = 0;
        return NGX_OK;
    }
#if (NGX_HTTP_V2)
    if (r->stream) c = r->stream->connection->connection;
#endif
    fp = connfp_cache(c);
    if (fp == NULL) return NGX_ERROR;
    if (data == 1 && !fp->syn_seen) {
        fp->syn_seen = 1;
#if (NGX_LINUX) && defined(TCP_SAVED_SYN)
        if (getsockopt(c->fd, IPPROTO_TCP, TCP_SAVED_SYN, packet, &len) == 0 && len) {
            (void)connfp_syn(packet, len, fp->syn);
        }
#endif
    }
    value = data == 0 ? fp->tls : fp->syn;
    v->len = ngx_strlen(value);
    v->data = (u_char *)value;
    v->valid = 1; v->not_found = 0; v->no_cacheable = 0;
    return NGX_OK;
}
