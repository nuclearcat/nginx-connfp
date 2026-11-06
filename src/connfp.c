/* SPDX-License-Identifier: BSD-2-Clause */
#include "connfp.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { const uint8_t *p; size_t n; } cursor;
typedef struct { uint16_t *v; size_t n; } list;

static unsigned u16(const uint8_t *p) { return ((unsigned)p[0] << 8) | p[1]; }
static int take(cursor *c, size_t n, cursor *value)
{
    if (n > c->n) return 0;
    value->p = c->p; value->n = n;
    c->p += n; c->n -= n;
    return 1;
}
static int vector(cursor *c, unsigned width, cursor *value)
{
    cursor length;
    if (!take(c, width, &length)) return 0;
    return take(c, width == 1 ? length.p[0] : u16(length.p), value);
}
/* RFC 8701: the two bytes must also be equal (0x1a2a is NOT GREASE). */
static int grease(unsigned v)
{
    return (v >> 8) == (v & 255) && (v & 15) == 10;
}
static int ephemeral(unsigned v)
{
    return v == 21 || v == 35 || v == 41 || v == 42 || v == 44 || v == 45;
}
static int compare(const void *a, const void *b)
{
    return (int)*(const uint16_t *)a - (int)*(const uint16_t *)b;
}
static int parse_list(cursor c, list *l, int filter)
{
    size_t i;
    if (c.n % 2) return 0;
    l->v = malloc(c.n ? c.n : 1);
    if (!l->v) return 0;
    for (i = 0; i < c.n; i += 2) {
        unsigned v = u16(c.p + i);
        if (!filter || !grease(v)) l->v[l->n++] = (uint16_t)v;
    }
    return 1;
}
static char *format_list(char *p, const list *l)
{
    size_t i;
    for (i = 0; i < l->n; ++i) {
        if (i) *p++ = ',';
        p += sprintf(p, "%04x", (unsigned)l->v[i]);
    }
    return p;
}
static int hash_lists(list *first, const list *second, char out[13])
{
    char *input, *end;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int size;
    size_t i, capacity = 5 * (first->n + (second ? second->n : 0)) + 2;
    input = malloc(capacity);
    if (!input) return 0;
    qsort(first->v, first->n, sizeof(uint16_t), compare);
    end = format_list(input, first);
    if (second) { *end++ = '_'; end = format_list(end, second); }
    i = EVP_Digest(input, (size_t)(end - input), digest, &size, EVP_sha256(), NULL);
    free(input);
    if (i != 1 || size < 6) return 0;
    for (i = 0; i < 6; ++i) sprintf(out + 2 * i, "%02x", digest[i]);
    return 1;
}
static const char *version_name(unsigned v)
{
    switch (v) {
    case 0x0300: return "s3";
    case 0x0301: return "10";
    case 0x0302: return "11";
    case 0x0303: return "12";
    case 0x0304: return "13";
    default: return "00";
    }
}
static char alpn_char(unsigned v)
{
    if (v >= 'A' && v <= 'Z') v += 'a' - 'A';
    return (v >= 'a' && v <= 'z') || (v >= '0' && v <= '9') ? (char)v : '0';
}

int connfp_tls(const uint8_t *hello, size_t len, char out[CONNFP_TLS_SIZE])
{
    cursor c = {hello, len}, header, field, exts, data, values;
    list ciphers = {0}, extensions = {0}, sigalgs = {0}, groups = {0};
    unsigned version, type, sni = 0, count = 0, seen_sig = 0, seen_groups = 0;
    unsigned seen_alpn = 0, seen_versions = 0;
    char alpn[3] = "00", b[13], h[13], d[13] = "";
    int ok = 0;
    out[0] = 0;
    if (!take(&c, 4, &header) || header.p[0] != 1
        || (((size_t)header.p[1] << 16) | ((size_t)header.p[2] << 8)
            | header.p[3]) != c.n) goto done;
    if (!take(&c, 34, &field)) goto done;
    version = u16(field.p);
    if (!vector(&c, 1, &field) || field.n > 32
        || !vector(&c, 2, &field) || !field.n
        || !parse_list(field, &ciphers, 1)
        || !vector(&c, 1, &field) || !field.n) goto done;
    exts.p = c.p; exts.n = 0;
    if (c.n && (!vector(&c, 2, &exts) || c.n)) goto done;
    extensions.v = malloc(exts.n ? exts.n : 1);
    if (!extensions.v) goto done;
    while (exts.n) {
        if (!take(&exts, 2, &field) || !vector(&exts, 2, &data)) goto done;
        type = u16(field.p);
        if (grease(type) || ephemeral(type)) continue;
        ++count;
        if (type != 0 && type != 16) extensions.v[extensions.n++] = (uint16_t)type;
        switch (type) {
        case 0: sni = 1; break;
        case 10:
        case 13:
            if (!vector(&data, 2, &values) || data.n || !values.n) goto done;
            if (type == 10) {
                if (seen_groups++ || !parse_list(values, &groups, 1)) goto done;
            } else {
                /* §6.6 preserves signature algorithms in advertised order. */
                if (seen_sig++ || !parse_list(values, &sigalgs, 0)) goto done;
            }
            break;
        case 16:
            if (seen_alpn++ || !vector(&data, 2, &values) || data.n) goto done;
            if (values.n) {
                if (!vector(&values, 1, &field)) goto done;
                if (field.n) {
                    alpn[0] = alpn_char(field.p[0]);
                    alpn[1] = alpn_char(field.p[field.n - 1]);
                }
                while (values.n) if (!vector(&values, 1, &field) || !field.n) goto done;
            }
            break;
        case 43:
            if (seen_versions++ || !vector(&data, 1, &values) || data.n
                || !values.n || values.n % 2) goto done;
            version = 0;
            while (values.n) {
                if (!take(&values, 2, &field)) goto done;
                if (!grease(u16(field.p)) && u16(field.p) > version) version = u16(field.p);
            }
            break;
        }
    }
    if (!hash_lists(&ciphers, NULL, b) || !hash_lists(&extensions, &sigalgs, h)
        || (groups.n && !hash_lists(&groups, NULL, d))) goto done;
    snprintf(out, CONNFP_TLS_SIZE, "t%s%c%02u%02u%s_%s_%s_%s",
             version_name(version), sni ? 'd' : 'i',
             (unsigned)(ciphers.n > 99 ? 99 : ciphers.n), count > 99 ? 99 : count,
             alpn, b, h, d);
    ok = 1;
done:
    free(ciphers.v); free(extensions.v); free(sigalgs.v); free(groups.v);
    return ok;
}

int connfp_syn(const uint8_t *p, size_t n, char out[CONNFP_SYN_SIZE])
{
    size_t offset, end, i, length, used = 0;
    unsigned ip, ttl, next, kind, window, mss = 0, scale = 0;
    int have_mss = 0, have_scale = 0;
    char options[128] = "", mss_text[8] = "-", scale_text[8] = "-", df[2] = "-";
    out[0] = 0;
    if (!n) return 0;
    ip = p[0] >> 4;
    if (ip == 4) {
        if (n < 20 || (p[0] & 15) < 5 || p[9] != 6 || (u16(p + 6) & 0x3fff)) return 0;
        offset = (p[0] & 15) * 4;
        ttl = p[8]; df[0] = p[6] & 0x40 ? '1' : '0';
    } else if (ip == 6) {
        if (n < 40) return 0;
        offset = 40; ttl = p[7]; next = p[6];
        while (next != 6) {
            if (offset + 2 > n) return 0;
            if (next == 0 || next == 43 || next == 60) length = ((size_t)p[offset + 1] + 1) * 8;
            else if (next == 51) length = ((size_t)p[offset + 1] + 2) * 4;
            else return 0;
            next = p[offset];
            if (length > n - offset) return 0;
            offset += length;
        }
    } else return 0;
    if (offset > n || n - offset < 20) return 0;
    /* Only a client SYN: not SYN+ACK, RST or FIN. */
    if ((p[offset + 13] & 0x17) != 2) return 0;
    end = offset + (p[offset + 12] >> 4) * 4;
    if (end < offset + 20 || end > n) return 0;
    window = u16(p + offset + 14);
    i = offset + 20;
    while (i < end) {
        kind = p[i];
        used += (size_t)snprintf(options + used, sizeof(options) - used,
                                "%s%u", used ? "-" : "", kind);
        if (used >= sizeof(options)) return 0;
        if (kind == 0) break;
        if (kind == 1) { ++i; continue; }
        if (end - i < 2 || p[i + 1] < 2 || p[i + 1] > end - i) return 0;
        length = p[i + 1];
        if (kind == 2) {
            if (length != 4 || have_mss++) return 0;
            mss = u16(p + i + 2);
        } else if (kind == 3) {
            if (length != 3 || have_scale++) return 0;
            scale = p[i + 2];
        }
        i += length;
    }
    if (have_mss) snprintf(mss_text, sizeof(mss_text), "%u", mss);
    if (have_scale) snprintf(scale_text, sizeof(scale_text), "%u", scale);
    snprintf(out, CONNFP_SYN_SIZE, "syn1:%u:%u:%s:%u:%s:%s:%s",
             ip, ttl, df, window, mss_text, scale_text, used ? options : "-");
    return 1;
}
