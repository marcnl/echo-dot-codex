#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "tls.h"

/* The stock libssl (BoringSSL).  Opaque types; only the calls below are used. */
typedef struct ssl_ctx_st SSL_CTX; typedef struct ssl_st SSL; typedef struct ssl_method_st SSL_METHOD;
typedef struct x509_vp_st X509_VERIFY_PARAM;

static struct {
    const SSL_METHOD *(*method)(void);
    SSL_CTX *(*ctx_new)(const SSL_METHOD *);
    void (*ctx_free)(SSL_CTX *);
    int (*load_locations)(SSL_CTX *, const char *file, const char *dir);
    void (*set_verify)(SSL_CTX *, int mode, void *cb);
    SSL *(*ssl_new)(SSL_CTX *);
    void (*ssl_free)(SSL *);
    int (*set_fd)(SSL *, int);
    int (*connect)(SSL *);
    int (*read)(SSL *, void *, int);
    int (*write)(SSL *, const void *, int);
    int (*get_error)(const SSL *, int);
    int (*pending)(const SSL *);
    int (*shutdown)(SSL *);
    long (*verify_result)(const SSL *);
    long (*sni)(SSL *, const char *);
    X509_VERIFY_PARAM *(*get0_param)(SSL *);
    int (*set1_host)(X509_VERIFY_PARAM *, const char *, size_t);
    unsigned long (*err_get)(void);
    void (*err_str_n)(unsigned long, char *, size_t);
} L;

static SSL_CTX *g_ctx;
static pthread_once_t g_once = PTHREAD_ONCE_INIT;

static void init(void)
{
    void *ssl = dlopen("libssl.so", RTLD_NOW), *cr = dlopen("libcrypto.so", RTLD_NOW);
    if (!ssl || !cr) { fprintf(stderr, "tls: cannot load libssl/libcrypto: %s\n", dlerror()); return; }
#define S(f, lib, name) *(void **)&L.f = dlsym(lib, name)
    S(method, ssl, "TLS_method"); S(ctx_new, ssl, "SSL_CTX_new"); S(ctx_free, ssl, "SSL_CTX_free");
    S(load_locations, ssl, "SSL_CTX_load_verify_locations"); S(set_verify, ssl, "SSL_CTX_set_verify");
    S(ssl_new, ssl, "SSL_new"); S(ssl_free, ssl, "SSL_free"); S(set_fd, ssl, "SSL_set_fd"); S(connect, ssl, "SSL_connect");
    S(read, ssl, "SSL_read"); S(write, ssl, "SSL_write"); S(get_error, ssl, "SSL_get_error"); S(pending, ssl, "SSL_pending");
    S(shutdown, ssl, "SSL_shutdown"); S(verify_result, ssl, "SSL_get_verify_result"); S(sni, ssl, "SSL_set_tlsext_host_name");
    S(get0_param, ssl, "SSL_get0_param"); S(set1_host, cr, "X509_VERIFY_PARAM_set1_host");
    S(err_get, cr, "ERR_get_error"); S(err_str_n, cr, "ERR_error_string_n");
    void **p = (void **)&L;
    for (size_t i = 0; i < sizeof L / sizeof *p; i++)
        if (!p[i]) { fprintf(stderr, "tls: libssl lacks a needed function (#%zu)\n", i); return; }
    SSL_CTX *c = L.ctx_new(L.method());
    if (!c) return;
    if (L.load_locations(c, NULL, "/system/etc/security/cacerts") != 1) {
        fprintf(stderr, "tls: cannot load CA store\n"); L.ctx_free(c); return;
    }
    L.set_verify(c, 1 /* SSL_VERIFY_PEER */, NULL);
    g_ctx = c;
}

static void report(const char *what)
{
    char b[160] = ""; unsigned long e = L.err_get();
    if (e) L.err_str_n(e, b, sizeof b);
    fprintf(stderr, "tls: %s%s%s\n", what, *b ? ": " : "", b);
}

struct pump { SSL *ssl; int tcp, app; };

/* Decrypted stream <-> app socket until either side closes. */
static void *pump(void *arg)
{
    struct pump *p = arg; char buf[8192];
    for (;;) {
        struct pollfd pf[2] = { { p->tcp, POLLIN, 0 }, { p->app, POLLIN, 0 } };
        if (L.pending(p->ssl) <= 0 && poll(pf, 2, -1) < 0 && errno != EINTR) break;
        if (L.pending(p->ssl) > 0 || (pf[0].revents & (POLLIN | POLLHUP | POLLERR))) {
            int n = L.read(p->ssl, buf, sizeof buf);
            if (n <= 0) { int e = L.get_error(p->ssl, n); if (e == 2 || e == 3) continue; break; }  /* WANT_READ/WRITE */
            for (int o = 0; o < n; ) {
                ssize_t w = send(p->app, buf + o, n - o, MSG_NOSIGNAL);
                if (w <= 0) goto done;
                o += w;
            }
        }
        if (pf[1].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t n = recv(p->app, buf, sizeof buf, 0);
            if (n <= 0) break;
            for (ssize_t o = 0; o < n; ) {
                int w = L.write(p->ssl, buf + o, n - o);
                if (w <= 0) goto done;
                o += w;
            }
        }
    }
done:
    L.shutdown(p->ssl); L.ssl_free(p->ssl); close(p->tcp); close(p->app); free(p);
    return NULL;
}

int tls_wrap(int fd, const char *host)
{
    pthread_once(&g_once, init);
    if (!g_ctx) { close(fd); return -1; }
    SSL *s = L.ssl_new(g_ctx);
    if (!s) { report("SSL_new"); close(fd); return -1; }
    L.sni(s, host);                                     /* SNI */
    L.set1_host(L.get0_param(s), host, 0);
    L.set_fd(s, fd);
    if (L.connect(s) != 1) {
        char m[96]; snprintf(m, sizeof m, "handshake with %s failed (verify result %ld)", host, L.verify_result(s));
        report(m);
        L.ssl_free(s); close(fd); return -1;
    }
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) { L.ssl_free(s); close(fd); return -1; }
    struct pump *p = malloc(sizeof *p);
    p->ssl = s; p->tcp = fd; p->app = sv[1];
    pthread_t t;
    if (pthread_create(&t, NULL, pump, p)) { L.ssl_free(s); close(fd); close(sv[0]); close(sv[1]); free(p); return -1; }
    pthread_detach(t);
    return sv[0];
}
