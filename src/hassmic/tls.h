/* Client-side TLS for the media downloader (https:// reply and music URLs), on the Echo's own libssl: hassmic has no TLS
 * code of its own and the NDK has no OpenSSL headers, so the few calls it needs are declared in tls.c and found with dlopen. */
#ifndef TLS_H
#define TLS_H

/* Takes the connected TCP socket fd to host, runs the TLS handshake and verifies the certificate chain (system CA store)
 * and that it is valid for host.  Returns a plain socket that carries the decrypted stream both ways (a thread pumps it
 * and closes the TCP socket when the returned fd is closed), or -1 with fd closed.  Errors go to stderr. */
int tls_wrap(int fd, const char *host);
#endif
