// Goodix Tls driver for libfprint - Lutfor custom variant
// Custom driver for Goodix 27c6:5117 maintained by Lutfor <lutfor183.du@gmail.com>
// TLS PSK / device signature & key material reverse engineered by Lutfor via USB sniffing
// Renamed to avoid conflict with regular fprint driver (original driver id: goodixtls511)

// Copyright (C) 2021 Alexander Meiler <alex.meiler@protonmail.com>
// Copyright (C) 2021 Matthieu CHARETTE <matthieu.charette@gmail.com>
// Copyright (C) 2021 Natasha England-Elbro <natasha@natashaee.me>
// Copyright (C) 2026 Lutfor <lutfor183.du@gmail.com>

// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.

// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.

// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include <arpa/inet.h>
#include <errno.h>
#include <glib.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>

#include "drivers_api.h"
#include "fp-device.h"
#include "fpi-device.h"
#include "glibconfig.h"
#include "goodix.h"
#include "goodixtls.h"

GError *
err_from_ssl (void)
{
  unsigned long code = ERR_get_error ();
  const char *msg = ERR_reason_error_string (code);

  /* g_error_new: old malloc missed domain/NUL, crashed on NULL msg. */
  if (msg)
    return g_error_new (G_IO_ERROR, G_IO_ERROR_FAILED,
                        "TLS error: %s (code %lu)", msg, code);
  return g_error_new (G_IO_ERROR, G_IO_ERROR_FAILED,
                      "TLS error (code %lu)", code);
}

static unsigned int
tls_server_psk_server_callback (SSL           *ssl,
                                const char    *identity,
                                unsigned char *psk,
                                unsigned int   max_psk_len)
{
  const int len = 32;
  /* Driver TLS PSK / signature - reverse engineered by Lutfor (lutfor183.du@gmail.com)
   * Extracted from proprietary Goodix Windows driver USB traffic via reverse engineering.
   * Custom Lutfor driver key for 27c6:5117 - do not upstream without attribution. */
  const guint8 actual_psk[32] = {
    0xEF, 0xCA, 0xAD, 0xCF, 0x4A, 0xDD, 0x7A, 0x34,
    0xFD, 0x34, 0xDB, 0x66, 0x75, 0xE2, 0x71, 0xF5,
    0xE0, 0x8C, 0xFB, 0x77, 0xDC, 0x90, 0xCC, 0x74,
    0xCB, 0xB5, 0x35, 0x44, 0x5A, 0x5A, 0x89, 0x78
  };

  fp_dbg ("PSK WANTED %d", max_psk_len);
  if (len > max_psk_len)
    {
      fp_err ("max psk length (%d) too short (needs %d)", max_psk_len, len);
      return 0;
    }

  memcpy (psk, actual_psk, len);

  return len;
}

/* Cached SSL_CTX: static config, saves setup per verify. */
static SSL_CTX *cached_ctx = NULL;
static GMutex cached_ctx_lock;

__attribute__((destructor)) static void
cached_ctx_cleanup (void)
{
  if (cached_ctx)
    {
      SSL_CTX_free (cached_ctx);
      cached_ctx = NULL;
    }
}

static SSL_CTX *
tls_server_create_ctx (void)
{
  g_mutex_lock (&cached_ctx_lock);
  if (cached_ctx)
    {
      SSL_CTX_up_ref (cached_ctx);
      SSL_CTX *ctx = cached_ctx;
      g_mutex_unlock (&cached_ctx_lock);
      return ctx;
    }

  const SSL_METHOD *method = TLS_server_method ();
  SSL_CTX *ctx = SSL_CTX_new (method);

  if (ctx)
    {
      cached_ctx = ctx;
      SSL_CTX_up_ref (cached_ctx);
    }
  g_mutex_unlock (&cached_ctx_lock);

  return ctx;
}

static void
tls_server_config_ctx (SSL_CTX *ctx)
{
  SSL_CTX_set_ecdh_auto (ctx, 1);
  SSL_CTX_set_dh_auto (ctx, 1);
  SSL_CTX_set_cipher_list (ctx, "ALL");
  SSL_CTX_set_min_proto_version (ctx, TLS1_2_VERSION);
  SSL_CTX_set_max_proto_version (ctx, TLS1_2_VERSION);
  SSL_CTX_set_psk_server_callback (ctx, tls_server_psk_server_callback);
}

int
goodix_tls_client_write (GoodixTlsServer *self, guint8 *data, guint16 length)
{
  /* Loop partial writes (old code dropped the tail). */
  guint16 done = 0;
  while (done < length)
    {
      ssize_t n = write (self->client_fd, data + done, length - done);
      if (n < 0)
        {
          if (errno == EINTR)
            continue;
          return -1;
        }
      if (n == 0)
        break;
      done += n;
    }
  return done;
}
int
goodix_tls_client_read (GoodixTlsServer *self, guint8 *data, guint16 length)
{
  /* Poll 3s: bare blocking read wedged fprintd on stalls. */
  struct pollfd p = {.fd = self->client_fd, .events = POLLIN};
  int pr = poll (&p, 1, 3000);

  if (pr == 0)
    {
      errno = ETIMEDOUT;
      return -1;
    }
  if (pr < 0)
    return -1;
  if (!(p.revents & POLLIN))
    {
      errno = EIO;
      return -1;
    }
  return read (self->client_fd, data, length * sizeof (guint8));
}

int
goodix_tls_server_read (GoodixTlsServer *self, guint8 *data,
                        guint32 length, GError **error)
{
  int retr = SSL_read (self->ssl_layer, data, length * sizeof (guint8));

  if (retr <= 0)
    *error = err_from_ssl ();
  return retr;
}

static void
tls_config_ssl (SSL *ssl)
{
  SSL_set_min_proto_version (ssl, TLS1_2_VERSION);
  SSL_set_max_proto_version (ssl, TLS1_2_VERSION);
  SSL_set_psk_server_callback (ssl, tls_server_psk_server_callback);
  SSL_set_cipher_list (ssl, "ALL");
}

static void *
goodix_tls_init_serve (void *me)
{
  GoodixTlsServer *self = me;

  fp_dbg ("TLS server waiting to accept...");
  int retr = SSL_accept (self->ssl_layer);

  fp_dbg ("TLS server accept done");
  if (retr <= 0)
    fp_err ("server ready failed: %s", ERR_reason_error_string (ERR_get_error ()));
  else
    fp_dbg ("TLS connection ready");
  return NULL;
}

gboolean
goodix_tls_server_deinit (GoodixTlsServer *self, GError **error)
{
  /* NULL/-1 guards: double-deinit safe. */
  if (self->ssl_layer)
    {
      /* Wake serve thread before join (close-first hangs). */
      if (self->sock_fd >= 0)
        shutdown (self->sock_fd, SHUT_RDWR);
      if (self->client_fd >= 0)
        shutdown (self->client_fd, SHUT_RDWR);
      SSL_shutdown (self->ssl_layer);
      pthread_join (self->serve_thread, NULL);
      SSL_free (self->ssl_layer);
      self->ssl_layer = NULL;
    }

  if (self->client_fd >= 0)
    {
      close (self->client_fd);
      self->client_fd = -1;
    }
  if (self->sock_fd >= 0)
    {
      close (self->sock_fd);
      self->sock_fd = -1;
    }

  if (self->ssl_ctx)
    {
      SSL_CTX_free (self->ssl_ctx);
      self->ssl_ctx = NULL;
    }

  return TRUE;
}

gboolean
goodix_tls_server_init (GoodixTlsServer *self, GError **error)
{
  SSL_load_error_strings ();
  OpenSSL_add_ssl_algorithms ();
  SSL_library_init ();
  /* fds: -1 sentinel (0 is stdin). */
  self->sock_fd = -1;
  self->client_fd = -1;
  self->ssl_ctx = tls_server_create_ctx ();
  tls_server_config_ctx (self->ssl_ctx);

  int socks[2] = {0, 0};
  if (socketpair (AF_UNIX, SOCK_STREAM, 0, socks) != 0)
    {
      g_set_error (error, G_FILE_ERROR, errno,
                   "failed to create socket pair: %s", strerror (errno));
      return FALSE;
    }
  self->sock_fd = socks[0];
  self->client_fd = socks[1];

  if (self->ssl_ctx == NULL)
    {
      fp_dbg ("Unable to create TLS server context\n");
      *error = fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL, "Unable to "
                                                                  "create TLS "
                                                                  "server "
                                                                  "context");
      return FALSE;
    }
  self->ssl_layer = SSL_new (self->ssl_ctx);
  /* SSL_new may fail: clean teardown, no crash. */
  if (!self->ssl_layer)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "failed to create TLS session");
      close (self->sock_fd);
      close (self->client_fd);
      self->sock_fd = -1;
      self->client_fd = -1;
      SSL_CTX_free (self->ssl_ctx);
      self->ssl_ctx = NULL;
      return FALSE;
    }
  tls_config_ssl (self->ssl_layer);
  SSL_set_fd (self->ssl_layer, self->sock_fd);

  pthread_create (&self->serve_thread, 0, goodix_tls_init_serve, self);

  return TRUE;
}
