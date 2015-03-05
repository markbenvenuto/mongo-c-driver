/*
 * Copyright 2015 MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mongoc-config.h"

#ifdef MONGOC_ENABLE_SSL
#ifdef MONGOC_WINDOWS_NATIVE_TLS

#include <bson.h>

#include <errno.h>
#include <string.h>

/* Use Windows SChannel */
#define SECURITY_WIN32
#include <security.h>
#include <Schnlsp.h>

#include "mongoc-counters-private.h"
#include "mongoc-errno-private.h"
#include "mongoc-stream-windows-tls.h"
#include "mongoc-stream-private.h"
#include "mongoc-ssl-private.h"
#include "mongoc-trace.h"
#include "mongoc-log.h"

#undef MONGOC_LOG_DOMAIN
#define MONGOC_LOG_DOMAIN "stream-windows-tls"

/* magic API setup for SChannel */
#define mongoc_stream_tls_do_handshake_impl mongoc_stream_windows_tls_do_handshake
#define mongoc_stream_tls_check_cert_impl mongoc_stream_windows_tls_check_cert
#define mongoc_stream_tls_new_impl mongoc_stream_windows_tls_new

#define SEC_SUCCESS(Status) ((Status) >= 0)
#define SEC_ISDONE(status) (!(status == SEC_I_CONTINUE_NEEDED || status  == SEC_I_COMPLETE_AND_CONTINUE))


/**
 * mongoc_stream_windows_tls_t:
 *
 * Private storage for handling callbacks from mongoc_stream and
 * SChannel.
 *
 * The one funny wrinkle comes with timeout, which we use to
 * statefully pass timeouts through from the mongoc-stream api.
 *
 * TODO: is there a cleaner way to manage that?
 */
typedef struct
{
   mongoc_stream_t  parent;
   mongoc_stream_t *base_stream;

   int client;

   int32_t          timeout_msec;
   bool             weak_cert_validation;

   int certificate_valid;
   char* server_target_name;

   /* Windows specific SChannel Data*/
   CredHandle credential_handle;
   SecHandle security_context;

   PCCERT_CONTEXT certificate;

   // SSL Padding
   ULONG ssl_max_packet_size;
   ULONG security_trailer_count;
   ULONG security_header_count;

   // Read Side Buffers
   // -------------------
   // Socket --> SSPI --> User
   //
   // Socket -- (SSPI Read Buffer) --> SSPI -- (User Read Buffer) --> User

   // Packet Read Buffers

   // This is our buffers when SChannel DecryptMessage decrypts more data then the user
   // is asking for at the moment
   //
   // This is the maximum size of an SSL packet as SSPI tells us
   // Set at init, and never changed
   char* packet_read_buffer_holder;
   unsigned packet_read_buffer_holder_length;

   // This is current amount of used data in the packet_read_buffer_holder
   char* packet_read_buffer;
   unsigned packet_read_buffer_length;

   // This is our buffer for when the socket reads more then one SSL packet
   // so we store the "extra" data until we do the next packet decryption
   //
   char* sspi_read_buffer_holder;
   unsigned sspi_read_buffer_holder_length;

   unsigned sspi_read_buffer_length;
   char* sspi_read_buffer;

} mongoc_stream_windows_tls_t;

/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_windows_tls_destroy --
 *
 *       Cleanup after usage of a mongoc_stream_windows_tls_t. Free all allocated
 *       resources and ensure connections are closed.
 *
 * Returns:
 *       None.
 *
 * Side effects:
 *       None.
 *
 *--------------------------------------------------------------------------
 */

static void
_mongoc_stream_windows_tls_destroy (mongoc_stream_t *stream)
{
   mongoc_stream_windows_tls_t *tls = (mongoc_stream_windows_tls_t *)stream;

   BSON_ASSERT (tls);


   DeleteSecurityContext(&tls->credential_handle);
   FreeCredentialHandle(&tls->security_context);

   free(tls->packet_read_buffer_holder);
   free(tls->sspi_read_buffer_holder);


   mongoc_stream_destroy (tls->base_stream);
   tls->base_stream = NULL;

   bson_free (stream);

   mongoc_counter_streams_active_dec();
   mongoc_counter_streams_disposed_inc();
}


/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_windows_tls_close --
 *
 *       Close the underlying socket.
 *
 * Returns:
 *       0 on success; otherwise -1.
 *
 * Side effects:
 *       None.
 *
 *--------------------------------------------------------------------------
 */

static int
_mongoc_stream_windows_tls_close (mongoc_stream_t *stream)
{
   mongoc_stream_windows_tls_t *tls = (mongoc_stream_windows_tls_t *)stream;

   BSON_ASSERT (tls);

   return mongoc_stream_close (tls->base_stream);
}


/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_windows_tls_flush --
 *
 *       Flush the underlying stream.
 *
 * Returns:
 *       0 if successful; otherwise -1.
 *
 * Side effects:
 *       None.
 *
 *--------------------------------------------------------------------------
 */

static int
_mongoc_stream_windows_tls_flush (mongoc_stream_t *stream)
{
   mongoc_stream_windows_tls_t *tls = (mongoc_stream_windows_tls_t *)stream;

   BSON_ASSERT (tls);

   return mongoc_stream_flush(tls->base_stream);
}

/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_windows_tls_ssl_read --
 *
 *       Reads encrypted data from the socket.
 *
 * Returns:
 *       0 on success.
 *
 * Side effects:
 *       None.
 *
 *--------------------------------------------------------------------------
 */

static int
_mongoc_stream_windows_tls_ssl_read(mongoc_stream_windows_tls_t* tls,
void *data,
size_t *data_length)
{
    // TODO this should sometimes return errors I think...
    mongoc_iovec_t iov;
    ssize_t read_length;

    iov.iov_base = data;
    iov.iov_len = (u_long)*data_length;
    read_length = mongoc_stream_readv(tls->base_stream, &iov, 1,
        1 /* min bytes */, tls->timeout_msec);
    *data_length = read_length;
    return 0;
}

/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_windows_tls_ssl_write --
 *
 *       Writes encrypted data to the socket.
 *
 * Returns:
 *       0 on success, -1 on error.
 *
 * Side effects:
 *       None.
 *
 *--------------------------------------------------------------------------
 */
static int
_mongoc_stream_windows_tls_ssl_write(mongoc_stream_windows_tls_t* tls,
const void *data,
size_t data_length)
{
    // TODO this should sometimes return errors I think...
    mongoc_iovec_t iov;
    ssize_t write_length;

    iov.iov_base = (char *)data;
    iov.iov_len = (u_long)data_length;
    write_length = mongoc_stream_writev(tls->base_stream, &iov, 1,
        tls->timeout_msec);
    if (write_length == -1)
        return -1;

    BSON_ASSERT(data_length == write_length);
    return (int)write_length;
}

/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_windows_tls_ssl_encrypt --
 *
 *       Encrypts and signs a buffer of data.
 *
 * Returns:
 *       SECURITY_STATUS
 *       Buffer is allocated in ppOutput that caller must free.
 *
 * Side effects:
 *       None
 *
 *--------------------------------------------------------------------------
 */
static SECURITY_STATUS 
_mongoc_stream_windows_tls_ssl_encrypt(
    mongoc_stream_windows_tls_t *tls,
    char* pMessage,
    unsigned cbMessage,
    char** ppOutput,
    unsigned *pcbOutput)
{
    SECURITY_STATUS   security_status;
    SecBufferDesc     security_buffer_desc;
    SecBuffer       security_buffer[4];
    ULONG             qop = 0;
    int buffer_size;

    printf("Data before encryption: %s\n", pMessage);
    printf("Length of data before encryption: %d \n", cbMessage);

    // TODO: remove buffer allocation or make this only occur on large messages
    buffer_size = tls->security_trailer_count + tls->security_header_count + cbMessage;
    *ppOutput = malloc(buffer_size);

    security_buffer_desc.ulVersion = 0;
    security_buffer_desc.cBuffers = 4;
    security_buffer_desc.pBuffers = security_buffer;

    security_buffer[0].BufferType = SECBUFFER_STREAM_HEADER;
    security_buffer[0].cbBuffer = tls->security_header_count;
    security_buffer[0].pvBuffer = *ppOutput;

    memcpy_s(*ppOutput + tls->security_header_count, 
        buffer_size - tls->security_header_count, pMessage, cbMessage);

    security_buffer[1].BufferType = SECBUFFER_DATA;
    security_buffer[1].cbBuffer = cbMessage;
    security_buffer[1].pvBuffer = *ppOutput + tls->security_header_count;

    security_buffer[2].cbBuffer = tls->security_trailer_count;
    security_buffer[2].BufferType = SECBUFFER_STREAM_TRAILER;
    security_buffer[2].pvBuffer = *ppOutput + tls->security_header_count + cbMessage;

    security_buffer[3].cbBuffer = 0;
    security_buffer[3].BufferType = SECBUFFER_EMPTY;
    security_buffer[3].pvBuffer = 0;

    security_status = EncryptMessage(
        &tls->security_context,
        qop,
        &security_buffer_desc,
        0);

    if (!SEC_SUCCESS(security_status))
    {
        free(*ppOutput);
        MONGOC_WARNING("EncryptMessage(): %d", security_status);
        return security_status;
    }

    int size = security_buffer[0].cbBuffer + security_buffer[1].cbBuffer + security_buffer[2].cbBuffer;
    *pcbOutput = size;

    printf("data after encryption including trailer (%lu bytes):\n",
        *pcbOutput);

    return SEC_E_OK;
}


/*
 *--------------------------------------------------------------------------
 *
 * __mongoc_stream_tls_write_buffered --
 *
 *       Encrypts and signs a buffer of data, and sends it over the network
 *
 * Returns:
 *       SECURITY_STATUS
 *
 * Side effects:
 *       None
 *
 *--------------------------------------------------------------------------
 */
static SECURITY_STATUS
_mongoc_stream_tls_write_buffered(mongoc_stream_windows_tls_t* tls, 
void* buf,
    int len,
    unsigned *written)
{
    SECURITY_STATUS security_status;
    char* pOutput;

    security_status = _mongoc_stream_windows_tls_ssl_encrypt(tls, (char*)buf, len, &pOutput, written);
    if (!SEC_SUCCESS(security_status)) {
        BSON_ASSERT(FALSE);
        return security_status;
    }

    int sent = _mongoc_stream_windows_tls_ssl_write(tls, pOutput, *written);

    free(pOutput);

    if (sent == -1) {
        BSON_ASSERT(FALSE);
        return ERROR_WRITE_FAULT;
    }

    BSON_ASSERT(sent == *written);

    // Tell the caller we sent the unencrypted length
    *written = len;

    return SEC_E_OK;
}

/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_windows_tls_writev --
 *
 *       Write the iovec to the stream. This function will try to write
 *       all of the bytes or fail. If the number of bytes is not equal
 *       to the number requested, a failure or EOF has occurred.
 *
 * Returns:
 *       -1 on failure, otherwise the number of bytes written.
 *
 * Side effects:
 *       None.
 *
 *--------------------------------------------------------------------------
 */
static ssize_t
_mongoc_stream_windows_tls_writev (mongoc_stream_t *stream,
                                 mongoc_iovec_t  *iov,
                                 size_t           iovcnt,
                                 int32_t          timeout_msec)
{
   mongoc_stream_windows_tls_t *tls = (mongoc_stream_windows_tls_t *)stream;
   int error;
   ssize_t ret = 0;
   size_t i;
   size_t iov_pos = 0;
   int write_ret;

   int64_t now;
   int64_t expire = 0;

   BSON_ASSERT (tls);
   BSON_ASSERT (iov);
   BSON_ASSERT (iovcnt);

   tls->timeout_msec = timeout_msec;

   if (timeout_msec >= 0) {
      expire = bson_get_monotonic_time () + (timeout_msec * 1000UL);
   }

   for (i = 0; i < iovcnt; i++) {
      iov_pos = 0;

      while (iov_pos < iov[i].iov_len) {
          error = _mongoc_stream_tls_write_buffered(tls,
                          iov[i].iov_base + iov_pos,
                          (int)(iov[i].iov_len - iov_pos),
                          &write_ret);

         if (0 != error) {
            return -1;
         }

         if (expire) {
            now = bson_get_monotonic_time ();

            if ((expire - now) < 0) {
               if (write_ret == 0) {
                  mongoc_counter_streams_timeout_inc();
                  errno = ETIMEDOUT;
                  return -1;
               }

               tls->timeout_msec = 0;
            } else {
               tls->timeout_msec = (int32_t)((expire - now) / 1000L);
            }
         }

         ret += write_ret;
         iov_pos += write_ret;
      }
   }

   if (ret >= 0) {
      mongoc_counter_streams_egress_add(ret);
   }

   return ret;
}


/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_windows_tls_ssl_try_decrypt --
 *
 *       Tries to decrypt data from sockets. May ask for more data,
 *       signal for renegotiation, or signal for connection shutdown.
 *
 * Returns:
 *       SECURITY_STATUS, may need for data from socket
 *
 * Side effects:
 *       May store extra data from sspi in sspi_read_buffer_holder.
 *
 *--------------------------------------------------------------------------
 */
static SECURITY_STATUS 
_mongoc_stream_windows_tls_ssl_try_decrypt(
    mongoc_stream_windows_tls_t* tls, 
    char* buf, unsigned used, 
    char** ppOutput, unsigned *pcbOutLen) {
    SECURITY_STATUS   security_status;
    SecBufferDesc     security_buffer_desc;
    SecBuffer         security_buffer[4];
    ULONG             qop = 0;

    security_buffer_desc.ulVersion = 0;
    security_buffer_desc.cBuffers = 4;
    security_buffer_desc.pBuffers = security_buffer;

    security_buffer[0].cbBuffer = used;
    security_buffer[0].BufferType = SECBUFFER_DATA;
    security_buffer[0].pvBuffer = buf;

    security_buffer[1].cbBuffer = 0;
    security_buffer[1].BufferType = SECBUFFER_EMPTY;
    security_buffer[1].pvBuffer = 0;

    security_buffer[2].cbBuffer = 0;
    security_buffer[2].BufferType = SECBUFFER_EMPTY;
    security_buffer[2].pvBuffer = 0;

    security_buffer[3].cbBuffer = 0;
    security_buffer[3].BufferType = SECBUFFER_EMPTY;
    security_buffer[3].pvBuffer = 0;

    security_status = DecryptMessage(
        &tls->security_context,
        &security_buffer_desc,
        0,
        &qop);

    if (!SEC_SUCCESS(security_status))
    {
        if (security_status == SEC_E_INCOMPLETE_MESSAGE ||
            security_status == SEC_I_RENEGOTIATE ||
            security_status == SEC_E_INCOMPLETE_MESSAGE) {
            return security_status;
        }

        MONGOC_WARNING("QuerySecurityPackageInfoA(): %d", security_status);
        return security_status;
    }

    // Locate data and (optional) extra buffers.
    SecBuffer* sspi_data_buffer = NULL;
    SecBuffer* sspi_extra_buffer = NULL;

    for (int i = 1; i < 4; i++)
    {
        if (sspi_data_buffer == NULL && security_buffer[i].BufferType == SECBUFFER_DATA)
        {
            sspi_data_buffer = &security_buffer[i];
        }
        if (sspi_extra_buffer == NULL && security_buffer[i].BufferType == SECBUFFER_EXTRA)
        {
            sspi_extra_buffer = &security_buffer[i];
        }
    }

    *ppOutput = (char*)sspi_data_buffer->pvBuffer;
    *pcbOutLen = sspi_data_buffer->cbBuffer;

    // If there is more data then SSPI needs, store the rest for the next decryption call
    //
    if (sspi_extra_buffer != NULL && sspi_extra_buffer->cbBuffer > 0) {
        memcpy_s(tls->sspi_read_buffer, tls->sspi_read_buffer_holder_length, sspi_extra_buffer->pvBuffer, sspi_extra_buffer->cbBuffer);
        tls->sspi_read_buffer_length = sspi_extra_buffer->cbBuffer;
    }

    return SEC_E_OK;
}

/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_windows_tls_ssl_fill_read_buffer --
 *
 *       Reads data from network. Also, includes but first tries to use
 *       any extra spill data from the last decryption operation.
 *
 * Returns:
 *       returns -1 on error.
 *
 * Side effects:
 *       May read extra data from sspi in sspi_read_buffer_holder.
 *
 *--------------------------------------------------------------------------
 */
static int 
_mongoc_stream_windows_tls_ssl_fill_read_buffer(mongoc_stream_windows_tls_t* tls, char* buf, int len) {

    int used = 0;

    // Do we have any extra data from our other SSPI stuff? 
    // "read" this into our out buffer first
    if (tls->sspi_read_buffer_length) {
        used = tls->sspi_read_buffer_length;

        // TODO: handle when len is too short for sspi spill over
        memcpy_s(buf, len, tls->sspi_read_buffer, tls->sspi_read_buffer_length);
        buf += tls->sspi_read_buffer_length;
        tls->sspi_read_buffer_length = 0;
    }

    // Read from the network, discounting by our SSPI spill over
    size_t read = len - used;
    int error = _mongoc_stream_windows_tls_ssl_read(tls, buf, &read);
    if (error == -1)
        return -1;

    used += (int)read;

    return used;
}

/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_windows_tls_ssl_fill_read_packet --
 *
 *       Reads, and decrypts one ssl packet worth of data from the network.
 *       Also handles renegotiate, and connect shutdown.
 *
 * Returns:
 *       Returns -1 on error, length read otherwise
 *
 * Side effects:
 *       None
 *
 *--------------------------------------------------------------------------
 */
static int
_mongoc_stream_windows_tls_ssl_fill_read_packet(mongoc_stream_windows_tls_t* tls, 
    char* buf, int len, char** ppOutBuf) {

    SECURITY_STATUS   security_status;
    int used = 0;

    while (true) {
        // Get some data from the network
        int ret = _mongoc_stream_windows_tls_ssl_fill_read_buffer(tls, buf + used, len - used);
        if (ret == -1)
            return ERROR_READ_FAULT;
        used += ret;

        unsigned outLen;

        // Try to decrypt the data
        security_status =_mongoc_stream_windows_tls_ssl_try_decrypt(tls, buf, used, ppOutBuf, &outLen);

        if (security_status == SEC_E_OK) {
            return outLen;
        }
        else if (security_status == SEC_E_INCOMPLETE_MESSAGE) {
            // We need more data to decrypt a single SSL packet.
            continue;
        }
        else if (security_status == SEC_I_RENEGOTIATE) {
            BSON_ASSERT(false);
            break;
        }
        else if (security_status == SEC_I_CONTEXT_EXPIRED) {
            BSON_ASSERT(false);
        }

        return -1;
    }

    // If we have been asked to renegotiate, we should restart the connection basically on either side
    // TODO: figure out how to test this before attempting to support it. 
    if (security_status == SEC_I_RENEGOTIATE) {
        MONGOC_WARNING("Ignoreing server request for renegotiation\n", security_status);
    }

    return -1;
}

/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_tls_read_buffered --
 *
 *       Reads, and decrypts one ssl packet worth of data from the network.
 *       Also handles renegotiate, and connect shutdown.
 *
 * Returns:
 *       returns -1 on error, otherwise returns the length
 *
 * Side effects:
 *       May read and write data it is forced to buffer to packet_read_buffer_holder.
 *
 *--------------------------------------------------------------------------
 */
static int
_mongoc_stream_tls_read_buffered(mongoc_stream_windows_tls_t* tls,
    void* buf,
    int len,
    int *read)
{
    *read = 0;

    // Do we have an empty data buffer? then get some data from the network
    if (tls->packet_read_buffer_length == 0) {
        tls->packet_read_buffer_length = _mongoc_stream_windows_tls_ssl_fill_read_packet(tls, 
            tls->packet_read_buffer_holder, tls->packet_read_buffer_holder_length, &tls->packet_read_buffer);

        if (tls->packet_read_buffer_length == -1)
            return -1;
    }

    // We have some data for them, return it
    if ((unsigned)len >= tls->packet_read_buffer_length) {
        int ret = tls->packet_read_buffer_length;
        memcpy_s(buf, len, tls->packet_read_buffer, tls->packet_read_buffer_length);

        tls->packet_read_buffer = NULL;
        tls->packet_read_buffer_length = 0;
        *read = ret;
        return 0;
    }
    else {
        // We have more data then they need, store some in our internal buffers
        memcpy_s(buf, len, tls->packet_read_buffer, len);

        tls->packet_read_buffer += len;
        tls->packet_read_buffer_length -= len;
        *read = len;
        return 0;
    }
}

/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_windows_tls_readv --
 *
 *       Read from the stream into iov. This function will try to read
 *       all of the bytes or fail. If the number of bytes is not equal
 *       to the number requested, a failure or EOF has occurred.
 *
 * Returns:
 *       -1 on failure, 0 on EOF, otherwise the number of bytes read.
 *
 * Side effects:
 *       iov buffers will be written to.
 *
 *--------------------------------------------------------------------------
 */
static ssize_t
_mongoc_stream_windows_tls_readv (mongoc_stream_t *stream,
                                mongoc_iovec_t  *iov,
                                size_t           iovcnt,
                                size_t           min_bytes,
                                int32_t          timeout_msec)
{
   mongoc_stream_windows_tls_t *tls = (mongoc_stream_windows_tls_t *)stream;
   int error;
   ssize_t ret = 0;
   size_t i;
   int read_ret;
   size_t iov_pos = 0;
   int64_t now;
   int64_t expire = 0;

   BSON_ASSERT (tls);
   BSON_ASSERT (iov);
   BSON_ASSERT (iovcnt);

   tls->timeout_msec = timeout_msec;

   if (timeout_msec >= 0) {
      expire = bson_get_monotonic_time () + (timeout_msec * 1000UL);
   }

   for (i = 0; i < iovcnt; i++) {
      iov_pos = 0;

      while (iov_pos < iov[i].iov_len) {

          error = _mongoc_stream_tls_read_buffered(tls,
                         iov[i].iov_base + iov_pos,
                         (int)(iov[i].iov_len - iov_pos),
                         &read_ret);
         if (0 != error) {
            return -1;
         }

         if (expire) {
            now = bson_get_monotonic_time ();

            if ((expire - now) < 0) {
               if (read_ret == 0) {
                  mongoc_counter_streams_timeout_inc();
                  errno = ETIMEDOUT;
                  return -1;
               }

               tls->timeout_msec = 0;
            } else {
               tls->timeout_msec = (int)((expire - now) / 1000L);
            }
         }

         ret += read_ret;

         if ((size_t)ret >= min_bytes) {
            mongoc_counter_streams_ingress_add(ret);
            return ret;
         }

         iov_pos += read_ret;
      }
   }

   if (ret >= 0) {
      mongoc_counter_streams_ingress_add(ret);
   }

   return ret;
}

/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_windows_tls_setsockopt --
 *
 *       Perform a setsockopt on the underlying stream.
 *
 * Returns:
 *       -1 on failure, otherwise opt specific value.
 *
 * Side effects:
 *       None.
 *
 *--------------------------------------------------------------------------
 */

static int
_mongoc_stream_windows_tls_setsockopt (mongoc_stream_t *stream,
                                     int              level,
                                     int              optname,
                                     void            *optval,
                                     socklen_t        optlen)
{
   mongoc_stream_windows_tls_t *tls = (mongoc_stream_windows_tls_t *)stream;

   BSON_ASSERT (tls);

   return mongoc_stream_setsockopt (tls->base_stream,
                                    level,
                                    optname,
                                    optval,
                                    optlen);
}




/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_windows_tls_try_generate_client_handshake_data --
 *
 *       Generates SSL packets for the client handshake.
 *       Requires multiple calls to complete handshake.
 *
 * Returns:
 *       SECURITY_STATUS
 *
 * Side effects:
 *       Allocates security_handle
 *
 *--------------------------------------------------------------------------
 */
static SECURITY_STATUS
_mongoc_stream_windows_tls_try_generate_client_handshake_data(
    mongoc_stream_windows_tls_t* tls, 
    char       *pIn,
    unsigned       cbIn,
    char       *pOut,
    unsigned      *pcbOut,
    char       *pszTarget)
{
    SECURITY_STATUS   security_status;
    TimeStamp         lifetime;
    SecBufferDesc     output_security_buffer_desc;
    SecBuffer         output_security_buffer;
    SecBufferDesc     input_security_buffer_desc;
    SecBuffer         input_security_buffer[2];
    ULONG             context_attributes;
    static CHAR      lpPackageName[32];

    DWORD sspi_flags = ISC_REQ_SEQUENCE_DETECT |
        ISC_REQ_REPLAY_DETECT |
        ISC_REQ_CONFIDENTIALITY |
        ISC_RET_EXTENDED_ERROR |
        ISC_REQ_STREAM;


    SCHANNEL_CRED credData;

    ZeroMemory(&credData, sizeof(credData));
    credData.dwVersion = SCHANNEL_CRED_VERSION;

    //-------------------------------------------------------
    // Specify the TLS V1.0 (client-side) security protocol.
    // TODO: Raise to TLS 1.2
    credData.grbitEnabledProtocols = SP_PROT_TLS1_0_CLIENT;

    if (tls->weak_cert_validation) {
        // Disable server certificate validation, Windows normally calls WinVerifyTrust
//        credData.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;
    }
    credData.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;
    credData.dwFlags |= ISC_REQ_USE_SUPPLIED_CREDS;
    credData.dwFlags |= SCH_USE_STRONG_CRYPTO;

    if (tls->certificate != NULL) {
        credData.cCreds = 1;
        credData.paCred = &tls->certificate;
    }

    if (NULL == pIn)
    {
        strcpy_s(lpPackageName, 32 * sizeof(CHAR), "SChannel");
        security_status = AcquireCredentialsHandleA(
            NULL,
            lpPackageName,
            SECPKG_CRED_OUTBOUND,
            NULL,
            &credData,
            NULL,
            NULL,
            &tls->credential_handle,
            &lifetime);

        if (!(SEC_SUCCESS(security_status)))
        {
            BSON_ASSERT(false);
        }
    }

    output_security_buffer_desc.ulVersion = 0;
    output_security_buffer_desc.cBuffers = 1;
    output_security_buffer_desc.pBuffers = &output_security_buffer;

    output_security_buffer.cbBuffer = *pcbOut;
    output_security_buffer.BufferType = SECBUFFER_TOKEN;
    output_security_buffer.pvBuffer = pOut;

    if (pIn)
    {
        input_security_buffer_desc.ulVersion = 0;
        input_security_buffer_desc.cBuffers = 2;
        input_security_buffer_desc.pBuffers = &input_security_buffer[0];

        input_security_buffer[0].cbBuffer = cbIn;
        input_security_buffer[0].BufferType = SECBUFFER_TOKEN;
        input_security_buffer[0].pvBuffer = pIn;

        input_security_buffer[1].cbBuffer = cbIn;
        input_security_buffer[1].BufferType = SECBUFFER_EMPTY;
        input_security_buffer[1].pvBuffer = pIn;

        security_status = InitializeSecurityContextA(
            &tls->credential_handle,
            &tls->security_context,
            pszTarget,
            sspi_flags,
            0,
            0,
            &input_security_buffer_desc,
            0,
            NULL,
            &output_security_buffer_desc,
            &context_attributes,
            &lifetime);
    }
    else
    {
        security_status = InitializeSecurityContextA(
            &tls->credential_handle,
            NULL,
            pszTarget,
            sspi_flags,
            0,
            0,
            NULL,
            0,
            &tls->security_context,
            &output_security_buffer_desc,
            &context_attributes,
            &lifetime);
    }

    if (!SEC_SUCCESS(security_status))
    {
        if (security_status == SEC_E_INCOMPLETE_MESSAGE) {
            return security_status;
        }

        if (security_status == SEC_E_CERT_EXPIRED || security_status == SEC_E_UNTRUSTED_ROOT) {
            tls->certificate_valid = 1;
            return SEC_E_OK;
        }

        BSON_ASSERT(false);

        return security_status;
    }

    // If this is the second message or later in the exchange
    if (pIn) {
        // Locate (optional) extra buffers.
        SecBuffer* sspi_extra_buffer = NULL;

        for (int i = 0; i < 2; i++)
        {
            if (sspi_extra_buffer == NULL && input_security_buffer[i].BufferType == SECBUFFER_EXTRA)
            {
                sspi_extra_buffer = &input_security_buffer[i];
            }
        }

        // If there is more data then SSPI needs, store the rest for the next decryption call
        //
        if (sspi_extra_buffer != NULL && sspi_extra_buffer->cbBuffer > 0) {
            memcpy_s(tls->sspi_read_buffer, tls->sspi_read_buffer_holder_length, sspi_extra_buffer->pvBuffer, sspi_extra_buffer->cbBuffer);
            tls->sspi_read_buffer_length = sspi_extra_buffer->cbBuffer;
        }
    }

    if ((SEC_I_COMPLETE_NEEDED == security_status)
        || (SEC_I_COMPLETE_AND_CONTINUE == security_status))
    {
        security_status = CompleteAuthToken(&tls->security_context, &output_security_buffer_desc);
        if (!SEC_SUCCESS(security_status))
        {
            MONGOC_WARNING("CompleteAuthToken failed: 0x%08x\n", security_status);
            return security_status;
        }
    }

    *pcbOut = output_security_buffer.cbBuffer;

    printf("Token buffer generated (%lu bytes):\n", output_security_buffer.cbBuffer);
    //PrintHexDump(output_security_buffer.cbBuffer, (PBYTE)output_security_buffer.pvBuffer);
    return security_status;
}

/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_windows_tls_generate_client_handshake_data --
 *
 *       After the Client sends ClientHello, TLS packets may be
 *       fragmented across socket reads, and this method handles this.
 *
 * Returns:
 *       SECURITY_STATUS
 *
 * Side effects:
 *       Makes progress in client handshake.
 *
 *--------------------------------------------------------------------------
 */
static SECURITY_STATUS
_mongoc_stream_windows_tls_generate_client_handshake_data(
    mongoc_stream_windows_tls_t* tls,
    char *pOut,
    unsigned *pcbOut,
    char* pszTarget)
{
    SECURITY_STATUS   security_status;
    char* extra_read_buffer = tls->packet_read_buffer_holder;
    unsigned extra_read_buffer_length = tls->packet_read_buffer_holder_length;

    int used = 0;

    while (true) {
        // get more data
        int ret = _mongoc_stream_windows_tls_ssl_fill_read_buffer(tls, extra_read_buffer + used, extra_read_buffer_length - used);
        if (ret == -1)
            return ERROR_READ_FAULT;

        used += ret;

        security_status = _mongoc_stream_windows_tls_try_generate_client_handshake_data(tls, extra_read_buffer, used, pOut, pcbOut, pszTarget);

        if (security_status != SEC_E_INCOMPLETE_MESSAGE) {
            return security_status;
        }
    }
}

/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_windows_tls_do_client_handshake --
 *
 *       Do TLS client handshake
 *
 * Returns:
 *       false on failure
 *
 * Side effects:
 *       Initializes credential_context, and security_context.
 *
 *--------------------------------------------------------------------------
 */
static bool
_mongoc_stream_windows_tls_do_client_handshake(mongoc_stream_windows_tls_t *tls)
{
    SECURITY_STATUS   security_status;

    char* pOutBuf = malloc(tls->ssl_max_packet_size);
    unsigned cbOut = tls->ssl_max_packet_size;

    security_status = _mongoc_stream_windows_tls_try_generate_client_handshake_data(
        tls,
        NULL,
        0,
        pOutBuf,
        &cbOut,
        tls->server_target_name
        );
    if (!SEC_SUCCESS(security_status)) {
        BSON_ASSERT(false);
        return false;
    }

    // Send the first SSL Handshake packet
    _mongoc_stream_windows_tls_ssl_write(tls, pOutBuf, cbOut);

    do {
        // Keep reading, and then send messages until SSPI says we are done
        cbOut = tls->ssl_max_packet_size;
        security_status = _mongoc_stream_windows_tls_generate_client_handshake_data(tls, pOutBuf, &cbOut, tls->server_target_name);

        // If we are done with the SSL handshake, exit the loop
        if(SEC_ISDONE(security_status))
            break;

        if (!SEC_SUCCESS(security_status)) {
            BSON_ASSERT(false);
            return false;
        }

        // send the next packet
        _mongoc_stream_windows_tls_ssl_write(tls, pOutBuf, cbOut);

    } while (!SEC_ISDONE(security_status));

    // Server is demanding we 
    if (security_status == SEC_I_INCOMPLETE_CREDENTIALS) {
        MONGOC_WARNING("Server asked for a clienter certificate which was not provided (): %d", security_status);
        return false;
    }

    return true;
}

/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_windows_tls_server_try_accept_handshake --
 *
 *       Generates SSL packets for the server handshake.
 *       Requires multiple calls to complete handshake.
 *
 * Returns:
 *       SECURITY_STATUS
 *
 * Side effects:
 *       Allocates security_handle
 *
 *--------------------------------------------------------------------------
 */
static SECURITY_STATUS 
_mongoc_stream_windows_tls_server_try_accept_handshake(
    mongoc_stream_windows_tls_t *tls,
    char *pIn,
    int cbIn,
    char *pOut,
    DWORD *pcbOut,
    bool fNewConversation) {
    SECURITY_STATUS   security_status;
    TimeStamp         lifetime;
    SecBufferDesc     output_security_buffer_desc;
    SecBuffer         output_security_buffer;
    SecBufferDesc     input_security_buffer_desc;
    SecBuffer         input_security_buffer[2];
    ULONG             attributes = 0;

    //----------------------------------------------------------------
    //  Prepare output buffers.

    output_security_buffer_desc.ulVersion = SECBUFFER_VERSION;
    output_security_buffer_desc.cBuffers = 1;
    output_security_buffer_desc.pBuffers = &output_security_buffer;

    output_security_buffer.cbBuffer = *pcbOut;
    output_security_buffer.BufferType = SECBUFFER_TOKEN;
    output_security_buffer.pvBuffer = pOut;

    //----------------------------------------------------------------
    //  Prepare input buffers.

    input_security_buffer_desc.ulVersion = SECBUFFER_VERSION;
    input_security_buffer_desc.cBuffers = 2;
    input_security_buffer_desc.pBuffers = input_security_buffer;

    input_security_buffer[0].cbBuffer = cbIn;
    input_security_buffer[0].BufferType = SECBUFFER_TOKEN;
    input_security_buffer[0].pvBuffer = pIn;

    input_security_buffer[1].cbBuffer = 0;
    input_security_buffer[1].BufferType = SECBUFFER_EMPTY;
    input_security_buffer[1].pvBuffer = NULL;


    printf("Token buffer received (%lu bytes):\n", input_security_buffer[0].cbBuffer);
    //PrintHexDump(input_security_buffer[0].cbBuffer, (PBYTE)input_security_buffer[0].pvBuffer);

    attributes = ASC_REQ_SEQUENCE_DETECT |
        ASC_REQ_REPLAY_DETECT |
        ASC_REQ_CONFIDENTIALITY |
        ASC_REQ_EXTENDED_ERROR |
        ASC_REQ_STREAM;

    security_status = AcceptSecurityContext(
        &tls->credential_handle,
        fNewConversation ? NULL : &tls->security_context,
        &input_security_buffer_desc,
        attributes,
        0,
        &tls->security_context,
        &output_security_buffer_desc,
        &attributes,
        &lifetime);

    if (!SEC_SUCCESS(security_status))
    {
        if (security_status == SEC_E_INCOMPLETE_MESSAGE) {
            return security_status;
        }

        MONGOC_WARNING("AcceptSecurityContext failed: 0x%08x\n", security_status);
        BSON_ASSERT(false);
        return security_status;
    }

    // Locate (optional) extra buffers.
    SecBuffer* sspi_extra_buffer = NULL;

    for (int i = 0; i < 2; i++)
    {
        if (sspi_extra_buffer == NULL && input_security_buffer[i].BufferType == SECBUFFER_EXTRA)
        {
            sspi_extra_buffer = &input_security_buffer[i];
        }
    }

    // If there is more data then SSPI needs, store the rest for the next decryption call
    //
    if (sspi_extra_buffer != NULL && sspi_extra_buffer->cbBuffer > 0) {
        memcpy_s(tls->sspi_read_buffer, tls->sspi_read_buffer_holder_length, sspi_extra_buffer->pvBuffer, sspi_extra_buffer->cbBuffer);
        tls->sspi_read_buffer_length = sspi_extra_buffer->cbBuffer;
    }

    if ((SEC_I_COMPLETE_NEEDED == security_status)
        || (SEC_I_COMPLETE_AND_CONTINUE == security_status))
    {
        security_status = CompleteAuthToken(&tls->security_context, &output_security_buffer_desc);
        if (!SEC_SUCCESS(security_status))
        {
            MONGOC_WARNING("CompleteAuthToken failed: 0x%08x\n", security_status);
            BSON_ASSERT(false);
            return security_status;
        }
    }

    *pcbOut = output_security_buffer.cbBuffer;

    printf("Token buffer generated (%lu bytes):\n",
        output_security_buffer.cbBuffer);

    return security_status;
}

/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_windows_tls_server_accept_handshake --
 *
 *       After the Client sends ClientHello to the server, TLS packets may be
 *       fragmented across socket reads, and this method handles this.
 *
 * Returns:
 *       SECURITY_STATUS
 *
 * Side effects:
 *       Makes progress in client handshake.
 *
 *--------------------------------------------------------------------------
 */
static SECURITY_STATUS
_mongoc_stream_windows_tls_server_accept_handshake(
    mongoc_stream_windows_tls_t *tls,
    char *pOut,
    DWORD *pcbOut,
    bool fNewConversation)
{
    SECURITY_STATUS   security_status;
    char* extra_read_buffer = tls->packet_read_buffer_holder;
    unsigned extra_read_buffer_length = tls->packet_read_buffer_holder_length;

    int used = 0;

    while (true) {
        // get more data
        int ret = _mongoc_stream_windows_tls_ssl_fill_read_buffer(tls, extra_read_buffer + used, extra_read_buffer_length - used);
        if (ret == -1)
            return ERROR_READ_FAULT;

        used += ret;
        security_status = _mongoc_stream_windows_tls_server_try_accept_handshake(tls, extra_read_buffer, used, pOut, pcbOut, fNewConversation);

        if (security_status != SEC_E_INCOMPLETE_MESSAGE) {
            return security_status;
        }

    }
}

/*
*--------------------------------------------------------------------------
*
* _mongoc_stream_windows_tls_do_server_handshake --
*
*       Do TLS server handshake
*
* Returns:
*       false on failure
*
* Side effects:
*       Initializes credential_context, and security_context.
*
*--------------------------------------------------------------------------
*/
static SECURITY_STATUS 
_mongoc_stream_windows_tls_do_server_handshake(mongoc_stream_windows_tls_t *tls,
    const char* initial, int len) {


    // Start handshake with Accept
    // 1. send packet based on output, wait for response
    // 2. finish exchange

    SECURITY_STATUS   security_status = 0;
    DWORD cbOut = 0;
    bool              done = false;
    TimeStamp         lifetime ;
    bool              fNewConversation;
    SCHANNEL_CRED credData;

    ZeroMemory(&credData, sizeof(credData));
    credData.dwVersion = SCHANNEL_CRED_VERSION;
    credData.grbitEnabledProtocols = SP_PROT_TLS1_0_SERVER;
    credData.dwFlags = SCH_USE_STRONG_CRYPTO;

    fNewConversation = true;

    credData.cCreds = 1;
    credData.paCred = &tls->certificate;

    security_status = AcquireCredentialsHandleA(
        NULL,
        "SChannel",
        SECPKG_CRED_INBOUND,
        NULL,
        &credData,
        NULL,
        NULL,
        &tls->credential_handle,
        &lifetime);

    if (!SEC_SUCCESS(security_status))
    {
        MONGOC_WARNING("AcquireCredentialsHandle failed: 0x%08x\n", security_status);
        BSON_ASSERT(false);
        return security_status;
    }

    // capture the intial accept buffer data
    if (len > 0) {
        tls->sspi_read_buffer = tls->sspi_read_buffer_holder;
        tls->sspi_read_buffer_length = len;
        memcpy_s(tls->sspi_read_buffer, tls->sspi_read_buffer_length, initial, len);
    }
    
    char* outBuf = malloc(tls->ssl_max_packet_size);
    cbOut = tls->ssl_max_packet_size;

    do {
        // Read packet until not runt message
        security_status = _mongoc_stream_windows_tls_server_accept_handshake(tls, outBuf, &cbOut, fNewConversation);
        // Process packet
        fNewConversation = false;
        // Either send/retry, or done
        _mongoc_stream_windows_tls_ssl_write(tls, outBuf, cbOut);

        // If we are done with the SSL handshake, exit the loop
        if (SEC_ISDONE(security_status))
            break;

        if (!SEC_SUCCESS(security_status)) {
            BSON_ASSERT(false);
            return false;
        }

    } while (!SEC_ISDONE(security_status));

    return SEC_E_OK;
}


/*
*--------------------------------------------------------------------------
*
* mongoc_stream_windows_tls_do_handshake:
*
*        Force an ssl handshake.
*        This will happen on the first read or write otherwise.
*
* Returns:
*
*        true for a successful handshake, false on error.
*
*--------------------------------------------------------------------------
*/

bool
mongoc_stream_windows_tls_do_handshake (mongoc_stream_t *stream,
                                      int32_t          timeout_msec)
{
   mongoc_stream_windows_tls_t *tls = (mongoc_stream_windows_tls_t *)stream;

   BSON_ASSERT (tls);

   tls->timeout_msec = timeout_msec;

   bool ret = false;
   if (tls->client)
       ret = _mongoc_stream_windows_tls_do_client_handshake(tls);
   else
        ret = SEC_SUCCESS(_mongoc_stream_windows_tls_do_server_handshake(tls, NULL, 0));
 
   if (ret == false)
       return false;

   SecPkgContext_StreamSizes SecPkgContextStreamSizes;

   SECURITY_STATUS security_status = QueryContextAttributes(
       &tls->security_context,
       SECPKG_ATTR_STREAM_SIZES,
       &SecPkgContextStreamSizes);

   if (!SEC_SUCCESS(security_status))
   {
       MONGOC_WARNING("QueryContextAttributes failed: 0x%08x\n", security_status);
       BSON_ASSERT(false);
       return false;
   }

   tls->security_trailer_count = SecPkgContextStreamSizes.cbTrailer;
   tls->security_header_count = SecPkgContextStreamSizes.cbHeader;

   return true;
}


/*
 *--------------------------------------------------------------------------
 *
 * mongoc_stream_windows_tls_check_cert:
 *
 *      Check the certificate returned by the other party.
 *
 *--------------------------------------------------------------------------
 */
bool
mongoc_stream_windows_tls_check_cert (mongoc_stream_t *stream,
                                    const char      *host)
{
    mongoc_stream_windows_tls_t *tls = (mongoc_stream_windows_tls_t *)stream;

    BSON_ASSERT(tls);
    BSON_ASSERT(host);


    /* if we don't want validation, skip */
    if (tls->weak_cert_validation) {
        return true;
    }
    
    /* Did SSPI complain about the certificate during client handshake? */
    if ( tls->certificate_valid ) {
        return false;
    }

    return true;
#if 0
   mongoc_stream_windows_tls_t *tls = (mongoc_stream_windows_tls_t *)stream;
   SECURITY_STATUS   security_status = 0;
   PCCERT_CONTEXT remote_cert;

   BSON_ASSERT (tls);
   BSON_ASSERT (host);

   /* if we don't want validation, skip */
   if (tls->weak_cert_validation) {
      return true;
   }

   /* get our certificate chain from the remote side*/
   security_status = QueryContextAttributes(
       &tls->security_context,
       SECPKG_ATTR_REMOTE_CERT_CONTEXT,
       remote_cert);

   if (!SEC_SUCCESS(security_status))
   {
       fprintf(stderr, "QueryContextAttributes failed: 0x%08x\n", security_status);
       BSON_ASSERT(false);
   }
   
https://msdn.microsoft.com/en-us/library/windows/desktop/aa378740%28v=vs.85%29.aspx
#endif
}

/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_windows_tls_get_base_stream --
 *
 *       Return the underlying stream.
 *
 *--------------------------------------------------------------------------
 */

static mongoc_stream_t *
_mongoc_stream_windows_tls_get_base_stream (mongoc_stream_t *stream)
{
   return ((mongoc_stream_windows_tls_t *)stream)->base_stream;
}

/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_windows_tls_check_closed --
 *
 *       Check if the underlying stream is closed.
 *
 *--------------------------------------------------------------------------
 */

static bool
_mongoc_stream_windows_tls_check_closed (mongoc_stream_t *stream) /* IN */
{
   mongoc_stream_windows_tls_t *tls = (mongoc_stream_windows_tls_t *)stream;
   bson_return_val_if_fail(stream, -1);
   return mongoc_stream_check_closed (tls->base_stream);
}

/*
 *--------------------------------------------------------------------------
 *
 * mongoc_stream_windows_tls_new --
 *
 *       Creates a new mongoc_stream_windows_tls_t to communicate with a remote
 *       server using a TLS stream.
 *
 *       @base_stream should be a stream that will become owned by the
 *       resulting tls stream. It will be used for raw I/O.
 *
 *       @trust_store_dir should be a path to the SSL cert db to use for
 *       BSON_ASSERTing trust of the remote server.
 *
 * Returns:
 *       NULL on failure, otherwise a mongoc_stream_t.
 *
 * Side effects:
 *       None.
 *
 *--------------------------------------------------------------------------
 */

mongoc_stream_t *
mongoc_stream_windows_tls_new (mongoc_stream_t  *base_stream,
                             mongoc_ssl_opt_t *opt,
                             int               client)
{
   mongoc_stream_windows_tls_t *tls;

   BSON_ASSERT(base_stream);
   BSON_ASSERT(opt);

   tls = bson_malloc0 (sizeof *tls);
   tls->base_stream = base_stream;

   tls->parent.type = MONGOC_STREAM_WINDOWS_TLS; // yes?
   tls->parent.destroy = _mongoc_stream_windows_tls_destroy;
   tls->parent.close = _mongoc_stream_windows_tls_close;
   tls->parent.flush = _mongoc_stream_windows_tls_flush;
   tls->parent.writev = _mongoc_stream_windows_tls_writev;
   tls->parent.readv = _mongoc_stream_windows_tls_readv;

   tls->parent.setsockopt = _mongoc_stream_windows_tls_setsockopt;
   tls->parent.get_base_stream = _mongoc_stream_windows_tls_get_base_stream;
   tls->parent.check_closed = _mongoc_stream_windows_tls_check_closed;
   tls->weak_cert_validation = opt->weak_cert_validation;
   tls->timeout_msec = -1;


   memset(&tls->credential_handle, 0, sizeof(CredHandle));
   memset(&tls->security_context, 0, sizeof(SecHandle));

   tls->ssl_max_packet_size = 0;

   tls->server_target_name = 0; // "mark";

   tls->certificate_valid = 0;
   tls->security_trailer_count = 0;
   tls->security_header_count = 0;

   tls->packet_read_buffer_holder = 0;
   tls->packet_read_buffer_holder_length = 0;
   tls->packet_read_buffer = 0;
   tls->packet_read_buffer_length = 0;

   tls->sspi_read_buffer_holder = 0;
   tls->sspi_read_buffer_holder_length = 0;
   tls->sspi_read_buffer_length = 0;
   tls->sspi_read_buffer = 0;
   tls->client = client;
   tls->certificate = opt->certificate;

   /* Get the maximum message size */
   PSecPkgInfoA pkgInfo;

   SECURITY_STATUS security_status = QuerySecurityPackageInfoA(
       "SChannel",
       &pkgInfo);

   if (!SEC_SUCCESS(security_status))
   {
       MONGOC_WARNING("QuerySecurityPackageInfoA(): %d", security_status);
       return NULL;
   }

   tls->ssl_max_packet_size = pkgInfo->cbMaxToken;

   FreeContextBuffer(pkgInfo);

   tls->packet_read_buffer_holder = malloc(tls->ssl_max_packet_size);
   tls->packet_read_buffer_holder_length = tls->ssl_max_packet_size;

   // extra stuff from sspi buffering, ie, sspi spill over area
   tls->sspi_read_buffer_holder = malloc(tls->ssl_max_packet_size);
   tls->sspi_read_buffer_holder_length = tls->ssl_max_packet_size;
   tls->sspi_read_buffer = tls->sspi_read_buffer_holder;

   mongoc_counter_streams_active_inc();

   return (mongoc_stream_t *)tls;
}

#endif /* MONGOC_WINDOWS_NATIVE_TLS */
#endif /* MONGOC_ENABLE_SSL */
