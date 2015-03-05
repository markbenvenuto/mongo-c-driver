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

#include <stdio.h>


/*
 *-------------------------------------------------------------------------
 *
 * _mongoc_ssl_windows_extract_subject --
 *
 *       Extract human-readable subject information from the certificate
 *       in @filename.
 *
 *       Depending on the OS version, we try several different ways of
 *       accessing this data, and the string returned may be a summary
 *       of the certificate, a long description of the certificate, or
 *       just the common name from the cert.
 *
 * Returns:
 *       Certificate data, or NULL if filename could not be processed.
 *
 *-------------------------------------------------------------------------
 */

char *
_mongoc_ssl_windows_extract_subject (const char *filename)
{
    // TODO - get subject name, desc, common name, etc
    // 
    // char buf[123];
    // NOte: Does not return prefix a of "CN = "
    // DWORD ret1 = CertGetNameStringA(opt->certificate, CERT_NAME_ATTR_TYPE, 0, szOID_COMMON_NAME, &buf[0], 123);
    // DWORD ret1 = CertGetNameStringA(opt->certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, &buf[0], 123);
    // 

    return "CN=markcb";
}

/*
 *-------------------------------------------------------------------------
 *
 * _mongoc_ssl_windows_init --
 *
 *       No-op.
 *
 *-------------------------------------------------------------------------
 */

void
_mongoc_ssl_windows_init (void)
{
   /* no-op */
   // TODO why is this a no-op?
}

/*
 *-------------------------------------------------------------------------
 *
 * _mongoc_ssl_windows_cleanup --
 *
 *       No-op.
 *
 *-------------------------------------------------------------------------
 */

void
_mongoc_ssl_windows_cleanup (void)
{
   /* no-op */
   // TODO why is this a no-op?
}


#endif /* MONGOC_WINDOWS_NATIVE_TLS */
#endif /* MONGOC_ENABLE_SSL */
