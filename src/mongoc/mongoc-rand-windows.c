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
#include <ntstatus.h>
#define WIN32_NO_STATUS

#include "mongoc-rand-windows.h"
#include "mongoc-rand-windows-private.h"



#include "mongoc.h"

#include <bcrypt.h>

/*
 *-------------------------------------------------------------------------
 *
 * _mongoc_rand_windows_bytes --
 *
 *       Uses CNG's default random number generator to fill
 *       @buf with @num cryptographically secure random bytes.
 *
 * Returns:
 *       1 on success, 0 on failure, with error in errno system variable.
 *
 *-------------------------------------------------------------------------
 */

int _mongoc_rand_windows_bytes(uint8_t * buf, int num) {
    static int initialized = 0;
    static BCRYPT_ALG_HANDLE hAlgorithm;
    NTSTATUS status = 0;

    if (initialized == 0) {
        status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_RNG_ALGORITHM, NULL, 0);
        if (STATUS_SUCCESS != status) {
            MONGOC_WARNING("BCryptOpenAlgorithmProvider(): %d", status);
        }
        initialized = 1;
    }

    status = BCryptGenRandom(hAlgorithm, buf, num, 0);
    if (STATUS_SUCCESS == status) {
      return 1;
   }

    MONGOC_WARNING("BCryptGenRandom(): %d", status);

   return 0;
}

/*
 *-------------------------------------------------------------------------
 *
 * _mongoc_pseudo_rand_windows_bytes --
 *
 *       With CNG, behaves like _mongoc_rand_bytes.
 *
 * Returns:
 *       1 on success, 0 on failure, with error in errno system variable.
 *
 *-------------------------------------------------------------------------
 */

int _mongoc_pseudo_rand_windows_bytes(uint8_t * buf, int num) {
   return _mongoc_rand_windows_bytes(buf, num);
}

void mongoc_rand_windows_seed(const void* buf, int num) {
    /* N/A - OS Does not need entropy seed */
}

void mongoc_rand_windows_add(const void* buf, int num, double entropy) {
    /* N/A - OS Does not need entropy seed */
}

int mongoc_rand_windows_status(void) {
    return 1;
}

#endif /* MONGOC_WINDOWS_NATIVE_TLS */
#endif /* MONGOC_ENABLE_SSL */
