/* platform_hacks.h */

/* all platform-specific ifdefs should go here */

#ifndef _PLATFORM_HACKS_H_
#define _PLATFORM_HACKS_H_

#ifdef __GNUC__
#define MONGO_INLINE static __inline__
#else
#define MONGO_INLINE static
#endif


#ifdef _MSC_VER
typedef __int64 int64_t;
#else
#include <stdint.h>
#endif

#ifdef MONGO_BIG_ENDIAN
MONGO_INLINE void bson_swap_endian64(void* outp, const void* inp){
    const char *in = inp;
    char *out = outp;

    out[0] = in[7];
    out[1] = in[6];
    out[2] = in[5];
    out[3] = in[4];
    out[4] = in[3];
    out[5] = in[2];
    out[6] = in[1];
    out[7] = in[0];

}
MONGO_INLINE void bson_swap_endian32(void* outp, const void* inp){
    const char *in = inp;
    char *out = outp;

    out[0] = in[3];
    out[1] = in[2];
    out[2] = in[1];
    out[3] = in[0];
}
#else
#define bson_swap_endian64(out, in) ( memcpy(out, in, 8) )
#define bson_swap_endian32(out, in) ( memcpy(out, in, 4) )
#endif

#endif
