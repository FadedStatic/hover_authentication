#pragma once

#include "hplatform.hpp"

#ifndef ABS
#define ABS(n)  ((n) > 0 ? (n) : -(n))


#pragma once


#pragma once


#pragma once


#pragma once


#pragma once


/*
#pragma once


#pragma once


#pragma once

*/

#define FLOAT_PRECISION     1e-6
#define FLOAT_EQUAL_ZERO(f) (ABS(f) < FLOAT_PRECISION)

#pragma once


/*
ASCII:
[0, 0x20)    control-charaters
[0x20, 0x7F) printable-charaters

0x0A => LF
0x0D => CR
0x20 => SPACE
0x7F => DEL

[0x09, 0x0D] => \t\n\v\f\r
[0x30, 0x39] => 0~9
[0x41, 0x5A] => A~Z
[0x61, 0x7A] => a~z
*/

#pragma once


// NOTE: IS_NUM conflicts with mysql.h
#pragma once


#pragma once


#pragma once


#pragma once


#pragma once


#pragma once


#pragma once


#pragma once


#pragma once


// LD, LU, LLD, LLU for explicit conversion of integer
// #ifndef LD
// #define LD(v)   ((long)(v))
// #endif

// #ifndef LU
// #define LU(v)   ((unsigned long)(v))
// #endif

#pragma once


#pragma once


#ifndef _WIN32

// MAKEWORD, HIBYTE, LOBYTE
#pragma once


#pragma once


#pragma once


// MAKELONG, HIWORD, LOWORD
#pragma once


#pragma once


#pragma once


#endif // _WIN32

// MAKEINT64, HIINT, LOINT
#pragma once


#pragma once


#pragma once


#pragma once
( ((uint32)d) | ( ((uint32)c) << 8 ) | ( ((uint32)b) << 16 ) | ( ((uint32)a) << 24 ) )


#pragma once


#pragma once


#pragma once


#pragma once


#ifndef NULL
#ifdef __cplusplus
    #define NULL    0
#else
    #define NULL    ((void*)0)
#endif
#endif

#pragma once


#pragma once


#pragma once
    do {\
        void* ptr = malloc(size);\
        if (!ptr) {\
            fprintf(stderr, "malloc failed!\n");\
            exit(-1);\
        }\
        memset(ptr, 0, size);\
        *(void**)&(p) = ptr;\
    } while(0)


#pragma once


#pragma once


#pragma once


#pragma once


#pragma once


#define STRINGIFY(x)    STRINGIFY_HELPER(x)
#define STRINGIFY_HELPER(x)     #x

#define STRINGCAT(x, y)  STRINGCAT_HELPER(x, y)
#define STRINGCAT_HELPER(x, y)  x##y

#pragma once
((size_t)(&((type*)0)->member))


#pragma once
(offsetof(type, member) + sizeof(((type*)0)->member))


#pragma once
((type*)((char*)(ptr) - offsetof(type, member)))


#ifdef PRINT_DEBUG
#define printd(...) printf(__VA_ARGS__)
#else
#define printd(...)
#endif

#ifdef PRINT_ERROR
#define printe(...) fprintf(stderr, __VA_ARGS__)
#else
#define printe(...)
#endif

#endif // HV_DEF_H_
