#pragma once


/*******************************************************************************
*   Ledger Nano S - Secure firmware
*   (c) 2019 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#ifndef OS_H
#define OS_H

#define TARGET_NANOSP
#define USB_SEGMENT_SIZE 64

// #include "os_hal.h"

// -----------------------------------------------------------------------
// - BASIC MATHS
// -----------------------------------------------------------------------
#define U2(hi, lo) ((((hi)&0xFFu) << 8) | ((lo)&0xFFu))
#define U4(hi3, hi2, lo1, lo0)                                                 \
  ((((hi3)&0xFFu) << 24) | (((hi2)&0xFFu) << 16) | (((lo1)&0xFFu) << 8) |      \
   ((lo0)&0xFFu))
#define U2BE(buf, off) ((((buf)[off] & 0xFFu) << 8) | ((buf)[off + 1] & 0xFFu))
#define U2LE(buf, off) ((((buf)[off + 1] & 0xFFu) << 8) | ((buf)[off] & 0xFFu))
#define U4BE(buf, off) ((U2BE(buf, off) << 16) | (U2BE(buf, off + 2) & 0xFFFFu))
#define U4LE(buf, off) ((U2LE(buf, off + 2) << 16) | (U2LE(buf, off) & 0xFFFFu))
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define IS_POW2(x) (((x) & ((x)-1)) == 0)
#define UPPER_ALIGN(adr, align, type)                                          \
  (type)((type)((type)(adr) +                                                  \
                (type)((type)((type)MAX((type)(align), (type)1UL)) -           \
                       (type)1UL)) &                                           \
         (type)(~(type)((type)((type)MAX(((type)align), (type)1UL)) -          \
                        (type)1UL)))
#define LOWER_ALIGN(adr, align, type)                                          \
  ((type)(adr) &                                                               \
   (type)((type) ~(type)(((type)MAX((type)(align), (type)1UL)) - (type)1UL)))
#define U4BE_ENCODE(buf, off, value)                                           \
  {                                                                            \
    (buf)[(off) + 0] = ((value) >> 24) & 0xFF;                                 \
    (buf)[(off) + 1] = ((value) >> 16) & 0xFF;                                 \
    (buf)[(off) + 2] = ((value) >> 8) & 0xFF;                                  \
    (buf)[(off) + 3] = ((value)) & 0xFF;                                       \
  }
#define U4LE_ENCODE(buf, off, value)                                           \
  {                                                                            \
    (buf)[(off) + 3] = ((value) >> 24) & 0xFF;                                 \
    (buf)[(off) + 2] = ((value) >> 16) & 0xFF;                                 \
    (buf)[(off) + 1] = ((value) >> 8) & 0xFF;                                  \
    (buf)[(off) + 0] = ((value)) & 0xFF;                                       \
  }
#define U2BE_ENCODE(buf, off, value)                                           \
  {                                                                            \
    (buf)[(off) + 0] = ((value) >> 8) & 0xFF;                                  \
    (buf)[(off) + 1] = ((value)) & 0xFF;                                       \
  }
#define U2LE_ENCODE(buf, off, value)                                           \
  {                                                                            \
    (buf)[(off) + 1] = ((value) >> 8) & 0xFF;                                  \
    (buf)[(off) + 0] = ((value)) & 0xFF;                                       \
  }

/**
 * Helper to perform compilation time assertions
 */
#if !defined(SYSCALL_GENERATE) &&                                              \
    (defined(__clang__) ||                                                     \
     (__GNUC__ > 4 || (__GNUC__ == 4 && (__GNUC_MINOR__ >= 6))))
#define CCASSERT(id, predicate) _Static_assert(predicate, #id)
#else
#define CCASSERT(id, predicate) __x_CCASSERT_LINE(predicate, id, __LINE__)
#define __x_CCASSERT_LINE(predicate, file, line)                               \
  __xx_CCASSERT_LINE(predicate, file, line)
#define __xx_CCASSERT_LINE(predicate, file, line)                              \
  typedef char CCASSERT_##file##_line_##line[((predicate) ? 1 : -1)]
#endif

#ifdef macro_offsetof
#define offsetof(type, field) ((unsigned int)&(((type *)NULL)->field))
#endif

/**
 * Quality development guidelines:
 * - NO header defined per arch and included in common if needed per arch,
 * define below
 * - exception model
 * - G_ prefix for RAM vars
 * - N_ prefix for NVRAM vars (mandatory for x86 link script to operate
 * correctly)
 * - C_ prefix for ROM   constants (mandatory for x86 link script to operate
 * correctly)
 * - extensive use of * and arch specific C modifier
 */

// error type definition
typedef unsigned short exception_t;


//#define macro_offsetof // already defined in stddef.h
#define OS_LITTLE_ENDIAN
#define NATIVE_64BITS
#define NVM_ERASED_WORD_VALUE 0xFFFFFFFFUL

#define WIDE // const // don't !!
#define WIDE_AS_INT unsigned long int
#define REENTRANT(x) x //

#include <setjmp.h>
// GCC/LLVM declare way too big jmp context, reduce them to what is used on CM0+
typedef struct try_context_s try_context_t;

struct try_context_s {
  // jmp context to backup (in increasing order address: r4, r5, r6, r7, r8, r9,
  // r10, r11, SP, setjmpcallPC)
  jmp_buf jmp_buf;

  // link to the previous jmp_buf context
  try_context_t *previous;

  // current exception
  exception_t ex;
};

// borrowed from setjmp.h

#ifdef __GNUC__
void longjmp(jmp_buf __jmpb, int __retval) __attribute__((__noreturn__));
#else
void longjmp(jmp_buf __jmpb, int __retval);
#endif
int setjmp(jmp_buf __jmpb);

#include "stddef.h"
#include "stdint.h"
// #include <core_sc000.h>

#define UNUSED(x) (void)x

#endif
#if defined(ST33)

#define NVM_ERASED_WORD_VALUE 0xFFFFFFFF

//#define macro_offsetof // already defined in stddef.h
#define OS_LITTLE_ENDIAN
#define NATIVE_64BITS
#define WIDE // const // don't !!
#define WIDE_AS_INT unsigned long int
#define REENTRANT(x) x //

//#include <setjmp.h>
// GCC/LLVM declare way too big jmp context, reduce them to what is used on CM0+
typedef struct try_context_s try_context_t;
typedef unsigned int jmp_buf[10];
struct try_context_s {
  // jmp context to backup (in increasing order address: r4, r5, r6, r7, r8, r9,
  // r10, r11, SP, setjmpcallPC)
  jmp_buf jmp_buf;

  // link to the previous jmp_buf context
  try_context_t *previous;
  // current exception
  exception_t ex;
};

// borrowed from setjmp.hm0

#ifdef __GNUC__
void longjmp(jmp_buf __jmpb, int __retval) __attribute__((__noreturn__));
#else
void longjmp(jmp_buf __jmpb, int __retval);
#endif
int setjmp(jmp_buf __jmpb);

#include "stddef.h"
#include "stdint.h"
#include <core_sc300.h>

#define UNUSED(x) (void)x

#endif

// #include "os_apilevel.h"

#ifndef NULL
#define NULL ((void *)0)
#endif

#ifndef WIDE_NULL
#define WIDE_NULL ((void WIDE *)0)
#endif

// Position-independent code reference
// Function that align the dereferenced value in a rom struct to use it
// depending on the execution address. Can be used even if code is executing at
// the same place where it had been linked.
#ifndef PIC
#define PIC(x) pic((unsigned int) x)
static inline __attribute__((always_inline)) unsigned int pic(unsigned int linked_address) {
    return linked_address;
}
#endif

#ifndef SYSCALL
// #define SYSCALL syscall
#define SYSCALL
#endif

#ifndef TASKSWITCH
// #define TASKSWITCH taskswitch
#define TASKSWITCH
#endif

#ifndef SUDOCALL
// #define SUDOCALL sudocall
#define SUDOCALL
#endif

#ifndef LIBCALL
// #define LIBCALL libcall
#define LIBCALL
#endif

#ifndef SHARED
// #define SHARED shared
#define SHARED
#endif

#ifndef PERMISSION
#define PERMISSION(...)
#endif

#ifndef PLENGTH
#define PLENGTH(...)
#endif

#ifndef CXPORT
#define CXPORT(...)
#endif

#ifndef TASKLEVEL
#define TASKLEVEL(...)
#endif

/* ----------------------------------------------------------------------- */
/* -                            APPLICATION PRIVILEGES                   - */
/* ----------------------------------------------------------------------- */

/**
 * No rights concealed to the call
 */
#define APPLICATION_FLAG_NONE 0x0

/**
 * Base flag added to loaded application, to allow them to call all syscalls by
 * default (the one requiring no extra permission)
 */
#define APPLICATION_FLAG_MAIN 0x1

/**
 * Flag which combined with ::APPLICATION_FLAG_ISSUER.
 * The application is given full nvram access after the global seed has been
 * destroyed.
 */
#define APPLICATION_FLAG_BOLOS_UPGRADE 0x2

// this flag is set when a valid signature of the loaded application is
// presented at the end of the bolos application load.
#define APPLICATION_FLAG_SIGNED 0x4

// must be set on one application in the registry which is used
#define APPLICATION_FLAG_BOLOS_UX 0x8

// application is allowed to use the raw master seed, if not set, at least a
// level of derivation is required.
#define APPLICATION_FLAG_DERIVE_MASTER 0x10

#define APPLICATION_FLAG_SHARED_NVRAM 0x20
#define APPLICATION_FLAG_GLOBAL_PIN 0x40

// This flag means the application is meant to be debugged and allows for dump
// or core ARM register in case of a fault detection
#define APPLICATION_FLAG_DEBUG 0x80

/**
 * Mark this application as defaultly booting along with the bootloader (no
 * application menu displayed) Only one application can have this at a time. It
 * is managed by the bootloader interface.
 */
#define APPLICATION_FLAG_AUTOBOOT 0x100

/**
 * Application is allowed to change the settings
 */
#define APPLICATION_FLAG_BOLOS_SETTINGS 0x200

#define APPLICATION_FLAG_CUSTOM_CA 0x400

/**
 * The application main can be called in two ways:
 *  - with first arg (stored in r0) set to 0: The application is called from the
 * dashboard
 *  - with first arg (stored in r0) set to != 0 (ram address likely): The
 * application is used as a library from another app.
 */
#define APPLICATION_FLAG_LIBRARY 0x800

/**
 * The application won't be shown on the dashboard (somewhat reasonable for pure
 * library)
 */
#define APPLICATION_FLAG_NO_RUN 0x1000

/**
 * The application is considered an IO task by the system. It only gives
 * privileges to BOLOS' internal IO task
 */
#define APPLICATION_FLAG_IO 0x2000

/**
 * Application has been loaded using a secure channel opened using the
 * bootloader's issuer public key. This application is ledger legit.
 */
#define APPLICATION_FLAG_ISSUER 0x4000

/**
 * Application is enabled (when not being updated or removed)
 */
#define APPLICATION_FLAG_ENABLED 0x8000

#define APPLICATION_FLAG_NEG_MASK 0xFFFF0000UL

/* ----------------------------------------------------------------------- */
/* -                            SYSCALL CRYPTO EXPORT                    - */
/* ----------------------------------------------------------------------- */

#define CXPORT_ED_DES 0x0001UL
#define CXPORT_ED_AES 0x0002UL
#define CXPORT_ED_RSA 0x0004UL

/* ----------------------------------------------------------------------- */
/* -                            TYPES                                    - */
/* ----------------------------------------------------------------------- */

/* ----------------------------------------------------------------------- */
/* -                            GLOBALS                                  - */
/* ----------------------------------------------------------------------- */

// the global apdu buffer
#ifdef HAVE_IO_U2F
#define IMPL_IO_APDU_BUFFER_SIZE (3 + 32 + 32 + 15 + 255)
#else
#define IMPL_IO_APDU_BUFFER_SIZE (5 + 255)
#endif

#ifdef CUSTOM_IO_APDU_BUFFER_SIZE
#define IO_APDU_BUFFER_SIZE                                                    \
  MAX(IMPL_IO_APDU_BUFFER_SIZE, CUSTOM_IO_APDU_BUFFER_SIZE)
#else
#define IO_APDU_BUFFER_SIZE IMPL_IO_APDU_BUFFER_SIZE
#endif
extern unsigned char G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];

#define CUSTOMCA_MAXLEN 64

/* ----------------------------------------------------------------------- */
/* -                            ENTRY POINT                              - */
/* ----------------------------------------------------------------------- */

// os entry point
void app_main(void);

// os initialization function to be called by application entry point
void os_boot();

/* ----------------------------------------------------------------------- */
/* -                            OS FUNCTIONS                             - */
/* ----------------------------------------------------------------------- */
#define os_swap_u16(u16)                                                       \
  ((((unsigned short)(u16) << 8) & 0xFF00U) |                                  \
   (((unsigned short)(u16) >> 8) & 0x00FFU))

#define os_swap_u32(u32)                                                       \
  (((unsigned long int)(u32) >> 24) |                                          \
   (((unsigned long int)(u32) << 8) & 0x00FF0000UL) |                          \
   (((unsigned long int)(u32) >> 8) & 0x0000FF00UL) |                          \
   ((unsigned long int)(u32) << 24))

REENTRANT(void os_memmove(void *dst, const void WIDE *src,
                          unsigned int length));
#define os_memcpy os_memmove

void os_memset(void *dst, unsigned char c, unsigned int length);

void os_memset4(void *dst, unsigned int initval, unsigned int nbintval);

char os_memcmp(const void WIDE *buf1, const void WIDE *buf2,
               unsigned int length);

void os_xor(void *dst, void WIDE *src1, void WIDE *src2, unsigned int length);

// Secure memory comparison
char os_secure_memcmp(void WIDE *src1, void WIDE *src2, unsigned int length);

// patch point, address used to dispatch, no index
REENTRANT(void patch(void));

// check API level
SYSCALL void check_api_level(unsigned int apiLevel);

// halt the chip, waiting for a physical user interaction
SYSCALL REENTRANT(void halt(void));

// deprecated
#define reset halt

// send tx_len bytes (atr or rapdu) and retrieve the length of the next command
// apdu (over the requested channel)
#define CHANNEL_APDU 0
#define CHANNEL_KEYBOARD 1
#define CHANNEL_SPI 2
#define IO_RESET_AFTER_REPLIED 0x80
#define IO_RECEIVE_DATA 0x40
#define IO_RETURN_AFTER_TX 0x20
#define IO_ASYNCH_REPLY                                                        \
  0x10 // avoid apdu state reset if tx_len == 0 when we're expected to reply
#define IO_FINISHED 0x08 // inter task communication value
#define IO_FLAGS 0xF8
unsigned short io_exchange(unsigned char channel_and_flags,
                           unsigned short tx_len);

typedef enum {
  IO_APDU_MEDIA_NONE = 0, // not correctly in an apdu exchange
  IO_APDU_MEDIA_USB_HID = 1,
  IO_APDU_MEDIA_BLE,
  IO_APDU_MEDIA_NFC,
  IO_APDU_MEDIA_USB_CCID,
  IO_APDU_MEDIA_USB_WEBUSB,
  IO_APDU_MEDIA_RAW,
  IO_APDU_MEDIA_U2F,
} io_apdu_media_t;

#ifndef USB_SEGMENT_SIZE
#ifdef IO_HID_EP_LENGTH
#define USB_SEGMENT_SIZE IO_HID_EP_LENGTH
#else
#error IO_HID_EP_LENGTH and USB_SEGMENT_SIZE not defined
#endif
#endif
#ifndef BLE_SEGMENT_SIZE
#define BLE_SEGMENT_SIZE USB_SEGMENT_SIZE
#endif

// common usb endpoint buffer
extern unsigned char
    G_io_usb_ep_buffer[MAX(USB_SEGMENT_SIZE, BLE_SEGMENT_SIZE)];

/**
 * Return 1 when the event has been processed, 0 else
 */
// io callback in the application called when an interrupt based channel has
// received data to be processed
unsigned char io_event(unsigned char channel);

/**
 * Function takes 0 for first call. Returns 0 when timeout has occured. Returned
 * value is passed as argument for next call, acting as a timeout context.
 */
unsigned short io_timeout(unsigned short last_timeout);
// write in persistent memory, to make things easy keep a layout of the memory
// in a structure and update fields upon needs The function throws exception
// when the requesting application buffer being written in its declared data
// segment. The later is declared during the application slot allocation (using
// --dataSize parameter in the python scripts) NOTE: accept copy from far memory
// to another far memory.
// @param src_adr NULL to fill with 00's
SYSCALL void nvm_write(void WIDE *dst_adr PLENGTH(src_len),
                       void WIDE *src_adr PLENGTH(src_len),
                       unsigned int src_len);
// the priviledged version of nvm_write, called by bolos itself
void nvm_write_os(void WIDE *dst_adr PLENGTH(src_len),
                  void WIDE *src_adr PLENGTH(src_len), unsigned int src_len);

// program a page with the content of the nvm_page_buffer
// HAL for the high level NVM management functions
SUDOCALL PERMISSION(APPLICATION_FLAG_ISSUER) void nvm_write_page(
    unsigned char WIDE *page_adr);
void svc_nvm_write_page(unsigned char WIDE *page_adr);

/* ----------------------------------------------------------------------- */
/* -                            EXCEPTIONS                               - */
/* ----------------------------------------------------------------------- */

// workaround to make sure defines are replaced by their value for example
#define CPP_CONCAT(x, y) CPP_CONCAT_x(x, y)
#define CPP_CONCAT_x(x, y) x##y

SUDOCALL PERMISSION(APPLICATION_FLAG_NONE) try_context_t *try_context_get(void);
try_context_t *svc_try_context_get(void);
// set the new try context and retrieve the previous one
// SECURITY NOTE: no PLENGTH(sizeof(try_context_t)) set because the value is
// never dereferenced within the SUDOCALL.
//                and is checked before being used in all SYSCALL that would use
//                it.
SUDOCALL PERMISSION(APPLICATION_FLAG_NONE)
    try_context_t *try_context_set(try_context_t *context);
try_context_t *svc_try_context_set(try_context_t *tryctx);

// -----------------------------------------------------------------------
// - BEGIN TRY
// -----------------------------------------------------------------------

#define BEGIN_TRY_L(L)                                                         \
  {                                                                            \
    try_context_t __try##L;

// -----------------------------------------------------------------------
// - TRY
// -----------------------------------------------------------------------
#define TRY_L(L)                                                               \
  /* previous exception context chain is saved within the setjmp r9 save */    \
  __try                                                                        \
    ##L.ex = setjmp(__try##L.jmp_buf);                                         \
  if (__try##L.ex == 0) {                                                      \
    __try                                                                      \
      ##L.previous = try_context_set(&__try##L);

// -----------------------------------------------------------------------
// - EXCEPTION CATCH
// -----------------------------------------------------------------------
#define CATCH_L(L, x)                                                          \
  goto CPP_CONCAT(__FINALLY, L);                                               \
  }                                                                            \
  else if (__try##L.ex == x) {                                                 \
    __try                                                                      \
      ##L.ex = 0;                                                              \
    CLOSE_TRY_L(L);

// -----------------------------------------------------------------------
// - EXCEPTION CATCH OTHER
// -----------------------------------------------------------------------
#define CATCH_OTHER_L(L, e)                                                    \
  goto CPP_CONCAT(__FINALLY, L);                                               \
  }                                                                            \
  else {                                                                       \
    exception_t e;                                                             \
    e = __try##L.ex;                                                           \
    __try                                                                      \
      ##L.ex = 0;                                                              \
    CLOSE_TRY_L(L);

// -----------------------------------------------------------------------
// - EXCEPTION CATCH ALL
// -----------------------------------------------------------------------
#define CATCH_ALL_L(L)                                                         \
  goto CPP_CONCAT(__FINALLY, L);                                               \
  }                                                                            \
  else {                                                                       \
    __try                                                                      \
      ##L.ex = 0;                                                              \
    CLOSE_TRY_L(L);

// -----------------------------------------------------------------------
// - FINALLY
// -----------------------------------------------------------------------
#define FINALLY_L(L)                                                           \
  goto CPP_CONCAT(__FINALLY, L);                                               \
  }                                                                            \
  CPP_CONCAT(__FINALLY, L)                                                     \
      : /* has TRY clause ended without nested throw ? */                      \
        if (try_context_get() == &__try##L) {                                  \
    /* restore previous context manually (as a throw would have when caught)   \
     */                                                                        \
    CLOSE_TRY_L(L);                                                            \
  }
// -----------------------------------------------------------------------
// - CLOSE TRY
// -----------------------------------------------------------------------
/**
 * Forced finally like clause.
 */
#define CLOSE_TRY_L(L) try_context_set(__try##L.previous)

// -----------------------------------------------------------------------
// - END TRY
// -----------------------------------------------------------------------
#define END_TRY_L(L)                                                           \
  /* nested throw not consumed ? (by CATCH* clause) */                         \
  if (__try##L.ex != 0) {                                                      \
    /* rethrow */                                                              \
    THROW_L(L, __try##L.ex);                                                   \
  }                                                                            \
  }

// -----------------------------------------------------------------------
// - EXCEPTION THROW
// -----------------------------------------------------------------------

/**
 Remember that using break/return/goto/continue keywords that disrupt the
 execution flow may introduce silent errors which can pop afterwards in a
 very sneaky and hard to debug way. Those keywords are malicious ONLY when
 jumping out of the current block (TRY/CATCH/CATCH_OTHER/CATCH_ALL) else
 they are perfectly fine.
 When those keywords use are unavoidable, then remember to CLOSE_TRY your
 opened BEGIN/END block.
 To detect those potential problems, here is a basic sed based script to
 narrow down the search to poentially suspicious cases.
 for i in `find . -name "*.c"`; do echo $i ; sed -n '/BEGIN_TRY/,/END_TRY/{
 /goto/{=;H;g;p} ;/return/{=;H;g;p} ; /continue/{=;H;g;p} ; /break/{=;H;g;p} ; h
 }' $i ; done Run it on your source code if unsure. The rule of thumb to respect
 to decide whether or not to use the CLOSE_TRY statement is the following:
 Jumping out of a TRY/CATCH/CATCH_ALL/CATCH_OTHER clause is not closing the
 BEGIN/TRY block if the FINALLY is not executed wholy (jumping to a label
 at the beginning of the FINALLY is not solving the above stated problem).

 Faulty example:
 ===============
 BEGIN_TRY {
   TRY {
    ...
   }
   CATCH {
     ...
     goto noway;
   }
   FINALLY {

   }
 }
 END_TRY;
 noway:
 return;

 Faulty example 2:
 ===============
 BEGIN_TRY {
   TRY {
    ...
     goto noway;
   }
   CATCH {
     ...
   }
   FINALLY {

   }
 }
 END_TRY;
 noway:
 return;

 Faulty example 3:
 ===============
 BEGIN_TRY {
   TRY {
    ...
   }
   CATCH {
     ...
     goto end;
     ...
   }
   FINALLY {
     end:
   }
 }
 END_TRY;
 noway:
 return;

 Faulty example 4:
 ===============
 for(;;) {
   BEGIN_TRY {
     TRY {
      ...
       continue;
       ...
     }
     CATCH {
       ...
     }
     FINALLY {

     }
   }
   END_TRY;
 }

 Ok example (but very suspicious algorithmly speaking):
 ===============
 BEGIN_TRY {
   TRY {
    ...
    yo:
    ...
   }
   CATCH {
     ...
     goto yo;
   }
   FINALLY {

   }
 }
 END_TRY;
 noway:
 return;

 Ok example 2:
 ===============
 BEGIN_TRY {
   TRY {
    ...
    CLOSE_TRY;
    goto noway;
    ...
   }
   CATCH {
     ...
   }
   FINALLY {

   }
 }
 END_TRY;
 noway:
 return;

 Ok example 3:
 ===============
 BEGIN_TRY {
   TRY {
    ...
    goto baz;
    ...
    baz:
   }
   CATCH {
     ...
   }
   FINALLY {

   }
 }
 END_TRY;

 Faulty example 5:
 ===============
 BEGIN_TRY {
   TRY {
    ...
   }
   CATCH {
     return val;
   }
   FINALLY {
     ...
   }
 }
 END_TRY;

 Faulty example 6:
 ===============
 BEGIN_TRY {
   TRY {
     ...
     return val;
   }
   CATCH {
     ...
   }
   FINALLY {
     ...
   }
 }
 END_TRY;

 Ok example 4:
 ===============
 BEGIN_TRY {
   TRY {
    ...
   }
   CATCH {
     ...
   }
   FINALLY {
     return val;
   }
 }
 END_TRY;
 */

// longjmp is marked as no return to avoid too much generated code
#ifdef __clang_analyzer__
void os_longjmp(unsigned int exception) __attribute__((analyzer_noreturn));
#else
void os_longjmp(unsigned int exception) __attribute__((noreturn));
#endif
#define THROW_L(L, x) os_longjmp(x)

// Default macros when nesting is not used.
#define THROW(x) THROW_L(EX, x)
#define BEGIN_TRY BEGIN_TRY_L(EX)
#define TRY TRY_L(EX)
#define CATCH(x) CATCH_L(EX, x)
#define CATCH_OTHER(e) CATCH_OTHER_L(EX, e)
#define CATCH_ALL CATCH_ALL_L(EX)
#define FINALLY FINALLY_L(EX)
#define CLOSE_TRY CLOSE_TRY_L(EX)
#define END_TRY END_TRY_L(EX)

#define EXCEPTION 1
#define INVALID_PARAMETER 2
#define EXCEPTION_OVERFLOW 3
#define EXCEPTION_SECURITY 4
#define INVALID_CRC 5
#define INVALID_CHECKSUM 6
#define INVALID_COUNTER 7
#define NOT_SUPPORTED 8
#define INVALID_STATE 9
#define TIMEOUT 10
#define EXCEPTION_PIC 11
#define EXCEPTION_APPEXIT 12
#define EXCEPTION_IO_OVERFLOW 13
#define EXCEPTION_IO_HEADER 14
#define EXCEPTION_IO_STATE 15
#define EXCEPTION_IO_RESET 16
#define EXCEPTION_CXPORT 17
#define EXCEPTION_SYSTEM 18
#define NOT_ENOUGH_SPACE 19

/* ----------------------------------------------------------------------- */
/* -                          CRYPTO FUNCTIONS                           - */
/* ----------------------------------------------------------------------- */
#include "cx.h"

/**
 BOLOS RAM LAYOUT
                msp                          psp                   psp
 | bolos ram <-os stack-| bolos ux ram <-ux_stack-| app ram <-app stack-|

 ux and app are seen as applications.
 os is not an application (it calls ux upon user inputs)
**/

/* ----------------------------------------------------------------------- */
/* -                        BOLOS UX DEFINITIONS                         - */
/* ----------------------------------------------------------------------- */
typedef enum bolos_ux_e {
  BOLOS_UX_INITIALIZE = 0, // tag to be processed by the UX from the serial line

  BOLOS_UX_EVENT, // tag to be processed by the UX from the serial line
  BOLOS_UX_KEYBOARD,
  BOLOS_UX_WAKE_UP, // the application/os asks for the screen to be waked up
                    // (asking pin if the lock period has been exceeded)
  BOLOS_UX_STATUS_BAR,

  BOLOS_UX_BOOT, // will never be presented to loaded UX app, this is for
                 // failsafe UX only
  BOLOS_UX_BOOT_NOT_PERSONALIZED,
  BOLOS_UX_BOOT_ONBOARDING,
  BOLOS_UX_BOOT_UNSAFE_WIPE,
  BOLOS_UX_BOOT_UX_NOT_SIGNED,
  BOLOS_UX_BOLOS_START = 10, // called in before dashboard displays
  BOLOS_UX_DASHBOARD,
  BOLOS_UX_PROCESSING,

  BOLOS_UX_LOADER, // display loader screen or advance it

  BOLOS_UX_VALIDATE_PIN,
  BOLOS_UX_CONSENT_UPGRADE,
  BOLOS_UX_CONSENT_APP_ADD,
  BOLOS_UX_CONSENT_APP_DEL,
  BOLOS_UX_CONSENT_APP_UPG,
  BOLOS_UX_CONSENT_ISSUER_KEY,
  BOLOS_UX_CONSENT_CUSTOMCA_KEY = 20,
  BOLOS_UX_CONSENT_FOREIGN_KEY,
  BOLOS_UX_CONSENT_GET_DEVICE_NAME,
  BOLOS_UX_CONSENT_SET_DEVICE_NAME,
  BOLOS_UX_CONSENT_RESET_CUSTOMCA_KEY,
  BOLOS_UX_CONSENT_SETUP_CUSTOMCA_KEY,
  BOLOS_UX_APP_ACTIVITY, // special code when application is processing data but
                         // not displaying UI. It prevent going poweroff, while
                         // not avoiding screen locking
  BOLOS_UX_CONSENT_NOT_INTERACTIVE_ONBOARD,
  BOLOS_UX_PREPARE_RUN_APP, // called before the os runs an application, the os
                            // ux must be cleared and not display anything on
                            // upcoming display processed events

  BOLOS_UX_MCU_UPGRADE_REQUIRED,
  BOLOS_UX_CONSENT_RUN_APP = 30,
  BOLOS_UX_SECURITY_BOOT_DELAY,
  DEPRECATED_BOLOS_UX_CONSENT_GENUINENESS,
  BOLOS_UX_BOOT_MENU,
  BOLOS_UX_CONTROL_CENTER,
  BOLOS_UX_ASYNCHMODAL_PAIRING_REQUEST, // ask the ux to display a modal to
                                        // accept/reject the current pairing
                                        // request
  BOLOS_UX_ASYNCHMODAL_PAIRING_CANCEL,  //

  BOLOS_UX_CONSENT_LISTAPPS,

  BOLOS_UX_LAST_ID, // keep that one at the end
} bolos_ux_t;

typedef char bolos_bool_t;
#define BOLOS_TRUE BOLOS_UX_OK
#define BOLOS_FALSE BOLOS_UX_CANCEL

typedef unsigned char bolos_task_status_t;

#define BOLOS_UX_OK 0xAA
#define BOLOS_UX_CANCEL 0x55
#define BOLOS_UX_ERROR 0xD6

/* Value returned by os_ux to notify the application that the processed event
 * must be discarded and not processed by the application. Generally due to
 * handling of power management/dim/locking */
#define BOLOS_UX_IGNORE 0x97
// a modal has destroyed the display, app needs to redraw its screen
#define BOLOS_UX_REDRAW 0x69
// ux has not finished processing yet (not a final status)
#define BOLOS_UX_CONTINUE 0

/* ----------------------------------------------------------------------- */
/* -                       APPLICATION FUNCTIONS                         - */
/* ----------------------------------------------------------------------- */

typedef void (*appmain_t)(void);

#define BOLOS_TAG_APPNAME 0x01
#define BOLOS_TAG_APPVERSION 0x02
#define BOLOS_TAG_ICON 0x03
#define BOLOS_TAG_DERIVEPATH 0x04
#define BOLOS_TAG_DATA_SIZE                                                    \
  0x05 // meta tag to retrieve the size of the data section for the application
// Library Dependencies are a tuple of 2 LV, the lib appname and the lib version
// (only exact for now). When lib version is not specified, it is not check,
// only name is asserted The DEPENDENCY tag may have several occurences, one for
// each dependency (by name). Malformed (multiple dep to the same lib with
// different version is is not ORed but ANDed, and then considered bogus)
#define BOLOS_TAG_DEPENDENCY 0x06
// first autorised tag value for user data
#define BOLOS_TAG_USER_TAG 0x20

// application slot description
typedef struct application_s {
  // nvram start address for this application (to check overlap when loading,
  // and mpu lock)
  unsigned char *nvram_begin;
  // nvram stop address (exclusive) for this application (to check overlap when
  // loading, and mpu lock)
  unsigned char *nvram_end;

  // address of the main address, must be set according to BLX spec ( ORed with
  // 1 when jumping into Thumb code
  appmain_t main;

  // special flags for this application
  unsigned int flags;

  // Memory organization: [ code (RX) |alignpage| data (RW) |alignpage| install
  // params (R) ]

  // length of the code section of the application (RX)
  unsigned int code_length;

  // NOTE: code_length+params_length must be a multiple of PAGE_SIZE
  // Length of the DATA section of the application. (RW)
  unsigned int data_length;

  // NOTE: code_length+params_length must be a multiple of PAGE_SIZE
  // length of the parameters sections of the application (R)
  unsigned int params_length;

  // Intermediate hash of the application's loaded code and data segments
  unsigned char sha256_code_data[32];
  // Hash of the application's loaded code, data and instantiation parameters
  unsigned char sha256_full[32];

} application_t;

// Structure that defines the parameters to exchange with the BOLOS UX
// application
typedef struct bolos_ux_params_s {
  bolos_ux_t ux_id;
  // length of parameters in the u union to be copied during the syscall
  unsigned int len;

  // structure to overlay parameters for each BOLOS_UX
  union {
    struct {
      unsigned int currently_onboarded;
      unsigned char hash[32];
    } boot_unsafe;

    struct {
      unsigned int app_idx;
    } appexitb;

    struct {
      unsigned int app_idx;
      application_t appentry;
    } appdel;

    struct {
      unsigned int app_idx;
      application_t appentry;
    } appadd;

    // pass the whole load application to that the os version and hash are
    // available
    struct {
      unsigned int app_idx;
      application_t upgrade;
    } upgrade;

    struct {
      application_t ux_app;
    } ux_not_signed;

    struct {
      unsigned int app_idx;
      application_t app;
    } run_app;

    struct {
      char name[CUSTOMCA_MAXLEN + 1];
      cx_ecfp_public_key_t public;
    } customca_key;

    struct {
      cx_ecfp_public_key_t host_pubkey;
    } foreign_key;

    struct {
      char name[CUSTOMCA_MAXLEN + 1];
      cx_ecfp_public_key_t public;
    } reset_customca;

    struct {
      char name[CUSTOMCA_MAXLEN + 1];
      cx_ecfp_public_key_t public;
    } setup_customca;

    struct {
      unsigned int keycode;
#define BOLOS_UX_MODE_UPPERCASE 0
#define BOLOS_UX_MODE_LOWERCASE 1
#define BOLOS_UX_MODE_SYMBOLS 2
#define BOLOS_UX_MODE_COUNT 3 // number of keyboard modes
      unsigned int mode;
      // + 1 EOS (0)
#define BOLOS_UX_KEYBOARD_TEXT_BUFFER_SIZE 32
      char entered_text[BOLOS_UX_KEYBOARD_TEXT_BUFFER_SIZE + 1];
    } keyboard;

    struct {
      unsigned int cancellable;
    } validate_pin;

    struct {
      unsigned int keycode;
    } pin_keyboard;

    struct {
      unsigned int fgcolor;
      unsigned int bgcolor;
    } status_bar;

    struct {
      unsigned int x;
      unsigned int y;
      unsigned int width;
      unsigned int height;
    } loader;

    struct {
      unsigned int id;
    } onboard;

    struct {
      unsigned int percent;
    } boot_delay;

    struct {
      enum {
        BOLOS_UX_ASYNCHMODAL_PAIRING_REQUEST_PASSKEY,
        BOLOS_UX_ASYNCHMODAL_PAIRING_REQUEST_NUMCOMP,
      } type;
      unsigned int pairing_info_len;
      char pairing_info[16];
    } pairing_request;

  } u;

} bolos_ux_params_t;

// any application can wipe the global pin, global seed, user's keys
// disabled for security reasons // SYSCALL void           os_perso_wipe(void);
// erase seed, settings AND applications
SYSCALL void os_perso_erase_all(void);

/* set_pin can update the pin if the perso is onboarded (tearing leads to perso
 * wipe though) */
SYSCALL PERMISSION(APPLICATION_FLAG_BOLOS_UX) void os_perso_set_pin(
    unsigned int identity, unsigned char *pin PLENGTH(length),
    unsigned int length);
// set the currently unlocked identity pin. (change pin feature)
SYSCALL
    PERMISSION(APPLICATION_FLAG_BOLOS_UX) void os_perso_set_current_identity_pin(
        unsigned char *pin PLENGTH(length), unsigned int length);

#define BOLOS_UX_ONBOARDING_ALGORITHM_BIP39 1
#define BOLOS_UX_ONBOARDING_ALGORITHM_ELECTRUM 2

/**
 * Set the persisted seed if none yet, else override the volatile seed (in RAM)
 */
SYSCALL PERMISSION(APPLICATION_FLAG_BOLOS_UX) void os_perso_set_seed(
    unsigned int identity, unsigned int algorithm,
    unsigned char *seed PLENGTH(length), unsigned int length);

SYSCALL PERMISSION(APPLICATION_FLAG_BOLOS_UX) void os_perso_derive_and_set_seed(
    unsigned char identity, const char *prefix PLENGTH(prefix_length),
    unsigned int prefix_length,
    const char *passphrase PLENGTH(passphrase_length),
    unsigned int passphrase_length, const char *words PLENGTH(words_length),
    unsigned int words_length);

// SYSCALL PERMISSION(APPLICATION_FLAG_BOLOS_UX) void
// os_perso_set_alternate_pin(unsigned char* pin PLENGTH(pinLength), unsigned int
// pinLength); SYSCALL PERMISSION(APPLICATION_FLAG_BOLOS_UX) void
// os_perso_set_alternate_seed(unsigned char* seed PLENGTH(seedLength), unsigned
// int seedLength);
SYSCALL PERMISSION(APPLICATION_FLAG_BOLOS_UX) void os_perso_set_words(
    const unsigned char *words PLENGTH(length), unsigned int length);
SYSCALL PERMISSION(APPLICATION_FLAG_BOLOS_UX) void os_perso_finalize(void);

// checked in the ux flow to avoid asking the pin for example
// NBA : could also be checked by applications running in unsecure mode - thus
// unprivilegied
// @return BOLOS_UX_OK when perso is onboarded.
SYSCALL bolos_bool_t os_perso_isonboarded(void);

// derive the seed for the requested BIP32 path
SYSCALL void os_perso_derive_node_bip32(
    cx_curve_t curve,
    const unsigned int *path PLENGTH(4 * (pathLength & 0x0FFFFFFFu)),
    unsigned int pathLength, unsigned char *privateKey PLENGTH(64),
    unsigned char *chain PLENGTH(32));

#define HDW_NORMAL 0
#define HDW_ED25519_SLIP10 1
// symmetric key derivation according to SLIP-0021
// this only supports derivation of the master node (level 1)
// the beginning of the authorized path is to be provided in the authorized
// derivation tag of the registry starting with a \x00 Note: for SLIP21, the
// path is a string and the pathLength is the number of chars including the
// starting \0 byte. However, firewall checks are processing a number of
// integers, therefore, take care not to locate the buffer too far in memory to
// pass the firewall check.
#define HDW_SLIP21 2
// derive the seed for the requested BIP32 path, with the custom provided
// seed_key for the sha512 hmac ("Bitcoin Seed", "Nist256p1 Seed", "ed25519
// seed", ...)
SYSCALL void os_perso_derive_node_with_seed_key(
    unsigned int mode, cx_curve_t curve,
    const unsigned int *path PLENGTH(4 * (pathLength & 0x0FFFFFFFu)),
    unsigned int pathLength, unsigned char *privateKey PLENGTH(64),
    unsigned char *chain PLENGTH(32),
    unsigned char *seed_key PLENGTH(seed_key_length),
    unsigned int seed_key_length);
#define os_perso_derive_node_bip32_seed_key(mode, curve, path, pathLength,     \
                                            privateKey, chain, seed_key,       \
                                            seed_key_length)                   \
  os_perso_derive_node_with_seed_key(mode, curve, path, pathLength,            \
                                     privateKey, chain, seed_key,              \
                                     seed_key_length)

/**
 * Generate a seed based cookie
 * seed => derivation (path 0xda7aba5e/0xc1a551c5) => priv key =SECP256K1=>
 * pubkey => sha512 => cookie
 */
SYSCALL unsigned int
os_perso_seed_cookie(unsigned char *seed_cookie PLENGTH(seed_cookie_length),
                     unsigned int seed_cookie_length);

// endorsement APIs
SYSCALL unsigned int
os_endorsement_get_code_hash(unsigned char *buffer PLENGTH(32));
SYSCALL unsigned int
os_endorsement_get_public_key(unsigned char index,
                              unsigned char *buffer PLENGTH(65));
SYSCALL unsigned int os_endorsement_get_public_key_certificate(
    unsigned char index,
    unsigned char *buffer PLENGTH(1 + 1 + 2 * (1 + 1 + 33)));
SYSCALL unsigned int
os_endorsement_key1_get_app_secret(unsigned char *buffer PLENGTH(64));
SYSCALL unsigned int os_endorsement_key1_sign_data(
    unsigned char *src PLENGTH(srcLength), unsigned int srcLength,
    unsigned char *signature PLENGTH(1 + 1 + 2 * (1 + 1 + 33)));
SYSCALL unsigned int os_endorsement_key2_derive_sign_data(
    unsigned char *src PLENGTH(srcLength), unsigned int srcLength,
    unsigned char *signature PLENGTH(1 + 1 + 2 * (1 + 1 + 33)));

// nvram shared zone access right => MPU opening at application switch, using a
// flags in the registry

// Global PIN
#define DEFAULT_PIN_RETRIES 3
/*
 * @return BOLOS_UX_OK if pin validated
 */
SYSCALL bolos_bool_t os_global_pin_is_validated(void);
/**
 * Validating the pin also setup the identity linked with this pin (normal or
 * alternate)
 * @return BOLOS_UX_OK if pin validated
 */
SYSCALL PERMISSION(APPLICATION_FLAG_GLOBAL_PIN) bolos_bool_t
    os_global_pin_check(unsigned char *pin_buffer PLENGTH(pin_length),
                        unsigned char pin_length);
SYSCALL
    PERMISSION(APPLICATION_FLAG_GLOBAL_PIN) void os_global_pin_invalidate(void);
SYSCALL PERMISSION(
    APPLICATION_FLAG_GLOBAL_PIN) unsigned int os_global_pin_retries(void);

SYSCALL
    PERMISSION(APPLICATION_FLAG_BOLOS_UX) unsigned int os_registry_count(void);
// return any entry, activated or not, enabled or not, empty or not. to enable
// full control
SYSCALL PERMISSION(APPLICATION_FLAG_BOLOS_UX) void os_registry_get(
    unsigned int index,
    application_t *out_application_entry PLENGTH(sizeof(application_t)));

// return !0 when ux scenario has ended, else 0
// while not ended, all display/touch/ticker and other events are to be
// processed by the ux. only io is not processed. when returning !0 the
// application must send a general status (or continue its command flow)
SYSCALL TASKSWITCH unsigned int
os_ux(bolos_ux_params_t *params PLENGTH(sizeof(bolos_ux_params_t)));
// read parameters back from the UX app. useful to read keyboard type or such
SYSCALL void
os_ux_result(bolos_ux_params_t *params PLENGTH(sizeof(bolos_ux_params_t)));
// Read the last os_ux call parameters from within the UX app. to make easier
// the firewalling between tasks.
SYSCALL PERMISSION(APPLICATION_FLAG_BOLOS_UX) void os_ux_read_parameters(
    bolos_ux_params_t *params PLENGTH(sizeof(bolos_ux_params_t)));

// process all possible messages while waiting for a ux to finish,
// unprocessed messages are replied with a generic general status
// when returning the application must send a general status (or continue its
// command flow)
unsigned int os_ux_blocking(bolos_ux_params_t *params);

/* ----------------------------------------------------------------------- */
/* -                            LIB FUNCTIONS                            - */
/* ----------------------------------------------------------------------- */
/**
 * Library call function.
 * call_parameters[0] = library name string pointer (const)
 * call_parameters[1] = library call identifier (0 = init, ...)
 * call_parameters[2+] = called function parameters
 */
SYSCALL void
os_lib_call(unsigned int *call_parameters PLENGTH(3 * sizeof(unsigned int)));
SYSCALL void os_lib_end(void);
SYSCALL void os_lib_throw(unsigned int exception);

/* ----------------------------------------------------------------------- */
/* -                            ID FUNCTIONS                             - */
/* ----------------------------------------------------------------------- */
#define OS_FLAG_RECOVERY 1
#define OS_FLAG_SIGNED_MCU_CODE 2
#define OS_FLAG_ONBOARDED 4
#define OS_FLAG_PIN_VALIDATED 128
//#define OS_FLAG_CUSTOM_UX       4
/* Enable application to retrieve OS current running options */
SYSCALL PERMISSION(APPLICATION_FLAG_NONE) unsigned int os_flags(void);
SYSCALL unsigned int os_version(unsigned char *version PLENGTH(maxlength),
                                unsigned int maxlength);
/* Grab the SE serial number */
SYSCALL unsigned int os_serial(unsigned char *serial PLENGTH(maxlength),
                               unsigned int maxlength);
#ifdef TARGET_NANOX
/* Grab the SEPROXYHAL's MCU serial number */
SYSCALL unsigned int os_seph_serial(unsigned char *serial PLENGTH(maxlength),
                                    unsigned int maxlength);
#endif // TARGET_NANOX
/* Grab the SEPROXYHAL's feature set */
SYSCALL unsigned int os_seph_features(void);
/* Grab the SEPROXYHAL's version */
SYSCALL unsigned int os_seph_version(unsigned char *version PLENGTH(maxlength),
                                     unsigned int maxlength);
SYSCALL unsigned int
os_bootloader_version(unsigned char *version PLENGTH(maxlength),
                      unsigned int maxlength);

/*
 * Copy the serial number in the given buffer and return its length
 */
unsigned int os_get_sn(unsigned char *buffer);

/* ----------------------------------------------------------------------- */
/* -                         SETTINGS FUNCTIONS                          - */
/* ----------------------------------------------------------------------- */
typedef enum os_setting_e {
  OS_SETTING_BRIGHTNESS,
  OS_SETTING_INVERT,
  OS_SETTING_ROTATION,
#ifdef HAVE_BOLOS_NOT_SHUFFLED_PIN
  OS_SETTING_NOSHUFFLE_PIN,
#endif // HAVE_BOLOS_NOT_SHUFFLED_PIN
  OS_SETTING_AUTO_LOCK_DELAY,
  OS_SETTING_POWER_OFF_DELAY,

  OS_SETTING_PLANEMODE,

  // default off
  OS_SETTING_PRIVACY_MODE,

  // before that value, all settings are only making use of the length value
  // with a null buffer to be set, and are returned through the return value
  // with a maxlength = 0 in the get.
  OS_SETTING_LAST_INT,

  // screen saver string to display
  OS_SETTING_SAVER_STRING = OS_SETTING_LAST_INT,
  OS_SETTING_DEVICENAME,
  OS_SETTING_BLEMACADR,

  OS_SETTING_LAST,
} os_setting_t;

/**
 * Retrieve the value of a setting in a user specified buffer, with a max
 * length, and return the effective returned length.
 */
SYSCALL PERMISSION(APPLICATION_FLAG_BOLOS_SETTINGS) unsigned int os_setting_get(
    unsigned int setting_id, unsigned char *value PLENGTH(maxlen),
    unsigned int maxlen);

/**
 * Define a setting's value from a user buffer and its length. In case of error,
 * a throw is executed.
 */
SYSCALL PERMISSION(APPLICATION_FLAG_BOLOS_SETTINGS) void os_setting_set(
    unsigned int setting_id, unsigned char *value PLENGTH(length),
    unsigned int length);

/* ----------------------------------------------------------------------- */
/* -                          DEBUG FUNCTIONS                           - */
/* ----------------------------------------------------------------------- */
void screen_printf(const char *format, ...);

// emit a single byte
void screen_printc(unsigned char const c);

// redefined if string.h not included
int snprintf(char *str, size_t str_size, const char *format, ...);

#ifndef PRINTF
#define PRINTF(...)
#endif

// syscall test
// SYSCALL void dummy_1(unsigned int* p PLENGTH(2+len+15+ len + 16 +
// sizeof(io_send_t) + 1 ), unsigned int len);

typedef struct meminfo_s {
  unsigned int free_nvram_size;
  unsigned int appMemory;
  unsigned int systemSize;
  unsigned int slots;
} meminfo_t;

SYSCALL PERMISSION(APPLICATION_FLAG_BOLOS_UX) void os_get_memory_info(
    meminfo_t *meminfo PLENGTH(sizeof(meminfo_t)));

// arbitraty max size for application names.
#define BOLOS_APPNAME_MAX_SIZE_B 32

// read from the application's install parameter TLV (if present), else 0 is
// returned (no exception thrown). takes into account the currently loaded
// application
#define OS_REGISTRY_GET_TAG_OFFSET_COMPARE_WITH_BUFFER (0x80000000UL)
#define OS_REGISTRY_GET_TAG_OFFSET_GET_LENGTH (0x40000000UL)

/**
 * @param appidx The application entry index in the registry (raw, not filtering
 * ux or whatever). If the entry index correspond to the application being
 * installed then RAM structure content is used instead of the NVRAM registry.
 * @param tlvoffset The offset within the install parameters memory area, in
 * bytes. Useful if tag is present multiple times. Can be null. The tlv offset
 * is the offset of the tag in the install parameters area when a tag is
 * matched. This way long tag can be read in multiple time without the need to
 * play with the tlvoffset. Add +1 to skip to the next one when seraching for
 * multiple tag occurences.
 * @param tag The tag to be searched for
 * @param value_offset The offset within the value for this occurence of the
 * tag. The OS_REGISTRY_GET_TAG_OFFSET_COMPARE_WITH_BUFFER or
 * OS_REGISTRY_GET_TAG_OFFSET_GET_LENGTH can be ORed to perform meta operation
 * on the TLV occurence.
 * @param buffer The user buffer for comparison or to retrieve the value of the
 * tag at the given offset.
 * @param maxlength Size of the buffer to be compared OR to be retrieved
 * (trimmed depending the TLV effective length).
 */
SYSCALL PERMISSION(APPLICATION_FLAG_BOLOS_UX) unsigned int os_registry_get_tag(
    unsigned int appidx, unsigned int *tlvoffset, unsigned int tag,
    unsigned int value_offset, void *buffer PLENGTH(maxlength),
    unsigned int maxlength);

// Copy the currently running application tag from its install parameters to the
// given user buffer. Only APPNAME/APPVERSION/DERIVEPATH/ICON tags are
// retrievable to avoid install parameters private information. Warning: this
// function returns tag content of the application lastly scheduled to run, not
// the tag content of the currently executed piece of code (libraries subcalls)
SYSCALL unsigned int
os_registry_get_current_app_tag(unsigned int tag,
                                unsigned char *buffer PLENGTH(maxlen),
                                unsigned int maxlen);

#ifndef HAVE_BOLOS_NO_CUSTOMCA
/* ----------------------------------------------------------------------- */
/* -                         CUSTOM CERTIFICATE AUTHORITY                - */
/* ----------------------------------------------------------------------- */

// Verify the signature is issued from the custom certificate authority
SYSCALL unsigned int
os_customca_verify(unsigned char *hash PLENGTH(32),
                   unsigned char *sign PLENGTH(sign_length),
                   unsigned int sign_length);
#endif // HAVE_BOLOS_NO_CUSTOMCA

/* ----------------------------------------------------------------------- */
/* -                         PRECISE WATCHDOG                            - */
/* ----------------------------------------------------------------------- */

#ifndef BOLOS_SECURITY_BOOT_DELAY_H
#ifdef BOLOS_RELEASE
// Boot delay before wiping the fault detection counter
#define BOLOS_SECURITY_BOOT_DELAY_H 5
#else // BOLOS_RELEASE
#define BOLOS_SECURITY_BOOT_DELAY_H 1 - (60 * 60 * 100) + 15 * 100
#endif // BOLOS_RELEASE
#endif // BOLOS_SECURITY_BOOT_DELAY_H
#ifndef BOLOS_SECURITY_ONBOARD_DELAY_S
#ifdef BOLOS_RELEASE
// Minimal time for an onboard
#define BOLOS_SECURITY_ONBOARD_DELAY_S (2 * 60)
#else // BOLOS_RELEASE
// small overhead in dev
#define BOLOS_SECURITY_ONBOARD_DELAY_S 5
#endif // BOLOS_RELEASE
#endif // BOLOS_SECURITY_ONBOARD_DELAY_S

#ifndef BOLOS_SECURITY_ATTESTATION_DELAY_S
// Minimal time interval in between two use of the device's private key (SCP
// opening and endorsement)
#define BOLOS_SECURITY_ATTESTATION_DELAY_S 5
#endif // BOLOS_SECURITY_ATTESTATION_DELAY_S

void safe_desynch();
#define SAFE_DESYNCH() safe_desynch()

typedef enum {
  /* Watchdog consumption lead to no action being taken, overflowed value is
     accounted and can be retrieved by the application */
  OS_WATCHDOG_NOACTION = 0,
  /* Request a platform reset when the watchdog set value is completely consumed
   */
  OS_WATCHDOG_RESET = 1,
  /* Request a wipe of the user data when the watchdog times out */
  OS_WATCHDOG_WIPE = 2,
} os_watchdog_behavior_t;

/**
 * This function arm a low level watchdog, when the value is consumed, and
 * depending on the requested behavior, an action can be taken.
 * @throw INVALID_PARAMETER when the useconds value overflows the possible
 * value.
 */
void os_watchdog_arm(unsigned int useconds, os_watchdog_behavior_t behavior);

/**
 * This function returns the number of useconds to be still consumed by the
 * watchdog (when > 0), or the overflowed useconds after the watchdog has timed
 * out (when < 0)
 */
int os_watchdog_value(void);

enum task_unsecure_id_e {
  TASK_BOLOS = 0, // can call os
  TASK_SYSCALL,   // can call os
  TASK_USERTASKS_START,
  // disabled for now // TASK_USER_UX, // must call syscalls to reach os, locked
  // in ux ram
  TASK_USER =
      TASK_USERTASKS_START, // must call syscalls to reach os, locked in app ram
  TASK_SUBTASKS_START,
  TASK_SUBTASK_0 = TASK_SUBTASKS_START,
#ifdef TARGET_NANOX
  TASK_SUBTASK_1,
  TASK_SUBTASK_2,
  TASK_SUBTASK_3,
#endif // TARGET_NANOX
  TASK_BOLOS_UX,
  TASK_MAXCOUNT, // must be last in the structure
};

// execute the given application index in the registry, this function kills the
// current app task
SYSCALL TASKSWITCH PERMISSION(APPLICATION_FLAG_BOLOS_UX) void os_sched_exec(
    unsigned int application_index);
// exit the current task
SYSCALL PERMISSION(APPLICATION_FLAG_NONE) void os_sched_exit(
    bolos_task_status_t exit_code);

// returns true when the given task is running, false else.
SYSCALL bolos_bool_t os_sched_is_running(unsigned int task_idx);

/**
 * Retrieve the last status issued by a task using either yield or exit.
 */
SUDOCALL PERMISSION(APPLICATION_FLAG_NONE) bolos_task_status_t
    os_sched_last_status(unsigned int task_idx);
bolos_task_status_t svc_os_sched_last_status(unsigned int task_idx);

/**
 * Current task is yielding the process to another task.
 * Meta call for task_switch with 'the enxt' task idx.
 * @param status is the current task status
 */
SUDOCALL TASKSWITCH PERMISSION(APPLICATION_FLAG_NONE) void os_sched_yield(
    bolos_task_status_t status);
void svc_os_sched_yield(bolos_task_status_t status);

/**
 * Perform task switching
 * @param registry_app_idx is the application registry index to switch into
 * @param status of the currently executed task
 * @return the status of the previously running task
 */
SUDOCALL TASKSWITCH PERMISSION(APPLICATION_FLAG_NONE) void os_sched_switch(
    unsigned int task_idx, bolos_task_status_t status);
void svc_os_sched_switch(unsigned int task_idx, bolos_task_status_t status);

/**
 * Function that returns the currently running task identifier.
 */
SUDOCALL
    PERMISSION(APPLICATION_FLAG_NONE) unsigned int os_sched_current_task(void);
unsigned int svc_os_sched_current_task(void);

/**
 * Create a new task with the given parameters and return its task identifier.
 * The newly created task is chrooted in the given nvram/ram1/ram2 segments
 * and its task pointer is set at the end of ram1 segment.
 * The task is bound to the currently running application.
 * The task identifiers are not garanteed to be the same after a power cycle.
 * At least valid main, nvram segment, ram0 segment and stack segment must be
 * provided with.
 * @param permissions to give to the task, permissions is a AND mask with the
 * application's installation flags (can only reduce scope, never grant more).
 * @param main The main function address to start the task with.
 * @param nvram The nvram segment address start
 * @param nvram_length The nvram segment length
 * @param ram0 /ram0_length the first RAM segment description
 * @param ram1 /ram1_length the second RAM segment description
 * @param stack /stack_length the task's stack RAM segment description
 */
SYSCALL unsigned int
os_sched_create(unsigned int permissions, void *main,
                void *nvram PLENGTH(nvram_length), unsigned int nvram_length,
                void *ram0 PLENGTH(ram0_length), unsigned int ram0_length,
                void *ram1 PLENGTH(ram1_length), unsigned int ram1_length,
                void *stack PLENGTH(stack_length), unsigned int stack_length);

// kill a task
SYSCALL void os_sched_kill(unsigned int taskidx);

#ifdef HAVE_BAGL
#ifdef TARGET_NANOX
// SYSCALL void screen_write_frame(unsigned char* framebuffer
// PLENGTH(BAGL_WIDTH*BAGL_HEIGHT/8));
/**
 * Initialize the screen driver and blank the screen.
 */
void screen_init(void);
/**
 * Blank the screen buffer but don't update the screen driver just yet.
 */
SYSCALL void screen_clear(void);
/**
 * Require the screen buffer to be pushed into the screen driver.
 */
SYSCALL void screen_update(void);
/**
 * Require a specific zone not to be cleared/drawn by any graphic HAL to
 * implement screen overlay
 */
SYSCALL void screen_set_keepout(unsigned int x, unsigned int y,
                                unsigned int width, unsigned int height);
/**
 * Draw the given bitmap, with the given colors and position into the screen
 * buffer. Don't update the screen driver.
 */
SYSCALL void bagl_hal_draw_bitmap_within_rect(
    int x, int y, unsigned int width, unsigned int height,
    unsigned int color_count,
    const unsigned int *colors PLENGTH(color_count * 4),
    unsigned int bit_per_pixel,
    const unsigned char *bitmap PLENGTH(1 + bitmap_length_bits / 8),
    unsigned int bitmap_length_bits);
/**
 * Fill a rectangle with a given color in the screen buffer, but don't update
 * the screen driver.
 */
SYSCALL void bagl_hal_draw_rect(unsigned int color, int x, int y,
                                unsigned int width, unsigned int height);
#endif // TARGET_NANOX
#endif // HAVE_BAGL

#ifdef HAVE_TINY_COROUTINE

/* ----------------------------------------------------------------------- */
/* -                            CO ROUTINES                              - */
/* ----------------------------------------------------------------------- */

/**
 * Coroutine entry function. Called when the task is run first
 */
typedef void (*tcr_entry_function_t)(void);

void tcr_init(void);

#define TCR_FLAG_PRIORITY_MAX 0x0
#define TCR_FLAG_PRIORITY_MIN 0xF
void tcr_add(unsigned int priority, unsigned int stack_ptr,
             unsigned int stack_size, tcr_entry_function_t coroutine_entry);
void tcr_harakiri(void);
void tcr_yield(void);
void tcr_start(void);

#endif // HAVE_TINY_COROUTINE

/* ----------------------------------------------------------------------- */
/*   -                            HELPERS                                - */
/* ----------------------------------------------------------------------- */

#define OS_PARSE_BERTLV_OFFSET_COMPARE_WITH_BUFFER 0x80000000UL
#define OS_PARSE_BERTLV_OFFSET_GET_LENGTH 0x40000000UL

unsigned int os_parse_bertlv(unsigned char *mem, unsigned int mem_len,
                             unsigned int *tlv_instance_offset,
                             unsigned int tag, unsigned int offset,
                             void **buffer, unsigned int maxlength);

#ifdef BOLOS_DEBUG
#ifdef TARGET_NANOX
SYSCALL void trigger_gpio3(unsigned int val);
SUDOCALL void l(char *fmt, unsigned int i);
#endif // TARGET_NANOX
#endif // BOLOS_DEBUG

/* ----------------------------------------------------------------------- */
/*   -                            I/O I2C                                - */
/* ----------------------------------------------------------------------- */

#ifdef HAVE_IO_I2C

#define IO_I2C_SPEED_STD 0
#define IO_I2C_SPEED_FAST 1
#define IO_I2C_SPEED_FASTPLUS 2
#define IO_I2C_SPEED_HS 3
#define IO_I2C_MASTER 0x80
/**
 * Configure the I2C peripheral.
 * @param speed_and_master enables to set the bus speed. And to select if the
 * peripheral will act as master (issuing Start and Stop condition upon need) or
 * slave mode.
 * @param address In master mode, this parameter sets the target I2C device's
 * address. In slave mode, the address is the desired I2C bus address for the
 * interface. The address is always a 7bit address (excluding the transfer
 * direction bit).
 */
SYSCALL void io_i2c_setmode(unsigned int speed_and_master,
                            unsigned int address);

/**
 * Setup the I2C peripheral for:
 * - In slave mode, receiving a WRITE transaction of maxlength bytes at most.
 * Upon WRITE transaction end, an SEPROXYHAL_TAG_I2C_EVENT is issued with the
 * received data. It has to be received through ::io_seph_recv.
 * - In master mode, this call is nop.
 */
SYSCALL void io_i2c_prepare(unsigned int maxlength);

#define IO_I2C_FLAGS_READ 0
#define IO_I2C_FLAGS_WRITE 1
#define IO_I2C_FLAGS_START 2
#define IO_I2C_FLAGS_STOP 4
/**
 * Request to execute a transfer:
 * - In slave mode, this call is non-blocking. It only enables to reply to a
 * READ transaction of at most length bytes. After the Stop condition is issued
 * from the master, a SEPROXYHAL_TAG_I2C_EVENT event containing the effectively
 * transferred length is issued and can be retrieved through ::io_seph_recv. To
 * restart or continue the transfer requires another call to ::io_i2c_xfer.
 * - In master mode, this call is blocking and triggers the transaction as
 * requested through the flags parameter. The READ or WRITE transaction will
 * place or transmit data from the given buffer and length. Depending on the
 * passed start/stop flags, corresponding bus condition are executed.
 */
SYSCALL void io_i2c_xfer(void *buffer PLENGTH(length), unsigned int length,
                         unsigned int flags);

#ifndef BOLOS_RELEASE
SYSCALL void io_i2c_dumpstate(void);
#endif // BOLOS_RELEASE


#ifndef SYSCALL_GENERATE
// #include "syscalls.h"
#endif // SYSCALL_GENERATE

#endif // OS_H
