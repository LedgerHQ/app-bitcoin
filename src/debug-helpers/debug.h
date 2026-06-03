#pragma once

/* SDK headers */
#include "os.h"

void debug_write(const char *buf);

int semihosted_printf(const char *format, ...);

#ifdef HAVE_SEMIHOSTED_PRINTF
// Route PRINTF to the semihosted implementation, instead of the default one
// that is routed through seproxyhal.
#undef PRINTF
#define PRINTF semihosted_printf
#endif

void print_stack_pointer(const char *file, int line, const char *func_name);

// Helper macro
#ifdef HAVE_PRINT_STACK_POINTER
#define PRINT_STACK_POINTER() print_stack_pointer(__FILE__, __LINE__, __func__)
#else
#define PRINT_STACK_POINTER()
#endif

static inline int print_error_info(const char *error_msg,
                                   const char *filename,
                                   int line,
                                   int retval) {
    (void) error_msg;
    (void) filename;
    (void) line;

    PRINTF("ERR (%s::%d): %s\n", filename, line, error_msg);
    return retval;
}

#define WITH_ERROR(retval, error_msg) print_error_info(error_msg, __FILE__, __LINE__, retval)