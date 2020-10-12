#ifndef _BTCHIP_DISPLAY_VARIABLES_H_
#define _BTCHIP_DISPLAY_VARIABLES_H_

// A path contains 10 elements max, which max length in ascii is 1 whitespace + 10 char + optional quote "'" + "/" + \0"
#define MAX_DERIV_PATH_ASCII_LENGTH 1 + 10*(10+2) + 1
#define MAX_CHAR_PER_LINE 25

#if defined(TARGET_BLUE)
#include "qrcodegen.h"
#include "bagl.h"

union display_variables {
    struct {
        char addressSummary[40]; // beginning of the output address ... end of
        char fullAmount[65];     // full amount
        char fullAddress[65];
        // the address
        char feesAmount[40]; // fees
        char output_numbering[10];
    } tmp;

    struct {
        char addressSummary[MAX_CHAR_PER_LINE + 1];
        bagl_icon_details_t icon_details;
        unsigned int colors[2];
        unsigned char qrcode[qrcodegen_BUFFER_LEN_FOR_VERSION(3)];
    } tmpqr;

    struct {
        // A bip44 path contains 5 elements, which max length in ascii is 10 char + optional quote "'" + "/" + \0"
        char derivation_path [MAX_DERIV_PATH_ASCII_LENGTH];
    } tmp_warning;

    unsigned int dummy; // ensure the whole vars is aligned for the CM0 to
                        // operate correctly
};

#else

typedef struct swap_data_s {
        int was_address_checked;
        // total number of inputs to be signed
        int totalNumberOfInputs;
        // number of already signed input in the transaction, to compare with
        // totalNumberOfInputs and exit properly
        int alreadySignedInputs;
        unsigned char amount[8];
        unsigned char fees[8];
        char destination_address[65];
        unsigned char should_exit;
} swap_data_t;

union display_variables {
    struct {
        // char addressSummary[40]; // beginning of the output address ... end
        // of

        char fullAddress[65]; // the address
        char fullAmount[20];  // full amount
        char feesAmount[20];  // fees
    } tmp;

    struct {
        char derivation_path [MAX_DERIV_PATH_ASCII_LENGTH];
    } tmp_warning;

    swap_data_t swap_data;
};
#endif

extern union display_variables vars;

#endif
