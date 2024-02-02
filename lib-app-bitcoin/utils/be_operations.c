#include "be_operations.h"

unsigned char transaction_amount_add_be(unsigned char *target,
                                        unsigned char *a,
                                        unsigned char *b) {
    unsigned char carry = 0;
    unsigned char i;
    for (i = 0; i < 8; i++) {
        unsigned short val = a[8 - 1 - i] + b[8 - 1 - i] + (carry ? 1 : 0);
        carry = (val > 255);
        target[8 - 1 - i] = (val & 255);
    }
    return carry;
}

unsigned char transaction_amount_sub_be(unsigned char *target,
                                        unsigned char *a,
                                        unsigned char *b) {
    unsigned char borrow = 0;
    unsigned char i;
    for (i = 0; i < 8; i++) {
        unsigned short tmpA = a[8 - 1 - i];
        unsigned short tmpB = b[8 - 1 - i];
        if (borrow) {
            if (tmpA <= tmpB) {
                tmpA += (255 + 1) - 1;
            } else {
                borrow = 0;
                tmpA--;
            }
        }
        if (tmpA < tmpB) {
            borrow = 1;
            tmpA += 255 + 1;
        }
        target[8 - 1 - i] = (unsigned char)(tmpA - tmpB);
    }

    return borrow;
}


