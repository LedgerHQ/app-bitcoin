/*******************************************************************************
*   Ledger App - Bitcoin Wallet
*   (c) 2016-2019 Ledger
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

#include "btchip_internal.h"

#define MAX_DEC_INPUT_SIZE 164
#define MAX_ENC_INPUT_SIZE 120

int btchip_decode_base58(const char *in, size_t length,
                         unsigned char *out, size_t *outlen) {
  unsigned char tmp[MAX_DEC_INPUT_SIZE];
  unsigned char buffer[MAX_DEC_INPUT_SIZE] = {0};
  unsigned char i;
  unsigned char j;
  unsigned char startAt;
  unsigned char zeroCount = 0;
  if ((length > MAX_DEC_INPUT_SIZE) || (length < 2)) {
    return -1;
  }
  os_memmove(tmp, in, length);
  PRINTF("To decode\n%.*H\n",length,tmp);
  for (i = 0; i < length; i++) {
    if (in[i] >= sizeof(BASE58TABLE)) {
      return -1;
    }
    tmp[i] = BASE58TABLE[(int)in[i]];
    if (tmp[i] == 0xff) {
      return -1;
    }
  }
  while ((zeroCount < length) && (tmp[zeroCount] == 0)) {
    ++zeroCount;
  }
  j = length;
  startAt = zeroCount;
  while (startAt < length) {
    unsigned short remainder = 0;
    unsigned char divLoop;
    for (divLoop = startAt; divLoop < length; divLoop++) {
      unsigned short digit256 = (unsigned short)(tmp[divLoop] & 0xff);
      unsigned short tmpDiv = remainder * 58 + digit256;
      tmp[divLoop] = (unsigned char)(tmpDiv / 256);
      remainder = (tmpDiv % 256);
    }
    if (tmp[startAt] == 0) {
      ++startAt;
    }
    buffer[--j] = (unsigned char)remainder;
  }
  while ((j < length) && (buffer[j] == 0)) {
    ++j;
  }
  length = length - (j - zeroCount);
  if (*outlen < length) {
    PRINTF("Decode overflow %d %d\n", length, *outlen);
    return -1;
  }

  os_memmove(out, buffer + j - zeroCount, length);
  PRINTF("Decoded\n%.*H\n",length,out);
  *outlen = length;
  return 0;
}

int btchip_encode_base58(const unsigned char *in, size_t length,
                         unsigned char *out, size_t *outlen) {
  unsigned char buffer[MAX_ENC_INPUT_SIZE * 138 / 100 + 1] = {0};
  size_t i = 0, j;
  size_t startAt, stopAt;
  size_t zeroCount = 0;
  size_t outputSize;

  if (length > MAX_ENC_INPUT_SIZE) {
    return -1;
  }

  PRINTF("Length to encode %d\n", length);
  PRINTF("To encode\n%.*H\n",length,in);

  while ((zeroCount < length) && (in[zeroCount] == 0)) {
    ++zeroCount;
  }

  outputSize = (length - zeroCount) * 138 / 100 + 1;
  stopAt = outputSize - 1;
  for (startAt = zeroCount; startAt < length; startAt++) {
    int carry = in[startAt];
    for (j = outputSize - 1; (int)j >= 0; j--) {
      carry += 256 * buffer[j];
      buffer[j] = carry % 58;
      carry /= 58;

      if (j <= stopAt - 1 && carry == 0) {
        break;
      }
    }
    stopAt = j;
  }

  j = 0;
  while (j < outputSize && buffer[j] == 0) {
    j += 1;
  }

  if (*outlen < zeroCount + outputSize - j) {
    *outlen = zeroCount + outputSize - j;
    return -1;
  }

  os_memset(out, BASE58ALPHABET[0], zeroCount);

  i = zeroCount;
  while (j < outputSize) {
    out[i++] = BASE58ALPHABET[buffer[j++]];
  }
  *outlen = i;
  PRINTF("Length encoded %d\n", i);
  PRINTF("Encoded\n%.*H\n",i,out);
  return 0;
}
