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

#pragma once

#include "os.h"
#include "cx.h"

unsigned char output_script_is_regular(unsigned char *buffer);
unsigned char output_script_is_p2sh(unsigned char *buffer);
unsigned char output_script_is_op_return(unsigned char *buffer);
unsigned char output_script_is_native_witness(unsigned char *buffer);
unsigned char output_script_is_op_create(unsigned char *buffer,
                                                size_t size);
unsigned char output_script_is_op_call(unsigned char *buffer,
                                                size_t size);

