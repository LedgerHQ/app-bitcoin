"""
*******************************************************************************    
*   BTChip Bitcoin Hardware Wallet Python API
*   (c) 2014 BTChip - 1BTChip7VfTnrPra5jqci7ejnMguuHogTn
*   
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*   Unless required by applicable law or agreed to in writing, software
*   distributed under the License is distributed on an "AS IS" BASIS,
*   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*   limitations under the License.
********************************************************************************
"""

from btchip.btchip import *
import sys
import binascii

if len(sys.argv) < 2:
	print("Usage : %s script to run" % sys.argv[0])
	sys.exit(2)

dongle = getDongle(True)

scriptFile = open(sys.argv[1], "r")
line = scriptFile.readline()
while line:	
	if (len(line) == 0) or (line[0] == '#') or (line.find('[') >= 0) or (line.find(']') >= 0):
		line = scriptFile.readline()
		continue
	line = line.replace('\"', '')
	line = line.replace(',', '')
	cancelResponse = (line[0] == '!')
	timeout = 10000
	if cancelResponse:
		line = line[1:]
		timeout = 1
	try:
		line = line.strip()		
		if len(line) == 0:
			continue
		dongle.exchange(bytearray(binascii.unhexlify(line)), timeout)
	except Exception:
		if cancelResponse:
			pass
		else:
			raise
	line = scriptFile.readline()
scriptFile.close()
