/********************************************************************************
*   Ledger Communication toolkit
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

'use strict';

var Ledger3 = function(scrambleKey, timeoutSeconds) {
	this.scrambleKey = Buffer.from(scrambleKey, 'ascii');
	this.timeoutSeconds = timeoutSeconds;
}

Ledger3.wrapApdu = function(apdu, key) {
	var result = Buffer.alloc(apdu.length);
	for (var i=0; i<apdu.length; i++) {
		result[i] = apdu[i] ^ key[i % key.length];
	}
	return result;
}

// Convert from normal to web-safe, strip trailing "="s
Ledger3.webSafe64 = function(base64) {
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Convert from web-safe to normal, add trailing "="s
Ledger3.normal64 = function(base64) {
    return base64.replace(/\-/g, '+').replace(/_/g, '/') + '=='.substring(0, (3*base64.length)%4);
}

Ledger3.prototype.u2fCallback = function(response, deferred, statusList) {
	if (typeof response['signatureData'] != "undefined") {
		var data = Buffer.from((Ledger3.normal64(response['signatureData'])), 'base64');
		if (typeof statusList != "undefined") {
			var statusFound = false;
			var sw = data.readUInt16BE(data.length - 2);
			for (var index in statusList) {
				if (statusList[index] == sw) {
					statusFound = true;
					break;
				}
			}
			if (!statusFound) {
				deferred.reject("Invalid status " + sw.toString(16));
			}
		}
		deferred.resolve(data.toString('hex', 5));
	}
	else {
		deferred.reject(response);
	}
}

Ledger3.prototype.exchange = function(apduHex, statusList) {
	var apdu = Buffer.from(apduHex, 'hex');
	var keyHandle = Ledger3.wrapApdu(apdu, this.scrambleKey);
	var challenge = Buffer.from("0000000000000000000000000000000000000000000000000000000000000000", 'hex');
	var key = {};
	key['version'] = 'U2F_V2';
	key['keyHandle'] = Ledger3.webSafe64(keyHandle.toString('base64'));	
	var self = this;
	var deferred = Q.defer();
	var localCallback = function(result) {
		self.u2fCallback(result, deferred, statusList);
	}
	u2f.sign(location.origin, Ledger3.webSafe64(challenge.toString('base64')), [key], localCallback, this.timeoutSeconds);	
	return deferred.promise;
}

module.exports = Ledger3
