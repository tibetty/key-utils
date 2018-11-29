"use strict";
let ku$assert = (condition, errMsg) => {
	if (!condition) {
		throw Error(errMsg);
	}
}

const keyUtils = {
	ecdhToEcdsa: async (keypair, extractable) => {
		let pk = keypair.publicKey, sk = keypair.privateKey;
		ku$assert(pk !== null && sk !== null, 'Not a valid key pair');
		ku$assert(pk.algorithm !== null && pk.algorithm.name === 'ECDH' && sk.algorithm !== null && sk.algorithm.name === 'ECDH', 'Not an ECDH key pair');
		ku$assert(pk.extractable && sk.extractable, 'Key pair is not extractable');
		ku$assert(crypto !== null && crypto.subtle !== null, 'Web crypto is not available');
		const subtle = crypto.subtle;
		extractable = extractable || false;
		let publicKey = await subtle.importKey('raw', await subtle.exportKey('raw', pk), {
				name: 'ECDSA',
				namedCurve: pk.algorithm.namedCurve
			},
			extractable,
			['verify']
		);
		let privateKey = await subtle.importKey('jwk', await Object.assign(await subtle.exportKey('jwk', sk), {key_ops: ['sign']}), {
				name: 'ECDSA',
				namedCurve: sk.algorithm.namedCurve
			},
			extractable,
			['sign']
		);	
		return {privateKey, publicKey};
	},

	ecdsaToEcdh: async (keypair, extractable) => {
		let pk = keypair.publicKey, sk = keypair.privateKey;
		ku$assert(pk !== null && sk !== null, 'Not a valid key pair');
		ku$assert(pk.algorithm !== null && pk.algorithm.name === 'ECDSA' && sk.algorithm !== null && sk.algorithm.name === 'ECDSA', 'Not an ECDSA key pair');
		ku$assert(pk.extractable && sk.extractable, 'Key pair is not extractable');
		ku$assert(crypto !== null && crypto.subtle !== null, 'Web crypto is not available');
		const subtle = crypto.subtle;
		extractable = extractable || false;
		let publicKey = await subtle.importKey('raw', await subtle.exportKey('raw', pk), {
				name: 'ECDH',
				namedCurve: pk.algorithm.namedCurve
			},
			extractable,
			[]
		);
		let privateKey = await subtle.importKey('jwk', await Object.assign(await subtle.exportKey('jwk', sk), {key_ops: ['deriveBits', 'deriveKey']}), {
				name: 'ECDH',
				namedCurve: sk.algorithm.namedCurve
			},
			extractable,
			['deriveBits', 'deriveKey']	
		);
		return {privateKey, publicKey};
	}
};