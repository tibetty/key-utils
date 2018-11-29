"use strict";

const keyUtils = (() => {
	function ku$assert(condition, errMsg) {
		if (!condition) {
			throw Error(errMsg);
		}
	}
	async function ku$ConvertKeyPair(keypair, extractable, srcAlgoName, dstAlgoName, pkOps, skOps) {
		const errMessages = [
			'Not a valid key pair',
			'Key pair is not extractable',
			'Web Crypto is not available'
		];

		let pk = keypair.publicKey, sk = keypair.privateKey;
		ku$assert(pk !== null && sk !== null, errMessages[0]);
		ku$assert(pk.algorithm !== null && pk.algorithm.name === srcAlgoName && sk.algorithm !== null && sk.algorithm.name === srcAlgoName, errMessages[0]);
		ku$assert(pk.extractable && sk.extractable, errMessages[1]);
		ku$assert(crypto !== null && crypto.subtle !== null, errMessages[2]);
		const subtle = crypto.subtle;
		extractable = extractable || false;
		let publicKey = await subtle.importKey('raw', await subtle.exportKey('raw', pk), {
				name: dstAlgoName,
				namedCurve: pk.algorithm.namedCurve
			},
			extractable,
			pkOps
		);
		let privateKey = await subtle.importKey('jwk', await Object.assign(await subtle.exportKey('jwk', sk), {key_ops: skOps}), {
				name: dstAlgoName,
				namedCurve: sk.algorithm.namedCurve
			},
			extractable,
			skOps
		);	
		return {publicKey, privateKey};
	}

	return {
		ecdhToEcdsa: async (keypair, extractable) => await ku$ConvertKeyPair(keypair, extractable, 'ECDH', 'ECDSA', ['verify'], ['sign']),
		ecdsaToEcdh: async (keypair, extractable) => await ku$ConvertKeyPair(keypair, extractable, 'ECDSA', 'ECDH', [], ['deriveBits', 'deriveKey'])
	};
})();