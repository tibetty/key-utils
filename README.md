# key-utils

A WebCrypto key utility which can convert keys between ECDH & ECDSA right now - more functions to be discovered and added

## Motivation

In many situations (esp. blockchain related ones), we need to maintain ONE keypair for both key agreement(ECDH)/secured data exchange (ECIES) and identity verification (ECDSA) purposes, which is also practical theoretically, but the encapsulation of WebCrypto makes it very hard to implement. I had figured out a polyfill to enable the very niche usage.

## Usage

```html
...
<script src="/your/path/to/key-utils.js"></script>
...
```

```js
let xkp = await crypto.subtle.generateKey({
		name: 'ECDH',
		namedCurve: 'P-256'
	},
	true,
	['deriveBits', 'deriveKey']
);

// you can use xkp for key agreement/data exchange
let dkp = await keyUtils.ecdhToEcdsa(xkp);

let message = new TextEncoder('utf-8').encode('The message you want to sign');
let sig = await crypto.subtle.sign({
		name: 'ECDSA',
		hash: {name: 'SHA-256'}
	}, dkp.privateKey, message
);

let result = await crypto.subtle.verify({
		name: 'ECDSA',
		hash: {name: 'SHA-256'}
	}, dkp.publicKey, sig, message
);
console.log(result);
```

## Dependencies
Browser with ES5 support

## License
Written in 2018 by tibetty <xihua.duan@gmail.com>
