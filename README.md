# key-utils

A WebCrypto key utility which can convert keys between ECDH & ECDSA right now - more functions to be discovered and added

## Motivation

In many situations (esp. blockchain related ones), we need to maintain ONE keypair for both key agreement (ECDH) / secured data exchanging (ECIES) and certification (ECDSA) purposes, which is also practical theoretically, but the encapsulation of WebCrypto makes it very hard to realize. This is some kind of polyfill to enable the very niche usage.

## CAUTION
Some people argue that this usage will compromise the security, so please DO ensure that your usage is unavoidable or secured enough before use this utility.

## Usage

`Add the reference in HTML file`
```html
...
<script src="/your/path/to/key-utils.js"></script>
...
```

`Now you can use this utility in your JavaScript code`
```js
let xkp = await crypto.subtle.generateKey({
		name: 'ECDH',
		namedCurve: 'P-256'
	},
	true,
	['deriveBits', 'deriveKey']
);
// By definition, you can use xkp for key agreement/data exchange

// Below code shows that how the same EC keys can be used for sign/verify with the help of this utility
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
