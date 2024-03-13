import { base_decode } from 'near-api-js/lib/utils/serialize';
import { ec as EC } from 'elliptic';
import BN from 'bn.js';
import keccak from 'keccak';
import hash from 'hash.js';
import bs58check from 'bs58check';

function najPublicKeyStrToUncompressedHexPoint(najPublicKeyStr) {
  return '04' + Buffer.from(base_decode(najPublicKeyStr.split(':')[1])).toString('hex');
}

async function sha256Hash(str) {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);

  const hashBuffer = await crypto.subtle.digest('SHA-256', data);

  const hashArray = [...new Uint8Array(hashBuffer)];
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

function sha256StringToScalarLittleEndian(hashString) {
  const littleEndianString = hashString.match(/../g).reverse().join('');

  const scalar = new BN(littleEndianString, 16);

  return scalar;
}

async function deriveChildPublicKey(
  parentUncompressedPublicKeyHex,
  signerId,
  path = ''
) {
  const ec = new EC('secp256k1');
  let scalar = await sha256Hash(
    `near-mpc-recovery v0.1.0 epsilon derivation:${signerId},${path}`
  );
  scalar = sha256StringToScalarLittleEndian(scalar);

  const x = parentUncompressedPublicKeyHex.substring(2, 66);
  const y = parentUncompressedPublicKeyHex.substring(66);

  // Create a point object from X and Y coordinates
  const oldPublicKeyPoint = ec.curve.point(x, y);

  // Multiply the scalar by the generator point G
  const scalarTimesG = ec.g.mul(scalar);

  // Add the result to the old public key point
  const newPublicKeyPoint = oldPublicKeyPoint.add(scalarTimesG);

  return '04' + (
    newPublicKeyPoint.getX().toString('hex').padStart(64, '0') +
    newPublicKeyPoint.getY().toString('hex').padStart(64, '0')
  );
}

function uncompressedHexPointToEvmAddress(uncompressedHexPoint) {
  const address = keccak('keccak256')
    .update(Buffer.from(uncompressedHexPoint.substring(2), 'hex'))
    .digest('hex');
  
  // Ethereum address is last 20 bytes of hash (40 characters), prefixed with 0x
  return '0x' + address.substring(address.length - 40)
}

async function uncompressedHexPointToBtcAddress(publicKeyHex) {
  // Step 1: SHA-256 hashing of the public key
  const publicKeyBytes = Uint8Array.from(Buffer.from(publicKeyHex, 'hex'));

  const sha256HashOutput = await crypto.subtle.digest(
    'SHA-256',
    publicKeyBytes
  );

  // Step 2: RIPEMD-160 hashing on the result of SHA-256
  const ripemd160 = hash
    .ripemd160()
    .update(Buffer.from(sha256HashOutput))
    .digest();

  // Step 3: Adding network byte (0x00 for Bitcoin Mainnet)
  const networkByte = Buffer.from([0x00]);
  const networkByteAndRipemd160 = Buffer.concat([
    networkByte,
    Buffer.from(ripemd160)
  ]);

  // Step 4: Base58Check encoding
  const address = bs58check.encode(networkByteAndRipemd160);

  return address;
}

async function generateAddress({
	publicKey,
	accountId,
	path,
  chain,
}) {
	const childPublicKey = await deriveChildPublicKey(
		najPublicKeyStrToUncompressedHexPoint(publicKey),
		accountId,
		path,
	)
  return chain === 'bitcoin' ? uncompressedHexPointToBtcAddress(childPublicKey) : uncompressedHexPointToEvmAddress(childPublicKey)
}

export async function handleMessage(event) {
	const data = event.data
	if (!data.publicKey || !data.accountId || !data.path) return
	console.log("KDF args", data)
	if (data.debug) {
		return console.log('DEBUG OUTPUT', 'Ethereum Address', await generateAddress(data))
	}
  const address = await generateAddress(data)
  console.log('address', address)
	window.top.postMessage({
		address
	}, "*")
}

// testing locally
// handleMessage({
// 	data: {
// 		publicKey:`secp256k1:4HFcTSodRLVCGNVcGc4Mf2fwBBBxv9jxkGdiW2S2CA1y6UpVVRWKj6RX7d7TDt65k2Bj3w9FU4BGtt43ZvuhCnNt`,
// 		accountId: `md1.testnet`,
// 		path: `ethereum,1`,
// 		debug: true,
// 	}
// })

// iframe
window.top.postMessage({
  loaded: true
}, "*");
window.addEventListener("message", handleMessage, false);






