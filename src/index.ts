import { base_decode } from 'near-api-js/lib/utils/serialize';
import { ec as EC } from 'elliptic';
import BN from 'bn.js';
import keccak from 'keccak';
import hash from 'hash.js';
import bs58check from 'bs58check';
import * as bitcoin from 'bitcoinjs-lib';

function najPublicKeyStrToUncompressedHexPoint(najPublicKeyStr) {
  return (
    '04' +
    Buffer.from(base_decode(najPublicKeyStr.split(':')[1])).toString('hex')
  );
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
  path = '',
) {
  const ec = new EC('secp256k1');
  let scalar = await sha256Hash(
    `near-mpc-recovery v0.1.0 epsilon derivation:${signerId},${path}`,
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

  return (
    '04' +
    (newPublicKeyPoint.getX().toString('hex').padStart(64, '0') +
      newPublicKeyPoint.getY().toString('hex').padStart(64, '0'))
  );
}

function uncompressedHexPointToEvmAddress(uncompressedHexPoint) {
  const address = keccak('keccak256')
    .update(Buffer.from(uncompressedHexPoint.substring(2), 'hex'))
    .digest('hex');

  // Ethereum address is last 20 bytes of hash (40 characters), prefixed with 0x
  return '0x' + address.substring(address.length - 40);
}

async function uncompressedHexPointToBtcAddress(publicKeyHex, networkByte) {
  // Step 1: SHA-256 hashing of the public key
  const publicKeyBytes = Uint8Array.from(Buffer.from(publicKeyHex, 'hex'));

  const sha256HashOutput = await crypto.subtle.digest(
    'SHA-256',
    publicKeyBytes,
  );

  // Step 2: RIPEMD-160 hashing on the result of SHA-256
  const ripemd160 = hash
    .ripemd160()
    .update(Buffer.from(sha256HashOutput))
    .digest();

  // Step 3: Adding network byte (0x00 for Bitcoin Mainnet)
  const networkByteAndRipemd160 = Buffer.concat([
    networkByte,
    Buffer.from(ripemd160),
  ]);

  // Step 4: Base58Check encoding
  const address = bs58check.encode(networkByteAndRipemd160);

  return address;
}

async function generateAddress({ publicKey, accountId, path, chain }) {
  const childPublicKey = await deriveChildPublicKey(
    najPublicKeyStrToUncompressedHexPoint(publicKey),
    accountId,
    path,
  );
  if (!chain) chain = 'ethereum';
  const chains = {
    btc: () =>
      uncompressedHexPointToBtcAddress(childPublicKey, Buffer.from([0x00])),
    bitcoin: () =>
      uncompressedHexPointToBtcAddress(childPublicKey, Buffer.from([0x6f])),
    ethereum: () => uncompressedHexPointToEvmAddress(childPublicKey),
  };
  return {
    address: await chains[chain](),
    publicKey: childPublicKey,
  };
}

// for bitcoin

const btcrpc = `https://blockstream.info/testnet/api`;
const fetchJson = (url) => fetch(url).then((r) => r.json());

async function fetchTransaction(transactionId): Promise<bitcoin.Transaction> {
  const data = await fetchJson(`${btcrpc}/tx/${transactionId}`);
  const tx = new bitcoin.Transaction();

  tx.version = data.version;
  tx.locktime = data.locktime;

  data.vin.forEach((vin) => {
    const txHash = Buffer.from(vin.txid, 'hex').reverse();
    const vout = vin.vout;
    const sequence = vin.sequence;
    const scriptSig = vin.scriptsig
      ? Buffer.from(vin.scriptsig, 'hex')
      : undefined;
    tx.addInput(txHash, vout, sequence, scriptSig);
  });

  data.vout.forEach((vout) => {
    const value = vout.value;
    const scriptPubKey = Buffer.from(vout.scriptpubkey, 'hex');
    tx.addOutput(scriptPubKey, value);
  });

  data.vin.forEach((vin, index) => {
    if (vin.witness && vin.witness.length > 0) {
      const witness = vin.witness.map((w) => Buffer.from(w, 'hex'));
      tx.setWitness(index, witness);
    }
  });

  return tx;
}

async function createBTC(data) {
  console.log('createBTC called', data);
  const { address, publicKey, sats, to, sig } = data;

  const res = await fetchJson(`${btcrpc}/address/${address}/utxo`);
  let utxos = res.map((utxo) => ({
    txid: utxo.txid,
    vout: utxo.vout,
    value: utxo.value,
  }));

  const psbt = new bitcoin.Psbt({ network: bitcoin.networks.testnet });
  let totalInput = 0;

  // ONLY SIGNING 1 UTXO PER TX IN BOS COMPONENT
  let maxValue = 0;
  utxos.forEach((utxo) => {
    // ONLY SIGNING THE MAX VALUE UTXO
    if (utxo.value > maxValue) maxValue = utxo.value;
  });
  utxos = utxos.filter((utxo) => utxo.value === maxValue);

  await Promise.all(
    utxos.map(async (utxo) => {
      totalInput += utxo.value;

      const transaction = await fetchTransaction(utxo.txid);
      let inputOptions;
      if (transaction.outs[utxo.vout].script.includes('0014')) {
        inputOptions = {
          hash: utxo.txid,
          index: utxo.vout,
          witnessUtxo: {
            script: transaction.outs[utxo.vout].script,
            value: utxo.value,
          },
        };
      } else {
        inputOptions = {
          hash: utxo.txid,
          index: utxo.vout,
          nonWitnessUtxo: Buffer.from(transaction.toHex(), 'hex'),
        };
      }

      psbt.addInput(inputOptions);
    }),
  );

  psbt.addOutput({
    address: to,
    value: sats,
  });

  const feeRate = await fetchJson(`${btcrpc}/fee-estimates`);
  const estimatedSize = utxos.length * 148 + 2 * 34 + 10;
  const fee = estimatedSize * (feeRate[6] + 3);
  console.log('btc fee', fee);
  console.log(
    'utxo to sign',
    utxos.find((utxo) => utxo.value === maxValue),
  );
  const change = totalInput - sats - fee;
  console.log('change leftover', change);
  if (change > 0) {
    psbt.addOutput({
      address: address,
      value: change,
    });
  }

  // get transaction hashes to sign
  const btcHashes = [];
  let keyPair = {
    publicKey: Buffer.from(publicKey, 'hex'),
    sign: async (transactionHash) => {
      // console.log('prepared btc hash', '0x' + transactionHash.toString('hex'))
      btcHashes.push('0x' + transactionHash.toString('hex'));
      return null;
    },
  };

  // if we already have signature values, sign inputs
  // TODO handle more than one sig input
  if (sig) {
    keyPair = {
      publicKey: Buffer.from(publicKey, 'hex'),
      sign: async (transactionHash) => {
        console.log('signing tx hash', '0x' + transactionHash.toString('hex'));
        const r = sig.r.substring(2).padStart(64, '0');
        const s = sig.s.substring(2).padStart(64, '0');
        return Buffer.from(r + s, 'hex');
      },
    };
  }

  await Promise.all(
    utxos.map(async (_, index) => {
      try {
        await psbt.signInputAsync(index, keyPair);
      } catch (e) {
        console.warn('not signed');
      }
    }),
  );

  if (!sig) {
    return window.top.postMessage({ btcHashes }, '*');
  }

  // broadcast tx
  psbt.finalizeAllInputs();
  // console.log('bitcoin tx payload', psbt.extractTransaction().toHex())

  let btcTxId;
  try {
    const res = await fetch(`https://corsproxy.io/?${btcrpc}/tx`, {
      method: 'POST',
      body: psbt.extractTransaction().toHex(),
    });

    console.log('bitcoin tx broadcasted', res);

    if (res.status === 200) {
      btcTxId = await res.text();
      console.log('bitcoin txid', btcTxId);
      window.top.postMessage({ btcTxId }, '*');
    }
  } catch (e) {
    console.log('error broadcasting bitcoin tx', JSON.stringify(e));
  }
}

export async function handleMessage(event) {
  const data = event.data;
  if (!data) return console.warn('handleMessage: no data');

  if (data.createBTC) return createBTC(data);

  // everything else is a KDF step

  if (!data.publicKey || !data.accountId || !data.path) return;
  console.log('KDF args', data);
  if (data.debug) {
    return console.log(
      'DEBUG OUTPUT',
      'Ethereum Address',
      await generateAddress(data),
    );
  }
  const res = await generateAddress(data);
  console.log('address', res.address);
  window.top.postMessage(res, '*');
}

// testing locally
function debug() {
  handleMessage({
    data: {
      createBTC: true,
      address: 'n47ZTPR31eyi5SZNMbZQngJ4wiZMxXw1bS',
      to: 'n47ZTPR31eyi5SZNMbZQngJ4wiZMxXw1bS',
      sats: 1,
      sig: {
        r: '0x8A091860F21DE08A6B03D9570E2FA88FB0180C8F399A509FF84267B93884476B'.toLowerCase(),
        s: '0x1456A6BEEF1718EE3220E0A08890AABDF4DF1C6F9B1E332231A0E2A1A9C82DB7'.toLowerCase(),
      },
      publicKey:
        '0438e7f8839e6010997540c903edf07c1b3153ddbfa8c142d2dcf3b6400d27344b5fe97e02bd31000f0606da4731b2224f6c8fa6e49c995a6056a21f68bf5f1788',
    },
  });
  // debug kdf
  // handleMessage({
  //   publicKey:`secp256k1:4HFcTSodRLVCGNVcGc4Mf2fwBBBxv9jxkGdiW2S2CA1y6UpVVRWKj6RX7d7TDt65k2Bj3w9FU4BGtt43ZvuhCnNt`,
  //   accountId: `md1.testnet`,
  //   path: `ethereum,1`,
  //   debug: true,
  // })
}
// debug()

// iframe
window.top.postMessage(
  {
    loaded: true,
  },
  '*',
);
window.addEventListener('message', handleMessage, false);
