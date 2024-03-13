# Installation

Use `pnpm install`

# Scripts

`pnpm start` to run locally

`pnpm build` to run

# How to use

Edit the script defaults and generate address 1 time (see console output)

*NOTE* default address generated is for Ethereum unless you specify `chain: 'bitcoin'` in your iframe message.

Or embed as an iframe and use in BOS component like this:

```js
// pre-kdf step
const mpcContract = `multichain-testnet-2.testnet`;
const publicKey = Near.view(mpcContract, "public_key");
const accountId = "md1.testnet";
const path = ",bitcoin,1";

<iframe
	src={"https://near-mpc-kdf-iframe.pages.dev/"}
	message={state.message}
	onMessage={(res) => {
	if (res.loaded) {
		State.update({
		message: { publicKey, accountId, path, chain: 'bitcoin' },
		});
	}
	if (res.address) {
		State.update({
		address: res.address,
		});
	}
	}}
/>
```