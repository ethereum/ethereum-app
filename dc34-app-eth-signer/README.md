# Universal Ethereum Signer for Xous on baosec / Def Con 34 badge

This application is an implementation of the Universal Ethereum Signer for [Xous](https://github.com/betrusted-io/xous-core), running on the [Def Con 34 badge](https://defcon.org/34b/) (baosec-lite)

The signer is airgapped using [ERC-4527](https://github.com/ethereum/ercs/blob/master/ERCS/erc-4527.md) QR codes and implements [Verifiable Signing](../verifiable_signing/README.md) using [ERC-8213](https://erc8213.eth.limo/) - it has no dependencies whatsoever on any external data source.

## For users

### Downloading the application

TBD, working on the distrbution channel

### Flashing the badge

Power cycle the badge and hold the first or second button when powering up, it should display "Update Mode" 

Connect the badge to your computer and copy the loader.uf2, swap.uf2 and xous.uf2 files to the storage device that was mounted

Make sure all data has been written correctly : if running on Linux use `sync`, on other OS unmount the storage device

Push the first or second button on the badge to commit

### Animated QR code scanning

At the moment QR code decoding is a bit slow so not suitable to scan animated QRs - it'll probably be hacked at some point though 

In the meantime you can use `tools/ur-bridge.html` to convert an animated QR to individual QR with a better formatting to be scanned by the badge, then send the sequence one by one. 

### Navigating the menus 

Use the jog dial to navigate the menu - push it to confirm

Push the jog dial to enter the main application menu

### Seed setup 

You can either generate a new BIP 39 seed or import one. 

To generate a new seed, use "New Seed" from the seed menu. This uses baochip TRNG. Write down the seed words **on paper** and select them back when requested. 

To import an existing seed, choose "Import seed" then add all words.

Do not use the QR code export/import features, which just use a base64 encoded version of the entropy.

After entering a seed, Select it from the seed menu to use it

### Accounts

To create an account, navigate to the "Accounts" menu and select the "New Account" item 

Keys are derived follwing the BIP 44 standard as m/60'/account'/0/index

Once the account is created, you can navigate to "Display accounts", click on the account you want and choose the following operations : 

* **Connect Wallet** : display an ERC-4527 crypto-hdkey QR code you can use to account this account to a compatible wallet
* **Verify Address** : scan an Ethereum address and check if it can be derived from this account (
for the 50 first addresses)
* **List Addresses** : display Ethereum addresses related to this account, display the address and associated QR code

### Wallet Connectivity

Click on the account you want to connect and choose the "Connect Wallet" option

If ERC-4527 is not an option in the wallet, choose to connect a Keystone hardware wallet which uses the same standard

### Signing a transaction

Select "Scan Request" in the application menu or press the middle button of the board, then scan each ERC-4527 QR code manually

You can choose the following items from the menu :
* **From** : Display the originating address of the transaction
* **To** : Display the destination address of the transaction
* **Amount** : Display the amount transferred in the transaction in ETH and Wei
* **Other infos** : Display the Chain Id and Max Fees
* **TX data** : Display the ERC-8213 Calldata Digest as text and QR code if the transaction has data
* **Sign** : Sign the transaction, you can scan the displayed ERC-4527 eth-signature QR code with the wallet

### Signing a typed message (EIP-712)

Select "Scan Request" in the application menu or press the middle button of the board, then scan each ERC-4527 QR code manually

You can choose the following items from the menu :
* **View message** : Navigate the full EIP-712 message as a JSON tree
* **EIP-712 Digest** : Display the ERC-8213 EIP-712 Digest as text and QR code
* **Domain Hash** : Display the ERC-8213 Domain Hash as text and QR code
* **Message Hash** : Display the ERC-8213 Message Hash as text and QR code
* **Sign** : Sign the typed message, you can scan the displayed ERC-4527 eth-signature QR code with the wallet

### Signing a standard message (ERC-191)

Select "Scan Request" in the application menu or press the middle button of the board, then scan each ERC-4527 QR code manually

You can choose the following items from the menu :
* **View message** : Display the message to be signed
* **EIP-191 Digest** : Display the ERC-8213 EIP-191 Digest as text and QR code
* **Sign** : Sign the message, you can scan the displayed ERC-4527 eth-signature QR code with the wallet

Check the message data, and the ERC-191 Digest if necessary

If everything matches your expectations move bottom signature slider all the way to the right and scan the displayed ERC-4527 eth-signature QR code with the wallet

## For developers

### Building the firmware

Clone Xous from https://github.com/betrusted-io/xous-core one directory above

Clone dc34-console from https://github.com/bunnie/dc34-console one directory above

Clone dc34-api from https://github.com/bunnie/dc34-api one directory above

The directory structure should then be 

```
 .
 ├── dc34-api
 ├── dc34-app-eth-signer
 ├── dc34-console
 └── xous-core
```

Things to do once :

* Install the UI Xous patches, from inside the 'xous-core' repository (those were originally applied at commit `f7d8c7e2a69db0f46f65e0aaeaf19a1bf7d94329`)

```shell
patch -p1 < ../dc34-app-eth-signer/xous-patches/0001-Add-bip39display.patch
patch -p1 < ../dc34-app-eth-signer/xous-patches/0002-modals-add-scrollable-notification-API.patch
```
   
* Install Xous toolkit : run `cargo xtask install-toolkit` inside the `xous-core` repository

Then run 

```shell
echo "===== Building Console ====="
(
    cd ../dc34-console &&
    cargo build --release --target riscv32imac-unknown-xous-elf --features board-baosec --features oem-baosec-lite --features bao1x --features utralib/bao1x &&
) || {
    echo "dc34-console build failed!"
    exit 1
}

echo "===== Building Eth Signer ====="
(
    cd ../dc34-app-eth-signer &&
    cargo build --release --target riscv32imac-unknown-xous-elf --features board-baosec &&
) || {
    echo "dc34-app-eth-signer build failed!"
    exit 1
}

cargo xtask baosec-lite ../dc34-console/target/riscv32imac-unknown-xous-elf/release/dc34-console~flash ../dc34-app-eth-signer/target/riscv32imac-unknown-xous-elf/release/dc34-eth-signer \
    --no-timestamp --feature usb --kernel-feature debug-proc --no-verify
```
