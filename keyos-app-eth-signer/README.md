# Universal Ethereum Signer for KeyOS

This application is an implementation of the Universal Ethereum Signer for [Foundation](https://foundation.xyz/) KeyOS, running on Foundation Passport Prime

The signer is airgapped using [ERC-4527](https://github.com/ethereum/ercs/blob/master/ERCS/erc-4527.md) QR codes and implements [Verifiable Signing](../verifiable_signing/README.md) using [ERC-8213](https://erc8213.eth.limo/) - it has no dependencies whatsoever on any external data source.

## For users

### Downloading the application 

TBD, working on the distrbution channel

### Seed setup 

By default, the wallet will be using a BIP 32 seed which is unique to this application, derived from the device master seed (_AppSeed_). 

You can choose to import a BIP 39 seed in the Settings item of the application menu, choosing the "Recovery Phrase" option, and enter it there. This seed will be securely backed up by the Envoy phone companion application.

When using a BIP 39 seed, you can also use a passphrase, choosing the "Apply Passphrase" item in the application menu.

### Accounts

To create an account select the "Create Account" item in the application menu. 

Keys are derived follwing the BIP 44 standard as m/60'/account'/0/index

Once the account is created, you can click on it and choose the following operations : 

* **Connect Wallet** : display an ERC-4527 crypto-hdkey QR code you can use to account this account to a compatible wallet
* **Verify Address** : scan an Ethereum address and check if it can be derived from this account (for the 50 first addresses)
* **Account Details** : Display the name, BIP 44 index and fingerprint of the main account and let you archive the account. You can then choose to restore it or delete it using the "View Archive" item in the application menu.

### Wallet Connectivity

Click on the account you want to connect and choose the "Connect Wallet" option

If ERC-4527 is not an option in the wallet, choose to connect a Keystone hardware wallet which uses the same standard

### Signing a transaction

Click the scan icon at the bottom right of the application and scan the ERC-4527 QR code

Check the transaction details and if the transaction contains data the ERC-8213 Calldata Digest 

If everything matches your expectations move bottom signature slider all the way to the right and scan the displayed ERC-4527 eth-signature QR code with the wallet

### Signing a typed message (EIP-712)

Click the scan icon at the bottom right of the application and scan the ERC-4527 QR code

Check the message data, and the EIP-712 Digest (or the Domain Hash and Message Hash) 

If everything matches your expectations move bottom signature slider all the way to the right and scan the displayed ERC-4527 eth-signature QR code with the wallet

### Signing a standard message (ERC-191)

Click the scan icon at the bottom right of the application and scan the ERC-4527 QR code

Check the message data, and the ERC-191 Digest if necessary

If everything matches your expectations move bottom signature slider all the way to the right and scan the displayed ERC-4527 eth-signature QR code with the wallet


## For developers

### Setting up KeyOS SDK

Install [KeyOS SDK](https://docs.foundation.xyz/developers/home/) following Foundation documentation

Generate a signing certificate with `foundation cert gen "<Your Name>"`

### Installing your certificate manually 

Copy `~/.foundation/signing/<identity>/certificate.crt` to Airlock (set it to R/W before) or a USB key

From the device install the certificate in Settings / Apps / Allowed Publishers / Add Publisher

### Building the application

Enter the SDK shell with `foundation develop`

Build the application with `foundation pack`

### Installing your application manually

Copy your generated `target/keyos/eth-signer.app` to Airlock (set it to R/W before) or a USB key

From the device install the application in Settings / Apps / Install App
