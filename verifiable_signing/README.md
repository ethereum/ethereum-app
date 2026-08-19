# Verifiable Signing

Verifiable Signing (_Cypherpunk Signing_ ?) is an attempt at finding a catchy marketing name for secure signers implementing [ERC-8213](https://erc8213.eth.limo/)

Verifiable Signing doesn't compete with [Clear Signing](https://clearsigning.org/) - it provides a minimalistic and definitive set of definitions for secure signers to provide information that can be used to implement and verify Clear Signing externally. Secure Signers can of course still implement Clear Signing internally, and optionally implement Verifiable Signing.

## Verifiable Signing in a couple seconds

Verifiable Signing provides the following definitions for hashes to be displayed when signing  :

  * A transaction : the **Calldata Digest** identifying the data parameters of the transaction. The remaninig parameters (destination, amount and fees paid, chainId) can be verified directly on the secure signer. 
  * A formatted ([EIP-712](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md)) message : the **EIP-712 Digest** identifying the message to be signed, as well as the **Domain Hash** and **Message Hash** that got popular thanks|due to Ledger Nano S.
  * An unformatted ([ERC-191](https://github.com/ethereum/ercs/blob/master/ERCS/erc-191.md)) message : the **ERC-191 Digest** identifying the message to be signed. 

## Advantages of implementing Verifiable Signing for a secure signer

It's easy - if you can sign, you already compute those values. And if you have a screen, you can display them. Ideally as a QR code for easy processing.

There are no external dependencies involved - Clear Signing requires to query external oracles or have built-in curated data.

## Disadvantages of only supporting Verifiable Signing for a secure signer

Transactions that have historically been easy to verify on secure signers such as ERC-20 transfers cannot be verified anymore without an external Clear Signing implementation since there is no token list anymore on the signer. 

## External Clear Signing implementations

The most popular implementation today is [Safe](https://safe.global) letting you verify the EIP-712 Digest (labeled as *SafeTxHash*)

This documentation will be extended with new tooling bridging Clear Signing and Verifiable Signing that you'll be able to run on your own terms being aware of the trade offs.
