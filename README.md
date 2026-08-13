# Universal Ethereum Signer

The Universal Ethereum Signer is a reference implementation for Ethereum hardware signers. 

This monorepo is opinionated towards Rust and the [Xous](https://github.com/betrusted-io/xous-core) ecosystem, reuse of existing well maintained libraries (such as [alloy](https://alloy.rs/)), and development fully driven by automatic programming.

## common-eth-signer 

This crate contains abstractions of the different Ethereum primitives needed for a wallet

It has no dependencies on Xous

## foundation-app-eth-signer

An implementation of the signer for [Foundation](https://foundation.xyz/) Passport Prime

In this version the signer is airgapped using [ERC-4527](https://github.com/ethereum/ercs/blob/master/ERCS/erc-4527.md) QR codes and implements "verifiable signing" using [ERC-8213](https://erc8213.eth.limo/) - it has no dependencies whatsoever on any external data source.  

Future versions will implement different bearers and optionally [Clear Signing](https://clearsigning.org/), with additional third party dependencies

## Security

See [SECURITY.md](SECURITY.md) for up to date information

At this time, this project has not yet been audited by a dedicated human. Use only with assets you can afford to lose.  
