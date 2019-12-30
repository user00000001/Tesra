
<h1 align="center">Tesranode</h1>
<h4 align="center">Version 0.0.1</h4>

[![GoDoc](https://godoc.org/github.com/TesraSupernet/Tesra?status.svg)](https://godoc.org/github.com/TesraSupernet/Tesra)
[![Go Report Card](https://goreportcard.com/badge/github.com/TesraSupernet/Tesra)](https://goreportcard.com/report/github.com/TesraSupernet/Tesra)
[![Travis](https://travis-ci.com/TesraSupernet/Tesra.svg?branch=master)](https://travis-ci.com/TesraSupernet/Tesra)

English | [中文](README_CN.md)

Welcome to the official Go implementation of the [Tesranode](https://www.tesra.me) blockchain!

Tesranode is a high-performance public blockchain project and distributed trust collaboration platform. It is highly customizable and suitable for all kinds of business requirements. The Tesranode MainNet[for testing] was launched on December 31th, 2019.

As a public blockchain project, Tesranode is currently maintained by both the Tesranode core tech team and community members who can all support you in development. There are many available tools for use for development - SDKs, the SmartX IDE, Tesranode blockchain explorer and more.

New features are still being rapidly developed, therefore the master branch may be unstable. Stable versions can be found in the [releases section](https://github.com/TesraSupernet/Tesra/releases).

- [Features](#features)
- [Build Development Environment](#build-development-environment)
- [Download Tesranode](#download-tesranode)
    - [Download Release](#download-release)
    - [Build from Source Code](#build-from-source-code)
- [Run Tesranode](#run-tesranode)
    - [MainNet Sync Node](#mainnet-sync-node)
    - [TestNet Sync Node](#testnet-sync-node)
    - [Local PrivateNet](#local-privatenet)
    - [Run with Docker](#run-in-docker)
- [Examples](#examples)
    - [ONT transfer sample](#ont-transfer-sample)
    - [Query transfer status sample](#query-transfer-status-sample)
    - [Query account balance sample](#query-account-balance-sample)
- [Contributions](#contributions)
- [License](#license)

## Features

- Scalable lightweight universal smart contracts
- Scalable WASM contract support
- Cross-chain interactive protocol
- Multiple encryption algorithms supported
- Highly optimized transaction processing speed
- P2P link layer encryption (optional module)
- Multiple consensus algorithms supported (VBFT/DBFT/RBFT/SBFT/PoW)
- Quick block generation time (1-30 seconds)


## Build Development Environment
The requirements to build Tesranode are:

- [Golang](https://golang.org/doc/install) version 1.11 or later
- [Glide](https://glide.sh) (a third party package management tool for Golang)

## Download Tesranode

### Download Release
You can download a stable compiled version of the Tesranode node software by either:

- Downloading the latest Tesranode binary file with `curl https://dev.ont.io/tesranode_install | sh`.
- Downloading a specific version from the [release section](https://github.com/TesraSupernet/Tesra/releases).

### Build from Source Code
Alternatively, you can build the Tesranode application directly from the source code. Note that the code in the `master` branch may not be stable.

1) Clone the Tesranode repository into the appropriate `$GOPATH/src/github.com/ontio` directory:

```
$ git clone https://github.com/TesraSupernet/Tesra.git
```
or
```
$ go get github.com/TesraSupernet/Tesra
```

2) Fetch the dependent third party packages with [Glide](https://glide.sh):

```
$ cd $GOPATH/src/github.com/TesraSupernet/Tesra
$ glide install
```

3) If necessary, update the dependent third party packages with Glide:

```
$ cd $GOPATH/src/github.com/TesraSupernet/Tesra
$ glide update
```

4) Build the source code with make:

```
$ make all
```

After building the source code successfully, you should see two executable programs:

- `tesranode`: The primary Tesranode node application and CLI.
- `tools/sigsvr`: The Tesranode Signature Server, `sigsvr` - an RPC server for signing transactions. 

## Run Tesranode

The Tesranode CLI can run nodes for the MainNet, TestNet and local PrivateNet. Check out the [Tesranode CLI user guide](https://github.com/TesraSupernet/Tesra/blob/master/docs/specifications/cli_user_guide.md) for a full list of commands.

### MainNet Sync Node

You can run an Tesranode MainNet node built from the source code with:

 ``` shell
./tesranode
 ```

 To run it with a macOS release build:

 ``` shell
 ./tesranode-darwin-amd64
 ```

 To run it with a Windows release build:

 ``` shell
 start tesranode-windows-amd64.exe
 ```

### TestNet Sync Node

You can run an Tesranode TestNet node built from the source code with:

 ``` shell
./tesranode --networkid 2
 ```

 To run it with a macOS release build:

 ``` shell
 ./tesranode-darwin-amd64 --networkid 2
 ```

 To run it with a Windows release build:

 ``` shell
 start tesranode-windows-amd64.exe --networkid 2
 ```

### Local PrivateNet

The Tesranode CLI allows you to run a local PrivateNet on your computer. Before you can run the PrivateNet you will need to create a wallet file. A wallet file named `wallet.dat` can be generated by running

``` shell
./tesranode account add -d
```

To start the PrivateNet built from the source code with:

``` shell
./tesranode --testmode
```

Here's an example of the directory structure

``` shell
$ tree
└── tesranode
    ├── tesranode
    └── wallet.dat
```

To run it with a macOS release build:

``` shell
./tesranode-darwin-amd64 --testmode
```

To run it with a Windows release build:

``` shell
start tesranode-windows-amd64.exe --testmode
```

### Run with Docker

You can run the Tesranode node software with Docker.

1. Setup Docker on your computer
  - You will need the latest version of [Docker Desktop](https://www.docker.com/products/docker-desktop).

2. Make a Docker image
  - In the root directory of the source code, run `make docker` to make an Tesranode image.

3. Run the Tesranode image
  - Run the command `docker run TesraSupernet/Tesra` to start Tesranode
  - Run the command `docker run -ti TesraSupernet/Tesra` to start Tesranode and allow interactive keyboard input
  - If you need to keep the data generated by the image, refer to Docker's data persistence function
  - You can add arguments to the Tesranode command, such as with `docker run TesraSupernet/Tesra --networkid 2`.

## Examples

### ONT transfer sample
 -- from: transfer from； -- to: transfer to； -- amount: ONT amount；
```shell
 ./tesranode asset transfer  --from=ARVVxBPGySL56CvSSWfjRVVyZYpNZ7zp48 --to=AaCe8nVkMRABnp5YgEjYZ9E5KYCxks2uce --amount=10
```
If the asset transfer is successful, the result will display as follows:

```shell
Transfer ONT
  From:ARVVxBPGySL56CvSSWfjRVVyZYpNZ7zp48
  To:AaCe8nVkMRABnp5YgEjYZ9E5KYCxks2uce
  Amount:10
  TxHash:437bff5dee9a1894ad421d55b8c70a2b7f34c574de0225046531e32faa1f94ce
```
TxHash is the transfer transaction hash, and we can query a transfer result by the TxHash.
Due to block time, the transfer transaction will not be executed before the block is generated and added.

If you want to transfer ONG, just add --asset=ong flag.

Note that ONT is an integer and has no decimals, whereas ONG has 9 decimals. For detailed info please read [Everything you need to know about ONG](https://medium.com/tesranodenetwork/everything-you-need-to-know-about-ong-582ed216b870).

```shell
./tesranode asset transfer --from=ARVVxBPGySL56CvSSWfjRVVyZYpNZ7zp48 --to=ARVVxBPGySL56CvSSWfjRVVyZYpNZ7zp48 --amount=95.479777254 --asset=ong
```
If transfer of the asset succeeds, the result will display as follows:

```shell
Transfer ONG
  From:ARVVxBPGySL56CvSSWfjRVVyZYpNZ7zp48
  To:AaCe8nVkMRABnp5YgEjYZ9E5KYCxks2uce
  Amount:95.479777254
  TxHash:e4245d83607e6644c360b6007045017b5c5d89d9f0f5a9c3b37801018f789cc3
```

Please note, when you use the address of an account, you can use the index or label of the account instead. Index is the sequence number of a particular account in the wallet. The index starts from 1, and the label is the unique alias of an account in the wallet.

```shell
./tesranode asset transfer --from=1 --to=2 --amount=10
```

### Query transfer status sample

```shell
./tesranode info status <TxHash>
```

For Example:

```shell
./tesranode info status 10dede8b57ce0b272b4d51ab282aaf0988a4005e980d25bd49685005cc76ba7f
```

Result:

```shell
Transaction:transfer success
From:AXkDGfr9thEqWmCKpTtQYaazJRwQzH48eC
To:AYiToLDT2yZuNs3PZieXcdTpyC5VWQmfaN
Amount:10
```

### Query account balance sample

```shell
./tesranode asset balance <address|index|label>
```

For Example:

```shell
./tesranode asset balance ARVVxBPGySL56CvSSWfjRVVyZYpNZ7zp48
```

or

```shell
./tesranode asset balance 1
```
Result:
```shell
BalanceOf:ARVVxBPGySL56CvSSWfjRVVyZYpNZ7zp48
  ONT:989979697
  ONG:28165900
```

## Contributions

Contributors to Tesranode are very welcome! Before beginning, please take a look at our [contributing guidelines](CONTRIBUTING.md). You can open an issue by [clicking here](https://github.com/TesraSupernet/Tesra/issues/new).

If you have any issues getting setup, open an issue or reach out in the [Tesranode Discord](https://discordapp.com/invite/4TQujHj).

## License

The Tesranode source code is available under the [LGPL-3.0](LICENSE) license.
