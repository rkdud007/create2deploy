# Create2 Deploy

A simple helper script for deploying contracts using CREATE2. This tool utilizes 0age's [Create2Factory Contract](https://github.com/0age/Pr000xy/blob/master/contracts/Create2Factory.sol) to pre-compute deterministic contract addresses based on salt values before deploy.

## Installation

Install from source:
```bash
cargo install --path .
```

## Usage

### Command Line Interface

```bash
create2deploy -h
Usage: create2deploy --rpc <RPC> --calldata <CALLDATA>

Options:
  -r, --rpc <RPC>            RPC Provider URL
  -c, --calldata <CALLDATA>  Path to calldata JSON file
  -h, --help                 Print help
  -V, --version              Print version
```

### Configuration

1. Create a `meta.json` file with your deployment parameters:
```json
{
    "salt": "0x..",
    "initCode": "deadbeaf.."
}
```

2. Set your `PRIVATE_KEY` environment variable before running the tool.

### Example

```
❯ create2deploy --rpc https://sepolia.optimism.io --calldata meta.json
👀 target address: 0xc8c8c8c8421e85597881ae753d040449e81e528a
Is this the target address you want? (y/n):
y
🚀 safeCreate2 transaction: TransactionReceipt { 
    // ... transaction details ... 
}
```


