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
❯ create2deploy -h
Usage: create2deploy --calldata <CALLDATA>

Options:
  -c, --calldata <CALLDATA>  Path to calldata JSON file path
  -h, --help                 Print help
  -V, --version              Print version
```

### Configuration

1. Create a `meta.json` file with your deployment parameters:
```json
{
     "rpc_urls": [
        "target-chain-rpc-url-1",
        "target-chain-rpc-url-2",
        ...
    ],
    "salt": "0x..",
    "initCode": "deadbeaf.."
}
```

2. Set your `PRIVATE_KEY` environment variable before running the tool.

### Example

```
❯ create2deploy -c meta.json
🔍 Target chain's rpc url: https://sepolia.base.org
👀 target address: 0xc8c8c8c8421e85597881ae753d040449e81e528a
Is this the target address you want? (y/n):
y
🚀 safeCreate2 transaction: TransactionReceipt { 
    // ... transaction details ... 
}
🔍 Target chain's rpc url: https://sepolia.optimism.io
👀 target address: 0xc8c8c8c8421e85597881ae753d040449e81e528a
Is this the target address you want? (y/n):
y
🚀 safeCreate2 transaction: TransactionReceipt { 
    // ... transaction details ... 
}
🎉 Deployed all target contracts using CREATE2
```


