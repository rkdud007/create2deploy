use std::{env, fs, str::FromStr};

use alloy::{
    hex::FromHex,
    network::EthereumWallet,
    primitives::{Address, Bytes, B256},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
    sol,
    transports::http::reqwest::Url,
};
use clap::Parser;
use serde_json::{from_str, Value};
use thiserror::Error;
use ImmutableCreate2Factory::ImmutableCreate2FactoryInstance;

sol! {
    /**
 *Submitted for verification at Etherscan.io on 2023-02-23
*/

pragma solidity 0.5.10; // optimization enabled, 99999 runs, evm: petersburg


/**
 * @title Immutable Create2 Contract Factory
 * @author 0age
 * @notice This contract provides a safeCreate2 function that takes a salt value
 * and a block of initialization code as arguments and passes them into inline
 * assembly. The contract prevents redeploys by maintaining a mapping of all
 * contracts that have already been deployed, and prevents frontrunning or other
 * collisions by requiring that the first 20 bytes of the salt are equal to the
 * address of the caller (this can be bypassed by setting the first 20 bytes to
 * the null address). There is also a view function that computes the address of
 * the contract that will be created when submitting a given salt or nonce along
 * with a given block of initialization code.
 * @dev This contract has not yet been fully tested or audited - proceed with
 * caution and please share any exploits or optimizations you discover.
 */
#[sol(rpc, bytecode="0x60806040526004361061003f5760003560e01c806308508b8f1461004457806364e030871461009857806385cf97ab14610138578063a49a7c90146101bc575b600080fd5b34801561005057600080fd5b506100846004803603602081101561006757600080fd5b503573ffffffffffffffffffffffffffffffffffffffff166101ec565b604080519115158252519081900360200190f35b61010f600480360360408110156100ae57600080fd5b813591908101906040810160208201356401000000008111156100d057600080fd5b8201836020820111156100e257600080fd5b8035906020019184600183028401116401000000008311171561010457600080fd5b509092509050610217565b6040805173ffffffffffffffffffffffffffffffffffffffff9092168252519081900360200190f35b34801561014457600080fd5b5061010f6004803603604081101561015b57600080fd5b8135919081019060408101602082013564010000000081111561017d57600080fd5b82018360208201111561018f57600080fd5b803590602001918460018302840111640100000000831117156101b157600080fd5b509092509050610592565b3480156101c857600080fd5b5061010f600480360360408110156101df57600080fd5b508035906020013561069e565b73ffffffffffffffffffffffffffffffffffffffff1660009081526020819052604090205460ff1690565b600083606081901c33148061024c57507fffffffffffffffffffffffffffffffffffffffff0000000000000000000000008116155b6102a1576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260458152602001806107746045913960600191505060405180910390fd5b606084848080601f0160208091040260200160405190810160405280939291908181526020018383808284376000920182905250604051855195965090943094508b93508692506020918201918291908401908083835b6020831061033557805182527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe090920191602091820191016102f8565b51815160209384036101000a7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff018019909216911617905260408051929094018281037fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe00183528085528251928201929092207fff000000000000000000000000000000000000000000000000000000000000008383015260609890981b7fffffffffffffffffffffffffffffffffffffffff00000000000000000000000016602183015260358201969096526055808201979097528251808203909701875260750182525084519484019490942073ffffffffffffffffffffffffffffffffffffffff81166000908152938490529390922054929350505060ff16156104a7576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252603f815260200180610735603f913960400191505060405180910390fd5b81602001825188818334f5955050508073ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff161461053a576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260468152602001806107b96046913960600191505060405180910390fd5b50505073ffffffffffffffffffffffffffffffffffffffff8116600090815260208190526040902080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff001660011790559392505050565b6000308484846040516020018083838082843760408051919093018181037fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe001825280845281516020928301207fff000000000000000000000000000000000000000000000000000000000000008383015260609990991b7fffffffffffffffffffffffffffffffffffffffff000000000000000000000000166021820152603581019790975260558088019890985282518088039098018852607590960182525085519585019590952073ffffffffffffffffffffffffffffffffffffffff81166000908152948590529490932054939450505060ff909116159050610697575060005b9392505050565b604080517fff000000000000000000000000000000000000000000000000000000000000006020808301919091523060601b6021830152603582018590526055808301859052835180840390910181526075909201835281519181019190912073ffffffffffffffffffffffffffffffffffffffff81166000908152918290529190205460ff161561072e575060005b9291505056fe496e76616c696420636f6e7472616374206372656174696f6e202d20636f6e74726163742068617320616c7265616479206265656e206465706c6f7965642e496e76616c69642073616c74202d206669727374203230206279746573206f66207468652073616c74206d757374206d617463682063616c6c696e6720616464726573732e4661696c656420746f206465706c6f7920636f6e7472616374207573696e672070726f76696465642073616c7420616e6420696e697469616c697a6174696f6e20636f64652ea265627a7a723058202bdc55310d97c4088f18acf04253db593f0914059f0c781a9df3624dcef0d1cf64736f6c634300050a0032")]
contract ImmutableCreate2Factory {
  // mapping to track which addresses have already been deployed.
  mapping(address => bool) private _deployed;

  /**
   * @dev Create a contract using CREATE2 by submitting a given salt or nonce
   * along with the initialization code for the contract. Note that the first 20
   * bytes of the salt must match those of the calling address, which prevents
   * contract creation events from being submitted by unintended parties.
   * @param salt bytes32 The nonce that will be passed into the CREATE2 call.
   * @param initializationCode bytes The initialization code that will be passed
   * into the CREATE2 call.
   * @return Address of the contract that will be created, or the null address
   * if a contract already exists at that address.
   */
  function safeCreate2(
    bytes32 salt,
    bytes calldata initializationCode
  ) external payable containsCaller(salt) returns (address deploymentAddress) {
    // move the initialization code from calldata to memory.
    bytes memory initCode = initializationCode;

    // determine the target address for contract deployment.
    address targetDeploymentAddress = address(
      uint160(                    // downcast to match the address type.
        uint256(                  // convert to uint to truncate upper digits.
          keccak256(              // compute the CREATE2 hash using 4 inputs.
            abi.encodePacked(     // pack all inputs to the hash together.
              hex "ff",            // start with 0xff to distinguish from RLP.
              address(this),      // this contract will be the caller.
              salt,               // pass in the supplied salt value.
              keccak256(          // pass in the hash of initialization code.
                abi.encodePacked(
                  initCode
                )
              )
            )
          )
        )
      )
    );

    // ensure that a contract hasn't been previously deployed to target address.
    require(
      !_deployed[targetDeploymentAddress],
      "Invalid contract creation - contract has already been deployed."
    );

    // using inline assembly: load data and length of data, then call CREATE2.
    assembly {                                // solhint-disable-line
      let encoded_data := add(0x20, initCode) // load initialization code.
      let encoded_size := mload(initCode)     // load the init code's length.
      deploymentAddress := create2(           // call CREATE2 with 4 arguments.
        callvalue,                            // forward any attached value.
        encoded_data,                         // pass in initialization code.
        encoded_size,                         // pass in init code's length.
        salt                                  // pass in the salt value.
      )
    }

    // check address against target to ensure that deployment was successful.
    require(
      deploymentAddress == targetDeploymentAddress,
      "Failed to deploy contract using provided salt and initialization code."
    );

    // record the deployment of the contract to prevent redeploys.
    _deployed[deploymentAddress] = true;
  }

  /**
   * @dev Compute the address of the contract that will be created when
   * submitting a given salt or nonce to the contract along with the contract's
   * initialization code. The CREATE2 address is computed in accordance with
   * EIP-1014, and adheres to the formula therein of
   * `keccak256( 0xff ++ address ++ salt ++ keccak256(init_code)))[12:]` when
   * performing the computation. The computed address is then checked for any
   * existing contract code - if so, the null address will be returned instead.
   * @param salt bytes32 The nonce passed into the CREATE2 address calculation.
   * @param initCode bytes The contract initialization code to be used.
   * that will be passed into the CREATE2 address calculation.
   * @return Address of the contract that will be created, or the null address
   * if a contract has already been deployed to that address.
   */
  function findCreate2Address(
    bytes32 salt,
    bytes calldata initCode
  ) external view returns (address deploymentAddress) {
    // determine the address where the contract will be deployed.
    deploymentAddress = address(
      uint160(                      // downcast to match the address type.
        uint256(                    // convert to uint to truncate upper digits.
          keccak256(                // compute the CREATE2 hash using 4 inputs.
            abi.encodePacked(       // pack all inputs to the hash together.
              hex "ff",              // start with 0xff to distinguish from RLP.
              address(this),        // this contract will be the caller.
              salt,                 // pass in the supplied salt value.
              keccak256(            // pass in the hash of initialization code.
                abi.encodePacked(
                  initCode
                )
              )
            )
          )
        )
      )
    );

    // return null address to signify failure if contract has been deployed.
    if (_deployed[deploymentAddress]) {
      return address(0);
    }
  }

  /**
   * @dev Compute the address of the contract that will be created when
   * submitting a given salt or nonce to the contract along with the keccak256
   * hash of the contract's initialization code. The CREATE2 address is computed
   * in accordance with EIP-1014, and adheres to the formula therein of
   * `keccak256( 0xff ++ address ++ salt ++ keccak256(init_code)))[12:]` when
   * performing the computation. The computed address is then checked for any
   * existing contract code - if so, the null address will be returned instead.
   * @param salt bytes32 The nonce passed into the CREATE2 address calculation.
   * @param initCodeHash bytes32 The keccak256 hash of the initialization code
   * that will be passed into the CREATE2 address calculation.
   * @return Address of the contract that will be created, or the null address
   * if a contract has already been deployed to that address.
   */
  function findCreate2AddressViaHash(
    bytes32 salt,
    bytes32 initCodeHash
  ) external view returns (address deploymentAddress) {
    // determine the address where the contract will be deployed.
    deploymentAddress = address(
      uint160(                      // downcast to match the address type.
        uint256(                    // convert to uint to truncate upper digits.
          keccak256(                // compute the CREATE2 hash using 4 inputs.
            abi.encodePacked(       // pack all inputs to the hash together.
              hex "ff",              // start with 0xff to distinguish from RLP.
              address(this),        // this contract will be the caller.
              salt,                 // pass in the supplied salt value.
              initCodeHash          // pass in the hash of initialization code.
            )
          )
        )
      )
    );

    // return null address to signify failure if contract has been deployed.
    if (_deployed[deploymentAddress]) {
      return address(0);
    }
  }

  /**
   * @dev Determine if a contract has already been deployed by the factory to a
   * given address.
   * @param deploymentAddress address The contract address to check.
   * @return True if the contract has been deployed, false otherwise.
   */
  function hasBeenDeployed(
    address deploymentAddress
  ) external view returns (bool) {
    // determine if a contract has been deployed to the provided address.
    return _deployed[deploymentAddress];
  }

  /**
   * @dev Modifier to ensure that the first 20 bytes of a submitted salt match
   * those of the calling account. This provides protection against the salt
   * being stolen by frontrunners or other attackers. The protection can also be
   * bypassed if desired by setting each of the first 20 bytes to zero.
   * @param salt bytes32 The salt value to check against the calling address.
   */
  modifier containsCaller(bytes32 salt) {
    // prevent contract submissions from being stolen from tx.pool by requiring
    // that the first 20 bytes of the submitted salt match msg.sender.
    require(
      (address(bytes20(salt)) == msg.sender) ||
      (bytes20(salt) == bytes20(0)),
      "Invalid salt - first 20 bytes of the salt must match calling address."
    );
    _;
  }
}
}

/// create2 factory from 0age
const IMMUTABLE_CREATE2_FACTORY_ADDRESS: &str = "0x0000000000FFe8B47B3e2130213B802212439497";

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to calldata JSON file path
    #[arg(short, long)]
    calldata: String,
}

#[tokio::main]
async fn main() -> Result<(), Create2Error> {
    let args = Args::parse();

    let pkey = env::var("PRIVATE_KEY")?;
    let signer = PrivateKeySigner::from_str(&pkey).map_err(|_| Create2Error::PrivateKeyError)?;
    let wallet = EthereumWallet::from(signer);

    // parse from calldata file
    let calldata = fs::read_to_string(&args.calldata)?;
    let json: Value = from_str(&calldata).unwrap();
    let rpc_urls: Vec<String> = json["rpc_urls"]
        .as_array()
        .ok_or_else(|| Create2Error::JsonParseError)?
        .iter()
        .filter_map(|url| url.as_str().map(String::from))
        .collect();

    if rpc_urls.is_empty() {
        println!("❗️ provide at least 1 rpc provider url to deploy contract");
        return Err(Create2Error::JsonParseError);
    }

    let salt = json["salt"]
        .as_str()
        .ok_or_else(|| Create2Error::JsonParseError)?;
    let init_code = json["initCode"]
        .as_str()
        .ok_or_else(|| Create2Error::JsonParseError)?;

    for rpc_url in rpc_urls {
        println!("🔍 Target chain's rpc url: {}", rpc_url);
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(wallet.clone())
            .on_http(Url::from_str(&rpc_url).unwrap());

        let address = Address::from_str(IMMUTABLE_CREATE2_FACTORY_ADDRESS)
            .map_err(|e| Create2Error::AddressParseError(e.to_string()))?;
        let create2_factory = ImmutableCreate2FactoryInstance::new(address, &provider);

        // Check if information is correct
        let address = create2_factory
            .findCreate2Address(
                B256::from_str(salt).map_err(|e| Create2Error::HexParseError(e.to_string()))?,
                Bytes::from_hex(init_code)
                    .map_err(|e| Create2Error::HexParseError(e.to_string()))?,
            )
            .call()
            .await
            .map_err(|e| Create2Error::ContractError(e.to_string()))?;
        println!("👀 target address: {:?}", address.deploymentAddress);

        // Confirmation prompt
        println!("Is this the target address you want? (y/n):");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        if input.trim().to_lowercase() != "y" {
            return Err(Create2Error::UserAborted);
        }

        // CREATE2
        let builder = create2_factory.safeCreate2(
            B256::from_str(salt).map_err(|e| Create2Error::HexParseError(e.to_string()))?,
            Bytes::from_hex(init_code).map_err(|e| Create2Error::HexParseError(e.to_string()))?,
        );

        builder
            .call()
            .await
            .map_err(|e| Create2Error::ContractError(e.to_string()))?;
        let tx = builder
            .send()
            .await
            .map_err(|e| Create2Error::ContractError(e.to_string()))?
            .get_receipt()
            .await
            .map_err(|e| Create2Error::ContractError(e.to_string()))?;

        println!("🚀 safeCreate2 transaction: {:?}", tx);
    }

    println!("🎉 Deployed all target contracts using CREATE2");
    Ok(())
}

#[derive(Error, Debug)]
pub enum Create2Error {
    #[error("Environment variable error: {0}")]
    EnvError(#[from] env::VarError),

    #[error("Failed to read calldata file: {0}")]
    FileReadError(#[from] std::io::Error),

    #[error("Failed to parse JSON")]
    JsonParseError,

    #[error("Failed to parse private key")]
    PrivateKeyError,

    #[error("Failed to parse address: {0}")]
    AddressParseError(String),

    #[error("Failed to parse salt or init code: {0}")]
    HexParseError(String),

    #[error("Contract call failed: {0}")]
    ContractError(String),

    #[error("User aborted deployment")]
    UserAborted,
}
