#![allow(unused)]
use num_bigint::{BigUint,BigInt};
use num_traits::{FromPrimitive,ToPrimitive};
use byteorder::{BigEndian, ByteOrder , LittleEndian};
use std::{path::PathBuf, process::Command};
use sha2::{Sha256,Sha512};
use sha2::Digest;
use ripemd::Ripemd160;
use hmac::{Hmac, Mac};
use secp256k1::constants::CURVE_ORDER;
use serde::Deserialize;
use serde_json::{Value};
use std::collections::{HashSet,HashMap};

extern crate rand;
extern crate libsecp256k1;

use rand::Rng;
use libsecp256k1::{SecretKey, PublicKey,Signature};
type HmacSha512 = Hmac<Sha512>;

//wallet_235: wpkh(tprv8ZgxMBicQKsPdr2vgwXafiaVmUrnLwwb32mpzYHywJ3JDYiXmnUKLySizdhhVNhh5C3B1JRmhsB6MwTyKYc2wkMKptkHKdVXZHJ9hQK1nhA/84h/1h/0h/0/*)#vh3pt8nf

// util functions

// ser32: serialize a 32-bit unsigned integer i as a 4-byte sequence, most significant byte first.
fn ser32(i: u32) -> [u8; 4] {
    let mut bytes = [0u8; 4];
    BigEndian::write_u32(&mut bytes, i);
    bytes
}

// ser256: serializes the integer p as a 32-byte sequence, most significant byte first.
fn ser256(p: &BigUint) -> Vec<u8> {
    let mut bytes = vec![0u8; 32];
    let p_bytes = p.to_bytes_be();
    bytes[(32 - p_bytes.len())..].copy_from_slice(&p_bytes);
    bytes
}

// parse256: interprets a 32-byte sequence as a 256-bit number, most significant byte first.
fn parse256(p: &[u8]) -> BigUint {
    BigUint::from_bytes_be(p)
}

// point: returns the coordinate pair resulting from EC point multiplication
// (repeated application of the EC group operation) of the secp256k1 base point with the integer p.
fn point(p: &BigUint) -> PublicKey {
    let secret_key = SecretKey::parse_slice(&ser256(p)).unwrap();
    PublicKey::from_secret_key(&secret_key)
}

// serP: serializes the coordinate pair P = (x,y) as a byte sequence using SEC1's compressed form:
// (0x02 or 0x03) || ser256(x), where the header byte depends on the parity of the omitted y coordinate.
fn ser_p(p: &PublicKey) -> Vec<u8> {
    p.serialize().to_vec()
}

//end

//hasher funtions

pub fn sha256_hash(input: &[u8]) -> Vec<u8> {
    let mut sha256 = Sha256::new();
    sha256.update(input);

    sha256.finalize().to_vec()
}

pub fn hash160(input: &[u8])-> Vec<u8> {
    let hash = sha256_hash(input);
    let mut ripemd160_hasher = Ripemd160::new();
    ripemd160_hasher.update(hash);
    let hash160 = ripemd160_hasher.finalize().to_vec();
    hash160
}

//end

//serde json structs 

#[derive(Deserialize, Debug)]
pub struct Block {
    hash: String,
    confirmations: u32,
    height: u32,
    version: u32,
    #[serde(rename = "versionHex")]
    version_hex: String,
    merkleroot: String,
    time: u64,
    mediantime: u64,
    nonce: u32,
    bits: String,
    difficulty: f64,
    chainwork: String,
    #[serde(rename = "nTx")]
    n_tx: u32,
    nextblockhash: Option<String>, // look into these
    previousblockhash: Option<String>, // look into these
    strippedsize: u32,
    size: u32,
    weight: u32,
    tx: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct SCRIPTSIG{
    pub asm: String,
    pub hex: String,
}

#[derive(Deserialize, Debug)]
pub struct VIN{
    pub txid: Option<String>,
    pub vout: Option<u32>,
    #[serde(rename = "scriptSig")]
    pub script_sig: Option<SCRIPTSIG>,
    pub txinwitness: Option<Vec<String>>,
    pub coinbase: Option<String>,
    pub sequence: Option<u64>,
}

#[derive(Deserialize, Debug)]
pub struct SCRIPTPUBKEY{
    pub asm: String,
    pub hex: String,
    pub desc: String,
    #[serde(rename = "type")]
    pub type_name: String,
    pub addresses: Option<String>,
  
}

#[derive(Deserialize, Debug)]
pub struct VOUT{
    pub value: f64,
    pub n: u32,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: SCRIPTPUBKEY,
}


#[derive(Deserialize, Debug)]
// [serde(deny_unknown_fields = false)]
pub struct Transaction{
  //pub in_active_chain: bool,
  pub txid: String ,
  pub hash: String ,
  pub size: u32 ,
  pub vsize: u32 ,
  pub weight: u32 ,
  pub locktime: u32 ,
  pub vin: Vec<VIN>,
  pub vout: Vec<VOUT>,
  pub version: u32, 
  pub blockhash: Option<String>,
  pub confirmations: Option<u32>,
  pub blocktime: Option<u32>,
  pub time: Option<u32>,
  pub hex: Option<String>,
}

//end

// Provided by administrator
pub const WALLET_NAME: &str = "wallet_235";
pub const EXTENDED_PRIVATE_KEY: &str = "tprv8ZgxMBicQKsPdr2vgwXafiaVmUrnLwwb32mpzYHywJ3JDYiXmnUKLySizdhhVNhh5C3B1JRmhsB6MwTyKYc2wkMKptkHKdVXZHJ9hQK1nhA";

#[derive(Debug)]
pub enum BalanceError {
    MissingCodeCantRun,
    // Add relevant error variants for various cases.
}

struct ExKey {
    version: [u8; 4],
    depth: [u8; 1],
    finger_print: [u8; 4],
    child_number: [u8; 4],
    chaincode: [u8; 32],
    key: [u8; 32],
}

// final wallet state struct
pub struct WalletState {
    pub utxos: Vec<Vec<u8>>,
    pub witness_programs: Vec<Vec<u8>>,
    pub public_keys: Vec<Vec<u8>>,
    pub private_keys: Vec<Vec<u8>>,
}

struct OUTPOINT {
    txid: String, // or bytes array choice
    index: u32,
    block_hash: String, 
}


impl WalletState {
    // Given a WalletState find the balance is satoshis
    pub fn balance(&self) -> u32 {
      
        let mut balance = 0u32;
         //let mut cnt =0;
         for utxo in &self.utxos {
             
            //let mut outpoint = vec![];
            //outpoint.extend_from_slice(&txid.as_bytes());
            //outpoint.extend_from_slice(&block_hash.as_bytes());
            //outpoint.extend_from_slice(&index.to_be_bytes());
    
            //utxos.push(outpoint);

            let txid = &utxo[0..32];
            let block_hash = &utxo[32..64];
            let index = LittleEndian::read_u32(&utxo[64..68]);

            let txid_hex = hex::encode(txid);
            let block_hash_hex = hex::encode(block_hash);

            
            // cnt+=1;
            // println!("txid: {}",txid_hex);
            // println!("block_hash: {}",block_hash_hex);
            // println!("index: {}",index);
            // println!("cnt: {}",cnt);

            let tx = serde_json::from_slice::<Transaction>(&bcli(&format!("-signet getrawtransaction {} true {}", txid_hex,block_hash_hex)).unwrap()).unwrap();

            let txout = tx.vout;
            let value = txout[index as usize].value;
            balance += (value * 100000000.0) as u32; // converting to satoshis
         }
        balance
    }
}


//wallet_235: wpkh(tprv8ZgxMBicQKsPdr2vgwXafiaVmUrnLwwb32mpzYHywJ3JDYiXmnUKLySizdhhVNhh5C3B1JRmhsB6MwTyKYc2wkMKptkHKdVXZHJ9hQK1nhA/84h/1h/0h/0/*)#vh3pt8nf

// Decode a base58 string into an array of bytes
fn base58_decode(base58_string: &str) -> Vec<u8> {

    let base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    // Convert Base58 string to a big integer

    let reversed_base58 = base58_string.chars().rev().collect::<String>();

    let mut result = BigUint::from(0u8);
    let mut base = BigUint::from(58u8);

    for (index, c) in reversed_base58.chars().enumerate() {
        let value = base58_alphabet.chars().position(|x| x == c).unwrap() as u8;
        result += BigUint::from(value) * base.pow(index as u32);
    }

    // Convert the integer to bytes

    let mut bytes = result.to_bytes_be();
    
    // Chop off the 32 checksum bits and return
    let ans = bytes[0..bytes.len() - 4].to_vec(); // checksum is appended at the last (like in descriptors)
    let checksum: Vec<u8> = bytes[bytes.len() - 4..].to_vec(); // last 4 bytes
      
    // BONUS POINTS: Verify the checksum!

    let hash_result = sha256_hash(&sha256_hash(&ans.clone()));

    return ans; //check for the size of the ans in bytes.
}

// Deserialize the extended pubkey bytes and return a ExKey object
// Bip32 Serialization format: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format
// 4 byte: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
// 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
// 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
// 4 bytes: child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
// 32 bytes: the chain code
// 33 bytes: the public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)

fn deserialize_key(bytes: &[u8]) -> ExKey {

    /*struct ExKey {
        version: [u8; 4],
        depth: [u8; 1],
        finger_print: [u8; 4],
        child_number: [u8; 4],
        chaincode: [u8; 32],
        key: [u8; 32],
     } */   

     let version = bytes[0..4].to_vec();
     let depth = bytes[4..5].to_vec();
     let finger_print = bytes[5..9].to_vec();
     let child_number = bytes[9..13].to_vec();
     let chaincode = bytes[13..45].to_vec();
     let key = bytes[46..78].to_vec(); // ignoring 45th byte . (we need private key it is only 32 bytes)

    ExKey {
        version: version.try_into().unwrap(),
        depth: depth.try_into().unwrap(),
        finger_print: finger_print.try_into().unwrap(),
        child_number: child_number.try_into().unwrap(),
        chaincode: chaincode.try_into().unwrap(),
        key: key.try_into().unwrap(),
    }

}

// Derive the secp256k1 compressed public key from a given private key
// BONUS POINTS: Implement ECDSA yourself and multiply you key by the generator point!

pub fn derive_public_key_from_private(key: &[u8]) -> Vec<u8> {

     // Create a SecretKey from the given private key bytes
     let private_key = SecretKey::parse_slice(key).expect("Invalid private key");
 
     // Derive the compressed public key from the private key
     let public_key = PublicKey::from_secret_key(&private_key);
    
     // Serialize the compressed public key
     let serialized_public_key = public_key.serialize_compressed(); // 33 bytes (1 byte for sign + 32 bytes for x coordinate)
 
     // Return the serialized public key as a Vec<u8>
     serialized_public_key.to_vec()
}

// Perform a BIP32 parent private key -> child private key derivation
// Return a derived child Xpriv, given a child_number. Check the struct docs for APIs.
// Key derivation steps: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#user-content-Private_parent_key_rarr_private_child_key

fn derive_priv_child(key: &ExKey, child_num: u32) -> ExKey {
    
    let mut mac = HmacSha512::new_from_slice(&key.chaincode).expect("HMAC can take key of any size");

    if child_num >= 0x80000000 { // hardened  

        let mut input_data = Vec::new();
        input_data.extend_from_slice(&[0x00]);
        input_data.extend_from_slice(&key.key);
        input_data.extend_from_slice(&ser32(child_num));
        
        mac.update(&input_data);
     
    } else { // normal 
        
        let mut input_data = Vec::new();
        input_data.extend_from_slice(&derive_public_key_from_private(&key.key));
        input_data.extend_from_slice(&ser32(child_num));
        
        mac.update(&input_data);
    }

    let result = mac.finalize();
    let result_bytes = result.into_bytes(); 
    let (il, ir) = result_bytes.split_at(32);
    //assert_eq!(il.len(), 32);
    let il_num = parse256(il);
    
    let curve_order = BigUint::from_bytes_be(&CURVE_ORDER);
    let ki = (il_num + (BigUint::from_bytes_be(&key.key))) % curve_order; // ki is parse256(IL) + kpar (mod n).
    
    let ci = ir; // ci is IR.

    ExKey {
        version: key.version,
        depth: [(key.depth[0] + 1)],
        finger_print: hash160(&derive_public_key_from_private(&key.key))[0..4].try_into().unwrap(), // The fingerprint is the first 4 bytes of the hash160 of the parent key.
        child_number: child_num.to_be_bytes(),
        chaincode: ci.to_vec().try_into().unwrap(),
        key: {
            let mut ki_bytes = ki.to_bytes_be();
            while ki_bytes.len() < 32 {
                ki_bytes.insert(0, 0); //THIS IS TO PAD WITH ZEROES WHEN LEADING ZEROES ARE LOST WHILE PARSING
            }
            ki_bytes.try_into().unwrap_or_else(|_| {
                panic!("Failed to convert ki to an array of bytes");
            })
        },
    }
}

// Given an extended private key and a BIP32 derivation path, compute the child private key found at the path
// Derivation paths are strings like "m/0'/1/2h/2"

fn get_child_key_at_path(key: ExKey, derivation_path: &str) -> ExKey {

   // Split the derivation path into parts
   let parts = derivation_path.split('/');
   
   let mut finalkey = key;

   for part in parts {

       // Check if the part is "m"
       if part == "m" {
           continue;
       }

       // Check if the part ends with "h" or "'"
       let hardened = part.ends_with('h') || part.ends_with('\'');

       // Parse the part as a u32
       let index = part.trim_end_matches(|c| c == 'h' || c == '\'').parse::<u32>().unwrap_or_else(|_| {
        panic!("Failed to parse part '{}' of the derivation path as a u32", part);
        });
        
       // If the part is hardened, add 0x80000000 to the index
       let index = if hardened { index | 0x80000000 } else { index };

       // Derive the child key
       finalkey = derive_priv_child(&finalkey, index);
   }

   finalkey

}

// Compute the first N child private keys.
// Return an array of keys.
fn get_keys_at_child_key_path(child_key: ExKey, num_keys: u32) -> Vec<ExKey> {
    
   // create a new vector of ExKey type
   let mut ans = vec![];

    // iterate over the num_keys and push the keys in the vector
   for i in 0..num_keys {
       let key = derive_priv_child(&child_key, i);
       ans.push(key);
   }
    
    // return the vector
    ans

}

// Derive the p2wpkh witness program (aka scriptPubKey) for a given compressed public key
// Return a bytes array to be compared with the JSON output of Bitcoin Core RPC getblock
// so we can find our received transactions in blocks
// These are segwit version 0 pay-to-public-key-hash witness programs
// https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#user-content-P2WPKH
pub fn get_p2wpkh_program(pubkey: &[u8]) -> Vec<u8> {
    
    //implementing hash160
    let hash160result = hash160(pubkey);
    
    //making it a scriptPubKey
    let mut result = vec![0x00, 0x14];
    result.extend_from_slice(&hash160result);
    
    //returning the result
    result
}


// Assuming Bitcoin Core is running and connected to signet using default datadir,
// execute an RPC and return its value or error message.
// https://github.com/bitcoin/bitcoin/blob/master/doc/bitcoin-conf.md#configuration-file-path
// Examples: bcli("getblockcount")
//            bcli("getblockhash 100")

pub fn bcli(cmd: &str) -> Result<Vec<u8>, BalanceError> {
    let args = cmd.split(' ').collect::<Vec<&str>>();

    //println!("Running command: {:?}", args); // Print the command being run

    let result = Command::new("bitcoin-cli")
        .args(&args)
        .output()
        .map_err(|_| BalanceError::MissingCodeCantRun)?;

    if result.status.success() {
        //println!("Command output: {:?}", String::from_utf8_lossy(&result.stdout)); // Print the command output
        return Ok(result.stdout);
    } else {
        //println!("Command error: {:?}", String::from_utf8_lossy(&result.stderr)); // Print the command error
        return Ok(result.stderr);
    }
}

// public function that will be called by `run` here as well as the spend program externally
pub fn recover_wallet_state(
    extended_private_key: &str,
    cookie_filepath: &str,
) -> Result<WalletState, BalanceError> {

    // Deserialize the provided extended private key
    let decoded_key = base58_decode(extended_private_key);
    let key = deserialize_key(&decoded_key); // 78 bytes deserealized ExKey

    // Derive the key and chaincode at the path in the descriptor (`84h/1h/0h/0`)
    
    // Get the child key at the derivation path
    let child_key = get_child_key_at_path(key, "m/84h/1h/0h/0");

    // Compute 2000 private keys from the child key path
    let child_keys = get_keys_at_child_key_path(child_key, 2000);

    // For each private key, collect compressed public keys and witness programs
    let mut private_keys = vec![];
    let mut public_keys = vec![];
    let mut witness_programs = vec![];
    
    //SET for help

    let mut set_for_pubkeys = HashSet::new();
    let mut set_for_witness_programs = HashSet::new();


    for key in child_keys {
        let private_key = key.key;
        let public_key = derive_public_key_from_private(&private_key);
        let witness_program = get_p2wpkh_program(&public_key);

        //inserting in the set

        //convert pubkey to hex string
        let public_key_hex = hex::encode(&public_key);
        set_for_pubkeys.insert(public_key_hex);

        //convert witness_program to hex string
        let witness_program_hex = hex::encode(&witness_program);
        set_for_witness_programs.insert(witness_program_hex);

        private_keys.push(private_key.to_vec());
        public_keys.push(public_key.to_vec());
        witness_programs.push(witness_program.to_vec());
    }
    
    // Collect outgoing and spending txs from a block scan
    let mut utxos: Vec<Vec<u8>> = vec![];
    
    // a txid is always 32 bytes long
    // other bytes for index
    
    //hashmap for help
    let mut map : HashMap<String,OUTPOINT> = HashMap::new();
    // let mut ins =0;
    // let mut spends=0;
    // Scan blocks 0 to 310 for transactions
    //skipped the genesis block

    for block_height in 1..310 {
       
        // Get the block hash for the block height
        let block_hash = bcli(&format!("-signet getblockhash {}", block_height)).unwrap();
        let block_hash_str = String::from_utf8(block_hash).unwrap().trim().to_string();
        
        // Get the block for the block hash
        let block = serde_json::from_slice::<Block>(&bcli(&format!("-signet getblock {}", block_hash_str)).unwrap()).unwrap();
       // println!("Block: {:?}", block); //Ok

        // // Get the transactions in the block
        let tx_array = block.tx;

        // For each transaction, check if it is outgoing or spending
        for transactions in tx_array {
           
            //println!("Transaction: {}", transactions); //Ok
          
          //let tx_object = serde_json::from_slice::<Transaction>(&bcli(&format!("getrawtransaction {} true {}", transactions,block_hash_str)).unwrap()).unwrap();
          let result = bcli(&format!("-signet getrawtransaction {} true {}", transactions, block_hash_str)).unwrap();
          let tx_object: Transaction = serde_json::from_slice(&result).unwrap();

          let txin = tx_object.vin;
          let txout = tx_object.vout;

          // check for vout -> scriptPubKey -> hex , we received it

          for tx in txout { // txout is vout array 
            let script_pub_key = tx.script_pub_key;
            let hex = script_pub_key.hex;
        
            if set_for_witness_programs.contains(&hex) {

                // concatenate the txid and index and map it with a OUTGOING struct
                let txid_index_string = format!("{}{}", tx_object.txid.clone(),tx.n.clone());
                 map.insert(txid_index_string, OUTPOINT{txid: tx_object.txid.clone(), index:tx.n.clone(), block_hash: block_hash_str.clone()});
               //  ins+=1;
            }
        }

          // check for vin -> scriptsig -> txwitness , we spent it
           
          for tx in txin { // txin is vin array
                let tx_witness = tx.txinwitness;
                if tx_witness != None {

                    let tx_witness = tx_witness.unwrap(); // since it is an option type

                    for witness in tx_witness {

                        if set_for_pubkeys.contains(&witness) {

                            // add to spending the transaction id with the index
                            let txid_index_string = format!("{}{}", tx.txid.clone().unwrap(), tx.vout.unwrap());

                            //delete this from the map
                            map.remove(&txid_index_string);
                            //spends+=1;
                        }

                    }

                }
          }

        }
        
    }

    // Check every tx input (witness) for our own compressed public keys. These are coins we have spent.
    // Check every tx output for our own witness programs. These are coins we have received.
    // Keep track of outputs by their outpoint so we can check if it was spent later by an input
    // Collect outputs that have not been spent into a utxo set
    // Return Wallet State
     
     //iterate over hashmap
        for (_, value) in map {

            let txid = value.txid;
            let block_hash = value.block_hash;
            let index = value.index;
            
            // println!("txid: {}",txid);
            // println!("block_hash: {}",block_hash);
            // println!("index: {}",index);

            let mut outpoint = vec![];

            let txid_bytes = hex::decode(&txid).expect("Invalid hex string");
            let block_hash_str = hex::decode(&block_hash).expect("Invalid hex string");

            outpoint.extend_from_slice(&txid_bytes);
            outpoint.extend_from_slice(&block_hash_str);
            outpoint.extend_from_slice(&index.to_le_bytes());
    
            utxos.push(outpoint);
        }
       
       //print utxo size
        //  println!("utxo size: {}", utxos.len());
        //  println!("total ins: {}",ins);
        //  println!("total spends: {}",spends);

    Ok(WalletState {
        utxos,
        public_keys,
        private_keys,
        witness_programs,
    })
}

pub fn tester_helper() {
   
 //let block_hash_str = "000002bccf400825cc325baddb79ad88bb52f1062b021edf4796f6a28bc2b02a";
 //let tx_str = "c14dd84a3501fb8b390c557833227257bdd66bff4113cd2e22da29fd65a64b86";
 
 let block_hash_str = "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6";
 let tx_str = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";

 let tx_object = serde_json::from_slice::<Transaction>(&bcli(&format!("-getrawtransaction {} true {}", tx_str,block_hash_str)).unwrap()).unwrap();
 
 // PRINT THE TRANSACTION
    println!("Transaction: {:?}", tx_object); //Ok

    //prints 

   // Transaction: Transaction { in_active_chain: true, txid: "c14dd84a3501fb8b390c557833227257bdd66bff4113cd2e22da29fd65a64b86", hash: "d65edf9adffd039425bbf758519f97225ad4334b18920bb1245bb1fb0a1abc4c", size: 282, vsize: 255, weight: 1020, locktime: 0, vin: [VIN { txid: None, vout: None, script_sig: None, txinwitness: Some(["0000000000000000000000000000000000000000000000000000000000000000"]), coinbase: Some("023601"), sequence: Some(4294967294) }], vout: [VOUT { value: 50.0, n: 0, script_pub_key: SCRIPTPUBKEY { asm: "0 e465e43a5e6a013f5c5ec43eae826f57cbb3f83d", hex: "0014e465e43a5e6a013f5c5ec43eae826f57cbb3f83d", desc: "addr(tb1qu3j7gwj7dgqn7hz7csl2aqn02l9m87pasuyrj4)#xhp3eqyj", type_name: "witness_v0_keyhash", addresses: None } }, VOUT { value: 0.0, n: 1, script_pub_key: SCRIPTPUBKEY { asm: "OP_RETURN aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9 ecc7daa2000247304402201110ff02e98863c09bdb6bd0f4286d468155df022ab0e636b4e31d84cced8b76022052e2ffe47ff6c9b37d7b3bf1c7b9cf915d3f9c8fb26aba65e0eed1eb457aa984012102dd853d283e55a2a9beb4c1908c6c1ac73b0f0d422f0905b537960526c731c821", hex: "6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c70ecc7daa2000247304402201110ff02e98863c09bdb6bd0f4286d468155df022ab0e636b4e31d84cced8b76022052e2ffe47ff6c9b37d7b3bf1c7b9cf915d3f9c8fb26aba65e0eed1eb457aa984012102dd853d283e55a2a9beb4c1908c6c1ac73b0f0d422f0905b537960526c731c821", desc: "raw(6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c70ecc7daa2000247304402201110ff02e98863c09bdb6bd0f4286d468155df022ab0e636b4e31d84cced8b76022052e2ffe47ff6c9b37d7b3bf1c7b9cf915d3f9c8fb26aba65e0eed1eb457aa984012102dd853d283e55a2a9beb4c1908c6c1ac73b0f0d422f0905b537960526c731c821)#yuysecde", type_name: "nulldata", addresses: None } }], version: 2, blockhash: Some("000002bccf400825cc325baddb79ad88bb52f1062b021edf4796f6a28bc2b02a"), confirmations: Some(3564), blocktime: Some(1704344596), time: Some(1704344596), hex: Some("020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03023601feffffff0200f2052a01000000160014e465e43a5e6a013f5c5ec43eae826f57cbb3f83d0000000000000000986a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c70ecc7daa2000247304402201110ff02e98863c09bdb6bd0f4286d468155df022ab0e636b4e31d84cced8b76022052e2ffe47ff6c9b37d7b3bf1c7b9cf915d3f9c8fb26aba65e0eed1eb457aa984012102dd853d283e55a2a9beb4c1908c6c1ac73b0f0d422f0905b537960526c731c8210120000000000000000000000000000000000000000000000000000000000000000000000000") }

//  let decoded_key = base58_decode("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi");
//  let key = deserialize_key(&decoded_key); // 78 bytes deserialized ExKey
//  let public_key = derive_public_key_from_private(&key.key);
//  let private_key = key.key;
 
//  // print in hexadecimal format in string the public key 
//  let public_key_hex = hex::encode(&public_key);
//  println!("public key: {}", public_key_hex);
//  assert_eq!(public_key_hex, "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2");
 
//  // print in hexadecimal format in string the private key
//  let private_key_hex = hex::encode(&private_key);
//  println!("private key: {}", private_key_hex);
//  assert_eq!(private_key_hex, "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35");
}

#[cfg(test)]

mod tests {

     use base58::FromBase58;
     use super::{base58_decode,EXTENDED_PRIVATE_KEY,deserialize_key,derive_public_key_from_private,get_child_key_at_path,derive_priv_child};

     //test for base58_decode function
     #[test]
     fn test_1() {

            // My base58 decoder
            let decoded_key = base58_decode(EXTENDED_PRIVATE_KEY);

            assert_eq!(decoded_key.len(),78); 
            
            let ans = EXTENDED_PRIVATE_KEY.from_base58().unwrap();
            let mut decoded_data1 = ans.clone();
            decoded_data1.truncate(decoded_data1.len() - 4);
            
            assert_eq!(decoded_key,decoded_data1);
     }
     
     //test for deserealisation function
     //https://bip32jp.github.io/english/ for testing
     #[test]
     fn test_2(){
       
      let decoded_key = base58_decode(EXTENDED_PRIVATE_KEY);
      let key = deserialize_key(&decoded_key);

     /*struct ExKey {
        version: [u8; 4],
        depth: [u8; 1],
        finger_print: [u8; 4],
        child_number: [u8; 4],
        chaincode: [u8; 32],
        key: [u8; 32],
     } */   

     assert_eq!(key.version, [0x04, 0x35, 0x83, 0x94]);
     assert_eq!(key.depth, [0]);
     assert_eq!(key.finger_print, [0x00, 0x00, 0x00, 0x00]);
     assert_eq!(key.child_number, [0, 0, 0, 0]);
     assert_eq!(key.chaincode, [0x61, 0xbf, 0x0d, 0x01, 0x42, 0x98, 0x9b, 0x2c, 0x3a, 0x1c, 0xaf, 0x46, 0xb8, 0x30, 0x39, 0x1f, 0x58, 0x61, 0x2f, 0x15, 0x49, 0x22, 0xa0, 0xd1, 0x46, 0xe0, 0x07, 0x85, 0x03, 0x70, 0x86, 0xfe]);
     assert_eq!(key.key, [0xf2, 0x99, 0x9e, 0x5a, 0xf3, 0x16, 0xf6, 0xe2, 0x30, 0xee, 0x8e, 0x3b, 0x70, 0x0d, 0x48, 0x6c, 0xb2, 0x9b, 0xbf, 0xce, 0x8e, 0x89, 0xb2, 0xc3, 0x85, 0x58, 0x4a, 0x61, 0xb5, 0xb1, 0x96, 0xd1]);
     }

     //test for checking the function [priv key to pub key]
     //https://en.bitcoin.it/wiki/BIP_0032_TestVectors
     #[test]
     fn test_3(){

            let test_key = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
            let decoded_key = base58_decode(test_key);
            let key = deserialize_key(&decoded_key);
            let private_key = key.key;
            let public_key = derive_public_key_from_private(&private_key);
            
            assert_eq!(private_key, [0xe8, 0xf3, 0x2e, 0x72, 0x3d, 0xec, 0xf4, 0x05, 0x1a, 0xef, 0xac, 0x8e, 0x2c, 0x93, 0xc9, 0xc5, 0xb2, 0x14, 0x31, 0x38, 0x17, 0xcd, 0xb0, 0x1a, 0x14, 0x94, 0xb9, 0x17, 0xc8, 0x43, 0x6b, 0x35]);
            assert_eq!(public_key, [0x03, 0x39, 0xa3, 0x60, 0x13, 0x30, 0x15, 0x97, 0xda, 0xef, 0x41, 0xfb, 0xe5, 0x93, 0xa0, 0x2c, 0xc5, 0x13, 0xd0, 0xb5, 0x55, 0x27, 0xec, 0x2d, 0xf1, 0x05, 0x0e, 0x2e, 0x8f, 0xf4, 0x9c, 0x85, 0xc2]);

     }

     //test for checking the function [priv key to child key]
     //https://en.bitcoin.it/wiki/BIP_0032_TestVectors
     #[test]
     fn test_4(){

            let test_key = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
            let decoded_key = base58_decode(test_key);
            let key = deserialize_key(&decoded_key);
            
            let child_child_key = get_child_key_at_path(key,"m/0'/1/2'/2/1000000000");
            let child_child_private_key = child_child_key.key;

            let child_key2_str = "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76";
            let decoded_child_key2 = base58_decode(child_key2_str);
            let child_key2 = deserialize_key(&decoded_child_key2);
            
            assert_eq!(child_child_private_key, child_key2.key);
            assert_eq!(child_child_private_key.len(), 32);
     }

     //test for checking the function [priv key to child keys from paths , leading zeroes retained]
     //https://en.bitcoin.it/wiki/BIP_0032_TestVectors
     #[test]
     fn test_5(){
            let test_key = "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U";
            let decoded_key = base58_decode(test_key);
            let key = deserialize_key(&decoded_key);

            let child_child_key = get_child_key_at_path(key,"m/0/2147483647'/1/2147483646'/2");
            let child_child_private_key = child_child_key.key;

            let child_key2_str = "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j";
            let decoded_child_key2 = base58_decode(child_key2_str);
            let child_key2 = deserialize_key(&decoded_child_key2);

            assert_eq!(child_child_private_key, child_key2.key);
            assert_eq!(child_child_private_key.len(), 32);
           // assert_eq!(child_private_key.to_vec(), expected_key);
     }

      //test for checking the function [priv key to child key]
     //https://en.bitcoin.it/wiki/BIP_0032_TestVectors
     #[test]
     fn test_6(){

            let test_key = "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U";
            let decoded_key = base58_decode(test_key);
            let key = deserialize_key(&decoded_key);
            
            let child_child_key = get_child_key_at_path(key,"m/0/2147483647'/1/2147483646'/2");
            let child_child_private_key = child_child_key.key;

            let child_key2_str = "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j";
            let decoded_child_key2 = base58_decode(child_key2_str);
            let child_key2 = deserialize_key(&decoded_child_key2);

            assert_eq!(child_child_private_key, child_key2.key);
            assert_eq!(child_child_private_key.len(), 32);
     }
     
      //test for checking the function [priv key to child key]
     //https://en.bitcoin.it/wiki/BIP_0032_TestVectors
     #[test]
     fn test_7(){

            let test_key = "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6";
            let decoded_key = base58_decode(test_key);
            let key = deserialize_key(&decoded_key);
            
            let child_child_key = get_child_key_at_path(key,"m/0h");
            let child_child_private_key = child_child_key.key;

            let child_key2_str = "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L";
            let decoded_child_key2 = base58_decode(child_key2_str);
            let child_key2 = deserialize_key(&decoded_child_key2);

            assert_eq!(child_child_private_key, child_key2.key);
            assert_eq!(child_child_private_key.len(), 32);
     }

     #[test]
     fn test_8(){

            let test_key = "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv";
            let decoded_key = base58_decode(test_key);
            let key = deserialize_key(&decoded_key);
            
            let child_child_key = get_child_key_at_path(key,"m/0h");
            let child_child_private_key = child_child_key.key;

            let child_key2_str = "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G";
            let decoded_child_key2 = base58_decode(child_key2_str);
            let child_key2 = deserialize_key(&decoded_child_key2);

            assert_eq!(child_child_private_key, child_key2.key);
            assert_eq!(child_child_private_key.len(), 32);
     }

     #[test]
     fn test_9(){

            let test_key = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
            let decoded_key = base58_decode(test_key);
            let key = deserialize_key(&decoded_key);
            
            let child_child_key = get_child_key_at_path(key,"m/0'/1/2'/2/1000000000");
            let child_child_private_key = child_child_key.key;

            let child_key2_str = "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76";
            let decoded_child_key2 = base58_decode(child_key2_str);
            let child_key2 = deserialize_key(&decoded_child_key2);

            assert_eq!(child_child_private_key, child_key2.key);
            assert_eq!(child_child_private_key.len(), 32);
     }
     
     #[test]
     fn test_10() {
        let witness = "ef10";
        let witness_vec = hex::decode(witness).expect("Decoding failed");
        let corrected_witness = [0xef , 0x10];
        assert_eq!(witness_vec,corrected_witness);
     }

     #[test]
     fn test_11() {
        let tx = "c14dd84a3501fb8b390c557833227257bdd66bff4113cd2e22da29fd65a64b86";
        //let tx_vec = hex::decode(tx).expect("Decoding failed");
        let tx_bytes_vec = tx.as_bytes().to_vec();

        let tx_bytes_vec_to_string = String::from_utf8(tx_bytes_vec).unwrap();
        
        assert_eq!(tx_bytes_vec_to_string,tx);
     }


}     

/* 
probot@Probot:~/signet-wallet-project$ bitcoin-cli -signet getrawtransaction c14dd84a3501fb8b390c557833227257bdd66bff4113cd2e22da29fd65a64b86 true 000002bc
cf400825cc325baddb79ad88bb52f1062b021edf4796f6a28bc2b02a
{
  "in_active_chain": true,
  "txid": "c14dd84a3501fb8b390c557833227257bdd66bff4113cd2e22da29fd65a64b86",
  "hash": "d65edf9adffd039425bbf758519f97225ad4334b18920bb1245bb1fb0a1abc4c",
  "version": 2,
  "size": 282,
  "vsize": 255,
  "weight": 1020,
  "locktime": 0,
  "vin": [
    {
      "coinbase": "023601",
      "txinwitness": [
        "0000000000000000000000000000000000000000000000000000000000000000"
      ],
      "sequence": 4294967294
    }
  ],
  "vout": [
    {
      "value": 50.00000000,
      "n": 0,
      "scriptPubKey": {
        "asm": "0 e465e43a5e6a013f5c5ec43eae826f57cbb3f83d",
        "desc": "addr(tb1qu3j7gwj7dgqn7hz7csl2aqn02l9m87pasuyrj4)#xhp3eqyj",
        "hex": "0014e465e43a5e6a013f5c5ec43eae826f57cbb3f83d",
        "address": "tb1qu3j7gwj7dgqn7hz7csl2aqn02l9m87pasuyrj4",
        "type": "witness_v0_keyhash"
      }
    },
    {
      "value": 0.00000000,
      "n": 1,
      "scriptPubKey": {
        "asm": "OP_RETURN aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9 ecc7daa2000247304402201110ff02e98863c09bdb6bd0f4286d468155df022ab0e636b4e31d84cced8b76022052e2ffe47ff6c9b37d7b3bf1c7b9cf915d3f9c8fb26aba65e0eed1eb457aa984012102dd853d283e55a2a9beb4c1908c6c1ac73b0f0d422f0905b537960526c731c821",
        "desc": "raw(6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c70ecc7daa2000247304402201110ff02e98863c09bdb6bd0f4286d468155df022ab0e636b4e31d84cced8b76022052e2ffe47ff6c9b37d7b3bf1c7b9cf915d3f9c8fb26aba65e0eed1eb457aa984012102dd853d283e55a2a9beb4c1908c6c1ac73b0f0d422f0905b537960526c731c821)#yuysecde",
        "hex": "6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c70ecc7daa2000247304402201110ff02e98863c09bdb6bd0f4286d468155df022ab0e636b4e31d84cced8b76022052e2ffe47ff6c9b37d7b3bf1c7b9cf915d3f9c8fb26aba65e0eed1eb457aa984012102dd853d283e55a2a9beb4c1908c6c1ac73b0f0d422f0905b537960526c731c821",
        "type": "nulldata"
      }
    }
  ],
  "hex": "020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03023601feffffff0200f2052a01000000160014e465e43a5e6a013f5c5ec43eae826f57cbb3f83d0000000000000000986a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c70ecc7daa2000247304402201110ff02e98863c09bdb6bd0f4286d468155df022ab0e636b4e31d84cced8b76022052e2ffe47ff6c9b37d7b3bf1c7b9cf915d3f9c8fb26aba65e0eed1eb457aa984012102dd853d283e55a2a9beb4c1908c6c1ac73b0f0d422f0905b537960526c731c8210120000000000000000000000000000000000000000000000000000000000000000000000000",
  "blockhash": "000002bccf400825cc325baddb79ad88bb52f1062b021edf4796f6a28bc2b02a",
  "confirmations": 3280,
  "time": 1704344596,
  "blocktime": 1704344596
}
*/