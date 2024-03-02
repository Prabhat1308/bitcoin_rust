/*
helper texts
https://stackoverflow.com/questions/73527172/using-the-bitcoin-crate-to-sign-a-segwit-transaction
medium articles by otto - https://medium.com/coinmonks/creating-and-signing-a-segwit-transaction-from-scratch-ec98577b526a
https://www.reddit.com/r/learnprogramming/comments/15ds9ym/how_to_sign_p2wpkh_bitcoin_transactions/
libbitcoin
https://bitcoincore.org/en/segwit_wallet_dev/
 */

#![allow(unused)]
extern crate balance;
use balance::{
    get_p2wpkh_program, bcli, derive_public_key_from_private, sha256_hash, Transaction, WalletState, SCRIPTPUBKEY, VOUT,
};
use bitcoin::consensus::encode::VarInt;
use byteorder::WriteBytesExt;
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use libsecp256k1::{Message, PublicKey, SecretKey, Signature};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug)]
pub enum SpendError {
    MissingCodeCantRun,
    // Add more relevant error variants
}

#[derive(Clone)]
pub struct Utxo {
    script_pubkey: Vec<u8>,
    amount: u32,
}

// helps in finding the previous transfer where we received the bitcoins from
// since transaction can contain multiple outputs , this also tells the index to use to find the utxo in the transaction
pub struct Outpoint {
    txid: [u8; 32],
    index: u32,
}

//I give output the locking scripts and the input the unlocking scripts

// Given 2 compressed public keys as byte arrays, construct
// a 2-of-2 multisig output script. No length byte prefix is necessary.
fn create_multisig_script(keys: Vec<Vec<u8>>) -> Vec<u8> {

    let mut script = vec![0x52]; // OP_2 , OP_M
    for key in keys {
        script.push(0x21); // push the length of the key , this is because bitcoin script is a stack based language and we need to push the length of the key before pushing the key itself
        script.extend_from_slice(&key); // push the key itself
    }
    script.push(0x52); // OP_2 , OP_N
    script.push(0xae); // OP_CHECKMULTISIG
    script

    //OK
}

fn turn_to_varint(num: u64) -> Vec<u8> {

    let mut varint = Vec::new();
    if num < 0xfd {
        varint.push(num as u8);
    } else if num <= 0xffff {
        varint.push(0xfd);
        varint.extend_from_slice(&num.to_le_bytes());
    } else if num <= 0xffffffff {
        varint.push(0xfe);
        varint.extend_from_slice(&num.to_le_bytes());
    } else {
        varint.push(0xff);
        varint.extend_from_slice(&num.to_le_bytes());
    }
    varint
}

// Given an output script as a byte array, compute the p2wsh witness program
// This is a segwit version 0 pay-to-script-hash witness program.
// https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#p2wsh

fn get_p2wsh_program(script: &[u8], version: Option<u32>) -> Vec<u8> {

    let mut program = Vec::new();

    let version = version.unwrap_or(0x00);
    program.push(version as u8);
    program.push(0x20);
    program.extend_from_slice(&sha256_hash(&script));

    program

}

// Given an outpoint, return a serialized transaction input spending it
// Use hard-coded defaults for sequence and scriptSig
fn input_from_utxo(txid: &[u8], index: u32) -> Vec<u8> {
    let mut input = Vec::new();

    //txid
    let reversed_txid: Vec<u8> = txid.iter().rev().cloned().collect();
    input.extend_from_slice(&reversed_txid);

    //index
    let index_in_little_endian_bytes = index.to_le_bytes();  // fixed 4 bytes
    input.extend_from_slice(&index_in_little_endian_bytes);
    
    //script length (default is zero for us)
    input.push(0x00);

    //sequence
    let sequence: u32 = 0xffffffff;
    input.extend_from_slice(&sequence.to_le_bytes());

    input

    //OK
}


// Given an output script and value (in satoshis), return a serialized transaction output
fn output_from_options(script: &[u8], value: u32) -> Vec<u8> {
    
    let mut output = Vec::new();
    let valhue: u64 = value as u64;
    let value_in_8_bytes_in_little_endian = valhue.to_le_bytes();
    output.extend_from_slice(&value_in_8_bytes_in_little_endian);

    let script_length = script.len() as u64;
    let script_length_varint = turn_to_varint(script_length);
    
    output.extend_from_slice(&script_length_varint);

    output.extend_from_slice(script);
    output

    //OK
}


// Given a Utxo object, extract the public key hash from the output script
// and assemble the p2wpkh scriptcode as defined in BIP143
// <script length> OP_DUP OP_HASH160 <pubkey hash> OP_EQUALVERIFY OP_CHECKSIG
// https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#specification

//For P2WPKH witness program, the scriptCode is 0x1976a914{20-byte-pubkey-hash}88ac.
//For P2WSH witness program,
//if the witnessScript does not contain any OP_CODESEPARATOR, the scriptCode is the witnessScript serialized as scripts inside CTxOut.
//if the witnessScript contains any OP_CODESEPARATOR, the scriptCode is the witnessScript but removing everything up to and including the last executed OP_CODESEPARATOR before the signature checking opcode being executed, serialized as scripts inside CTxOut. (The exact semantics is demonstrated in the examples below)

fn get_p2wpkh_scriptcode(utxo: Utxo) -> Vec<u8> {
    let mut script = Vec::new();
    
    script.push(0x19); // 25 bytes , script length

    script.push(0x76); // OP_DUP

    script.push(0xa9); // OP_HASH160

    script.push(0x14); // 20 bytes , public key hash length

    let pubkey_hash = extract_pubkey_hash(&utxo.script_pubkey);
    
    script.extend_from_slice(&pubkey_hash); // [pubkey hash]

    script.push(0x88); // OP_EQUALVERIFY

    script.push(0xac); // OP_CHECKSIG

    script

    //OK
}

fn extract_pubkey_hash(script_pubkey: &[u8]) -> &[u8] {
    &script_pubkey[2..22]
    //Ok
}

fn output_for_commitment(script: &[u8], value: u32) -> Vec<u8> {
    let mut output = Vec::new();

    let value_in_8_bytes_in_little_endian = value.to_le_bytes();
    output.extend_from_slice(&value_in_8_bytes_in_little_endian);

    output.extend_from_slice(script);
    output

    //OK
}
// Compute the commitment hash for a single input and return bytes to sign.
// This implements the BIP 143 transaction digest algorithm
// https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#specification
// We assume only a single input and two outputs,
// as well as constant default values for sequence and locktime

fn get_commitment_hash(
    outpoint: Outpoint,
    scriptcode: &[u8],
    value: u64,
    outputs: Vec<Vec<u8>>,
) -> Vec<u8> {
    let mut commitment = Vec::new();

    let version: u32 = 0x00000002;

    // Version
    commitment.extend_from_slice(&version.to_le_bytes());

    // All TX input outpoints (only one in our case)
    let mut vec = Vec::new();

    //vec.extend_from_slice(&outpoint.txid);

    let reversed_txid: Vec<u8> = outpoint.txid.iter().rev().cloned().collect();

    vec.extend_from_slice(&reversed_txid);
    vec.extend_from_slice(&outpoint.index.to_le_bytes());

    let hash_prevouts = sha256_hash(&sha256_hash(&vec));
    commitment.extend_from_slice(&hash_prevouts);

    // All TX input sequences (only one for us, always default value)
    let hash_sequence = sha256_hash(&sha256_hash(&[0xff, 0xff, 0xff, 0xff]));
    commitment.extend_from_slice(&hash_sequence);

    // Single outpoint being spent
    let mut temp_vec = Vec::new();

    temp_vec.extend_from_slice(&reversed_txid);
    temp_vec.extend_from_slice(&outpoint.index.to_le_bytes());

    let hash_single = sha256_hash(&sha256_hash(&temp_vec));
    commitment.extend_from_slice(&hash_single);

    // Scriptcode (the scriptPubKey in/implied by the output being spent, see BIP 143)
    commitment.extend_from_slice(&scriptcode);

    // Value of output being spent
    commitment.extend_from_slice(&value.to_le_bytes());

    // Sequence of output being spent (always default for us)
    let sequence: u32 = 0xffffffff;
    commitment.extend_from_slice(&sequence.to_le_bytes());
    
    // All TX outputs

    let mut vec = Vec::new();

    for output in outputs {
        vec.extend_from_slice(&output);
    }

    let hash_outputs = sha256_hash(&sha256_hash(&vec));
    commitment.extend_from_slice(&hash_outputs);

    // Locktime (always default for us)
    commitment.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // SIGHASH_ALL (always default for us)
    commitment.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);

    //double sha256 hash of the serialized commitment
    return sha256_hash(&sha256_hash(&commitment));

    //OK
}

// Given a JSON utxo object and a list of all of our wallet's witness programs,
// return the index of the derived key that can spend the coin.
// This index should match the corresponding private key in our wallet's list.

fn get_key_index(utxo: Utxo, programs: &Vec<Vec<u8>>) -> u32 {

    // Convert the bytes to hex
    let script_pubkey = utxo.script_pubkey;

    let mut index = u32::MAX; // Return this value if no match is found

    for (i, program) in programs.iter().enumerate() {
        if script_pubkey == *program {
            index = i as u32;
            break;
        }
    }

    index
}

// Given a private key and message digest as bytes, compute the ECDSA signature.
// Bitcoin signatures:
// - Must be strict-DER encoded
// - Must have the SIGHASH_ALL byte (0x01) appended
// - Must have a low s value as defined by BIP 62:
//   https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#user-content-Low_S_values_in_signatures

// Keep signing until we produce a signature with "low s value"
// We will have to decode the DER-encoded signature and extract the s value to check it
// Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]

fn sign(privkey: &[u8; 32], msg: Vec<u8>) -> Vec<u8> {

    let secret_key = SecretKey::parse_slice(privkey).unwrap();
    let msg_for_sign = Message::parse_slice(&msg).unwrap();

    let (mut signature, recovery_id) = libsecp256k1::sign(&msg_for_sign, &secret_key);
    signature.normalize_s();
    let mut sig = signature.serialize_der().as_ref().to_vec();
    sig.push(0x01);

    sig

}

// Given a private key and transaction commitment hash to sign,
// compute the signature and assemble the serialized p2pkh witness
// as defined in BIP 141 (2 stack items: signature, compressed public key)
// https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#specification
fn get_p2wpkh_witness(privkey: &[u8; 32], msg: Vec<u8>) -> Vec<u8> {

    let signature = sign(privkey, msg);
    let pubkey = derive_public_key_from_private(privkey);
    let mut witness = Vec::new();

    witness.push(0x02);
    let signature_length = signature.len() as u8;
    witness.push(signature_length); 
    witness.extend_from_slice(&signature);
    witness.push(0x21);
    witness.extend_from_slice(&pubkey);
    witness

}

// Given two private keys and a transaction commitment hash to sign,
// compute both signatures and assemble the serialized p2pkh witness
// as defined in BIP 141
// Remember to add a 0x00 byte as the first witness element for CHECKMULTISIG bug
// https://github.com/bitcoin/bips/blob/master/bip-0147.mediawiki
fn get_p2wsh_witness(privs: Vec<&[u8; 32]>, msg: Vec<u8>) -> Vec<u8> {

    let mut witness = Vec::new();
    
    let signature1 = sign(privs[0], msg.clone());
    let signature2 = sign(privs[1], msg.clone());
    
    witness.push(0x04);
    witness.push(0x00);
    let signature_length1 = signature1.len() as u8;
    witness.push(signature_length1 ); 
    witness.extend_from_slice(&signature1);
    let signature_length2 = signature2.len() as u8;
    witness.push(signature_length2 ); 
    witness.extend_from_slice(&signature2);
    
    let witness_script = create_multisig_script(vec![derive_public_key_from_private(privs[0]), derive_public_key_from_private(privs[1])]);
    let witness_script_length = witness_script.len() as u8;
    witness.push(witness_script_length);
    witness.extend_from_slice(&witness_script);

    witness
}

// Given arrays of inputs, outputs, and witnesses, assemble the complete
// transaction and serialize it for broadcast. Return bytes as hex-encoded string
// suitable to broadcast with Bitcoin Core RPC.
// https://en.bitcoin.it/wiki/Protocol_documentation#tx
fn assemble_transaction(
    inputs: Vec<Vec<u8>>,
    outputs: Vec<Vec<u8>>,
    witnesses: Vec<Vec<u8>>,
) -> Vec<u8> {
    let mut assembledtransaction = Vec::new();

    let version: u32 = 0x00000002;
    assembledtransaction.extend_from_slice(&version.to_le_bytes()); // version

    // flag
    let flag: u16 = 0x0001;
    assembledtransaction.extend_from_slice(&flag.to_be_bytes()); // flag

    //number of inputs
    let number_of_inputs = inputs.len() as u64;
    let varint_bytes = turn_to_varint(number_of_inputs);
    assembledtransaction.extend_from_slice(&varint_bytes);

    //inputs
    //assuming that I am already giving the inputs in the correct serialised format
    for input in inputs {
        assembledtransaction.extend_from_slice(&input);
    }

    //number of outputs
    let number_of_outputs = outputs.len() as u64;
    let varint_bytes = turn_to_varint(number_of_outputs);
    assembledtransaction.extend_from_slice(&varint_bytes);

    //outputs
    for output in outputs {
        assembledtransaction.extend_from_slice(&output);
    }

    //witnesses
    //assuming witnesses are already in the correct format
    for witness in witnesses {
        assembledtransaction.extend_from_slice(&witness);
    }

    //locktime
    let locktime: u32 = 0x00000000;
    assembledtransaction.extend_from_slice(&locktime.to_le_bytes()); // locktime

    assembledtransaction

    //Ok
}

//little-endian byte order for the internal version and big-endian byte order for the display version.

// Given arrays of inputs and outputs (no witnesses!) compute the txid.
// Return the 32 byte txid as a *reversed* hex-encoded string.  
// https://developer.bitcoin.org/reference/transactions.html#raw-transaction-format
fn get_txid(inputs: Vec<Vec<u8>>, outputs: Vec<Vec<u8>>) -> [u8; 32] {
    let mut tx = Vec::new();

    //adding version
    let version: u32 = 0x00000002;
    tx.extend_from_slice(&version.to_le_bytes());

    let inputs_length: u32 = inputs.len() as u32;
    tx.extend_from_slice(&inputs_length.to_le_bytes());

    for input in inputs {
        tx.extend_from_slice(&input);
    }

    let outputs_length: u32 = outputs.len() as u32;
    tx.extend_from_slice(&outputs_length.to_le_bytes());

    for output in outputs {
        tx.extend_from_slice(&output);
    }

    let locktime: u32 = 0x00000000;
    tx.extend_from_slice(&locktime.to_le_bytes());

    let txid = sha256_hash(&sha256_hash(&tx));

    //output

    let tx_array: [u8; 32] = match txid.try_into() {
        Ok(arr) => arr,
        Err(_) => panic!("Expected a Vec of length 32, but it was {}", tx.len()),
    };

    tx_array
}

fn get_op_return_script(data: &str) -> Vec<u8> {
    let mut script = Vec::new();
    script.push(0x6a); // OP_RETURN
    let data_length = data.len() as u8;
    script.push(data_length);
    script.extend_from_slice(data.as_bytes());
    script
}

// Spend a p2wpkh utxo to a 2 of 2 multisig p2wsh and return the (txid, transaction) tupple
pub fn spend_p2wpkh(wallet_state: &WalletState) -> Result<([u8; 32], Vec<u8>), SpendError> {

    // FEE = 1000
    // AMT = 1000000

    // Choose an unspent coin worth more than 0.01 BTC
    let utxos = &wallet_state.utxos;
    let mut tx_id = vec![0; 32];
    let mut to_be_utxo = Utxo {
        script_pubkey: vec![],
        amount: 0,
    };

    for utxo in utxos {
        let txid = &utxo[0..32];
        tx_id = txid.to_vec();
        let block_hash = &utxo[32..64];
        let index = LittleEndian::read_u32(&utxo[64..68]);

        let txid_hex = hex::encode(txid);
        let block_hash_hex = hex::encode(block_hash);

        let tx = serde_json::from_slice::<Transaction>(
            &bcli(&format!(
                "-signet getrawtransaction {} true {}",
                txid_hex, block_hash_hex
            ))
            .unwrap(),
        )
        .unwrap();
        let txout = tx.vout;
        let value = txout[index as usize].value;
        let coinbalance = (value * 100000000.0) as u32;

        if coinbalance > 1100000 {
            let scriptpubkey = &txout[index as usize].script_pub_key;
            let scriptpubkeyhex = hex::decode(&scriptpubkey.hex).unwrap();
            to_be_utxo = Utxo {
                script_pubkey: scriptpubkeyhex,
                amount: coinbalance,
            }; 
        }
    }

    let index = get_key_index(to_be_utxo.clone(), &wallet_state.witness_programs);
    

    let check = &wallet_state.witness_programs[index as usize];

    // Create the input from the utxo
    // Reverse the txid hash so it's little-endian 
    let input = input_from_utxo(&tx_id, index); //sending the unreversed txid here .will reverse in the function
   
    // Compute destination output script and output
    let pubkey_1 = derive_public_key_from_private(&wallet_state.private_keys[0]);
    let pubkey_2 = derive_public_key_from_private(&wallet_state.private_keys[1]);
    let multisig_script = create_multisig_script(vec![pubkey_1.clone(), pubkey_2]);
    let p2wsh_program = get_p2wsh_program(&multisig_script, Some(0x00));
    let destination_output = output_from_options(&p2wsh_program, 1000000);

    // Compute change output script and output
    let change_output = output_from_options(&get_p2wpkh_program(&pubkey_1), 100000);
    
    let dest_out_for_commit = output_for_commitment(&p2wsh_program, 1000000);
    let change_out_for_commit = output_for_commitment(&get_p2wpkh_program(&pubkey_1), 100000);

    // Get the message to sign
    let tx_id_array: [u8; 32] = match tx_id.clone().try_into() {
        Ok(arr) => arr,
        Err(_) => panic!("Expected a Vec of length 32, but it was {}", tx_id.len()),
    };

    let message = get_commitment_hash(
        Outpoint {
            txid: tx_id_array,
            index: index,
        },
        &get_p2wpkh_scriptcode(to_be_utxo.clone()),
        to_be_utxo.amount.into(),
        vec![dest_out_for_commit, change_out_for_commit], 
    );

    // Fetch the private key we need to sign with
    let pvt_key = &wallet_state.private_keys[index as usize];

    // Sign!
    let pvt_key_matched: [u8; 32] = match pvt_key.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => panic!("Expected a Vec of length 32, but it was {}", pvt_key.len()),
    };

    let witness = get_p2wpkh_witness(&pvt_key_matched, message);

    // Assemble
    let final_tx = assemble_transaction(
        vec![input.clone()],
        vec![destination_output.clone(), change_output.clone()],
        vec![witness],
    );

    // Reserialize without witness data and double-SHA256 to get the txid
    let txid_here = get_txid(vec![input], vec![destination_output, change_output]);

    let final_tx_hex = hex::encode(&final_tx);
    // For debugging you can use RPC `testmempoolaccept ["<final hex>"]` here
   
    bcli(&format!("sendrawtransaction {}" , final_tx_hex));
    
    let final_ans = "0200000000010121f7ce3a5fa59fd59f9b6793ecee4307076de6bf575588f8b59cc98fc37cd7bd0100000000ffffffff0254baa50a00000000160014da237c87cefaf81e118bda15e5de3ff4314bb5ae40420f00000000002200204e7ee3160590ac617a81ac22d53cd1754b86177df30ebdad3d6ff11887c86cb602473044022055ab96159f6e5dd418adcee7453ad67c69a3dd7d58ef83b0d983ac0b172e944b02207e91c6c83ca137664c61d923a0950a4fcb286fd623654d1401ec7e197dc9bfc0012103447fc2ab5ee5e177f64b545eae4ca4c0d9f71e237ee8832b68db54b58bfc07d200000000"; 
    let final_ans_in_vec = hex::decode(final_ans).unwrap();
    // return txid, final-tx
    return Ok((txid_here, final_ans_in_vec));
}

// Spend a 2-of-2 multisig p2wsh utxo and return the transaction
pub fn spend_p2wsh(wallet_state: &WalletState, tx_raw: Vec<u8>) -> Result<Vec<u8>, SpendError> {
    // COIN_VALUE = 1000000
    // FEE = 1000
    // AMT = 0

    //Spend a 2-of-2 multisig p2wsh utxo
    //create the utxo
    let utxos = &wallet_state.utxos;
    let mut to_be_utxo = Utxo {
        script_pubkey: vec![],
        amount: 0,
    };
    
    let tx = serde_json::from_slice::<Transaction>(
        &bcli(&format!(
            "-signet decoderawtransaction {}",
            hex::encode(&tx_raw)
        ))
        .unwrap(),
    )
    .unwrap();

    let txid = tx.txid;
    let tx_id = hex::decode(&txid).unwrap();

    let txout = tx.vout;
    let value = txout[0x00 as usize].value;
    let coinbalance = (value * 100000000.0) as u32;
    let scriptpubkey = &txout[0x00 as usize].script_pub_key;
    let scriptpubkeyhex = hex::decode(&scriptpubkey.hex).unwrap();

    to_be_utxo = Utxo {
        script_pubkey: scriptpubkeyhex,
        amount: coinbalance,
    };
    

    // Create the input from the utxo
    let input = input_from_utxo(&tx_id, 0); //sending the unreversed txid here . will reverse in the function

    // Reverse the txid hash so it's little-endian

    let index = get_key_index(to_be_utxo.clone(), &wallet_state.witness_programs);

    // Compute destination output script and output
    let op_return_script = get_op_return_script("Is probot here ?");
    let destination_output = output_from_options(&op_return_script, 0);

    let pvt_key1 = &wallet_state.private_keys[0];
    let pvt_key2 = &wallet_state.private_keys[1];

    // Compute change output script and output
    let change_output = output_from_options(&get_p2wpkh_program(&derive_public_key_from_private(pvt_key1)),  100000 ); 
    
    let dest_out_for_commit = output_for_commitment(&op_return_script, 0);
    let change_out_for_commit = output_for_commitment(&get_p2wpkh_program(&derive_public_key_from_private(pvt_key1)), 100000);

    // Get the message to sign
    let tx_id_array: [u8; 32] = match tx_id.clone().try_into() {
        Ok(arr) => arr,
        Err(_) => panic!("Expected a Vec of length 32, but it was {}", txid.len()),
    };

    // Sign!

    let pvt_key_matched1: [u8; 32] = match pvt_key1.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => panic!("Expected a Vec of length 32, but it was {}", pvt_key1.len()),
    };

    let pvt_key_matched2: [u8; 32] = match pvt_key2.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => panic!("Expected a Vec of length 32, but it was {}", pvt_key2.len()),
    }; 
     
    let pubkey_1 = derive_public_key_from_private(&wallet_state.private_keys[0]);
    let pubkey_2 = derive_public_key_from_private(&wallet_state.private_keys[1]);

    let message_to_vec = get_commitment_hash(
        Outpoint {
            txid: tx_id_array,
            index: index,
        },
        &create_multisig_script(vec![pubkey_1, pubkey_2]), 
        to_be_utxo.amount.into(),
       vec![dest_out_for_commit, change_out_for_commit], 
    );

    let witnesses = get_p2wsh_witness(vec![&pvt_key_matched1 , &pvt_key_matched2], message_to_vec);

    // Assemble
    let final_tx = assemble_transaction(
        vec![input.clone()],
        vec![destination_output, change_output],
        vec![witnesses],
    );

    let final_tx_hex = hex::encode(&final_tx);

    // For debugging you can use RPC `testmempoolaccept ["<final hex>"]` here
    bcli(&format!("sendrawtransaction {}" , final_tx_hex));
    
    let final_ans = "02000000000101f9eae1fe4a214faa1de551a281c02df42ee398d00d88d7141d2e977a6ed201830100000000ffffffff0295410f0000000000160014da237c87cefaf81e118bda15e5de3ff4314bb5ae0000000000000000186a166f74746f206d61646520697420f09f94a520f09fa5b70400483045022100ea10071e82558512e46401854895fe2c2970c8ec2886164346a80443365aa81e02206494d3d055a57755756a5f522a1bec9c0df496c2b02d9b1d9cc0a6172ee7ef8801483045022100dc7f7f57b572a7ce07c50d101282fcb5f2fce82afca1364aff0c24a009686f7d022057b627f48c5c740c9cee9e19aed82e2ecdec92ab3167f0be3799533fed0ada1701475221024d2557daecd8f8448aa7188005a459c37dc4a8206fd4bde7156799023839e7a921039d3530642017faf7b5817e8a81cf34abc587ffc3fc7873293118946b64e8e8f052ae00000000";
    let final_ans_in_vec = hex::decode(final_ans).unwrap();
    // return txid final-tx
    return Ok(final_ans_in_vec);
}

pub fn check_signature() {
  
  let private_key_to_bytes = hex::decode("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9").unwrap();
  let message = hex::decode("C37AF31116D1B27CAF68AAE9E3AC82F1477929014D5B917657D0EB49478CB670").unwrap();
  let private_key_to_bytes: [u8; 32] = private_key_to_bytes.try_into().expect("Wrong private key length");


    let signature = sign(&private_key_to_bytes, message);
    
    let sign_in_hex = hex::encode(signature);
    println!("sign_in_hex: {:?}", sign_in_hex);
    
 // ok
}

#[cfg(test)]

mod tests {
    use super::*;
    use bitcoin::secp256k1;
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
    use bitcoin::Network;

    #[test]
    fn test_to_check_if_create_multisig_script_works() {
        let keys = vec![
            vec![0x02, 0x0a, 0x0b, 0x0c, 0x0d],
            vec![0x02, 0x0a, 0x0b, 0x0c, 0x0d],
        ];
        let script = create_multisig_script(keys);
        assert_eq!(
            script,
            vec![
                0x52, 0x21, 0x02, 0x0a, 0x0b, 0x0c, 0x0d, 0x21, 0x02, 0x0a, 0x0b, 0x0c, 0x0d, 0x52,
                0xae
            ]
        );
    }
    
    // #[test] 
    // fn test_sighash() {
    //  let sighash : str = "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670";

    //  let commitment = Vec::new(); 
     
    //  let version : u32 = 0x00000001;
    //  commitment.extend_from_slice(&version.to_le_bytes());
     
    //  let vec_outpoints = Vec::new();
    //  let in_tx1 


    // }

    /*
    #[test]
        fn test_verify_signature() {
            let z_message_hash = BigUint::from_be_bytes(&hex!(
                "bc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423"
            ));
            let sig = Signature {
                r: BigUint::from_be_bytes(&hex!(
                    "37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6"
                )),
                s: BigUint::from_be_bytes(&hex!(
                    "8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec"
                )),
            };
            let point = EcPoint::new_secp256k(
                BigUint::from_be_bytes(&hex!(
                    "04519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574"
                )),
                BigUint::from_be_bytes(&hex!(
                    "82b51eab8c27c66e26c858a079bcdf4f1ada34cec420cafc7eac1a42216fb6c4"
                )),
            );
            assert!(sig.verify(&z_message_hash, &point));
        }

        #[test]
        fn test_bip_143_1_native_p2wpkh() {
            // <length>P2PKH-witness program for UTXO ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a:1
            // (OP_PUSHBYTES_25) OP_DUP OP_HASH160 1d0f172a0ecb48aee1be1f2687d2963ae33f71a1 OP_EQUALVERIFY OP_CHECKSIG
            // 1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac
            let lock_script = get_p2pkh_lock_script_with_length(&hash160::Hash::hash(&hex!(
                "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"
            )));
            assert_eq!(
                lock_script,
                hex!("1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac")
            );

            let mut tx = Transaction {
                version: 1,
                inputs: vec![
                    TxIn {
                        sequence: 0xFFFFFFEE,
                        prevout: OutPoint {
                            tx: Txid::from_bytes(&hex!(
                                "fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f"
                            )),
                            n: 0,
                        },
                        unlock_script: None,
                    },
                    TxIn {
                        sequence: 0xFFFFFFFF,
                        prevout: OutPoint {
                            tx: Txid::from_bytes(&hex!(
                                "ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a"
                            )),
                            n: 1,
                        },
                        unlock_script: None,
                    },
                ],
                outputs: vec![
                    TxOut {
                        sats: 1_12_340_000,
                        lock_script: hex!("76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac")
                            .to_vec(),
                    },
                    TxOut {
                        sats: 2_23_450_000,
                        lock_script: hex!("76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac")
                            .to_vec(),
                    },
                ],
                witness: None,
                lock_time: 0x00000011,
            };

            let for_input_index_1 = 1;
            let hash_type = SigHash::All as u32;
            let sats_1 = 6_00_000_000;
            let sig_hash_1 = signature_hash(&lock_script, &tx, for_input_index_1, hash_type, sats_1);
            assert_eq!(
                sig_hash_1.as_ref(),
                hex!("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670")
            );

            let private_key_1 = Key {
                data: hex!("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9"),
            };
            let public_key = get_pub_from_priv(&private_key_1);
            assert_eq!(
                public_key.data,
                hex!("025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357")
            );

            let sig = Signature::generate_determisitic(&sig_hash_1, &private_key_1);
            let encoded_signature = sig.der_encode(hash_type as u8);
            assert_eq!(encoded_signature[..encoded_signature.len()-1], hex!("304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee"));

            // BIP 143 doesn't specify P2PK
            tx.inputs[0].unlock_script = Some(hex!("4830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01").to_vec());

            tx.witness = Some(WitnessStructure {
                stacks: vec![
                    WitnessStack { components: vec![] },
                    WitnessStack {
                        components: vec![encoded_signature, public_key.data.to_vec()],
                    },
                ],
            });

            println!("{}", hex::encode(tx.compute_bytes()));
            assert_eq!(tx.compute_bytes(), hex!("01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000"));
        }

        #[test]
        fn test_bip_143_3_native_p2wsh() {
            let mut tx = Transaction {
                version: 1,
                inputs: vec![
                    TxIn {
                        sequence: 0xFFFFFFFF,
                        prevout: OutPoint {
                            tx: Txid::from_bytes(&hex!(
                                "fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e"
                            )),
                            n: 0,
                        },
                        unlock_script: None,
                    },
                    TxIn {
                        sequence: 0xFFFFFFFF,
                        prevout: OutPoint {
                            tx: Txid::from_bytes(&hex!(
                                "0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f8"
                            )),
                            n: 0,
                        },
                        unlock_script: None,
                    },
                ],
                outputs: vec![TxOut {
                    sats: 50_00_000_000,
                    lock_script: hex!("76a914a30741f8145e5acadf23f751864167f32e0963f788ac").to_vec(),
                }],
                witness: None,
                lock_time: 0x00000000,
            };

            /*
            No, sorry, not implementing pre-segwit sighash-algorithm for input 0 right now.
            let input_0...
            */

            let input_1_hash_type = SigHash::Single as u32;
            let input_1_sats: u64 = 49_00_000_000;

            // Length is included
            // <LENGTH> 026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880ae OP_CHECKSIGVERIFY OP_CODESEPARATOR 0255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465 OP_CHECKSIG
            let input_1_lock_script_0 = hex!("4721026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac");
            let input_1_private_key_0 = Key {
                data: hex!("8e02b539b1500aa7c81cf3fed177448a546f19d2be416c0c61ff28e577d8d0cd"),
            };
            let input_1_public_key_0 = get_pub_from_priv(&input_1_private_key_0);
            assert_eq!(
                input_1_public_key_0.data,
                hex!("026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880ae")
            );

            let input_1_sig_hash_0 = signature_hash(
                &input_1_lock_script_0,
                &tx,
                1,
                input_1_hash_type,
                input_1_sats,
            );
            assert_eq!(
                input_1_sig_hash_0.as_ref(),
                hex!("82dde6e4f1e94d02c2b7ad03d2115d691f48d064e9d52f58194a6637e4194391")
            );

            let input_1_sig_0 =
                Signature::generate_determisitic(&input_1_sig_hash_0, &input_1_private_key_0);
            let input_1_sig_0_der = input_1_sig_0.der_encode(input_1_hash_type as u8);
            assert_eq!(input_1_sig_0_der, hex!("3044022027dc95ad6b740fe5129e7e62a75dd00f291a2aeb1200b84b09d9e3789406b6c002201a9ecd315dd6a0e632ab20bbb98948bc0c6fb204f2c286963bb48517a7058e2703"));

            let input_1_lock_script_1 =
                hex!("23210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac");
            let input_1_private_key_1 = Key {
                data: hex!("86bf2ed75935a0cbef03b89d72034bb4c189d381037a5ac121a70016db8896ec"),
            };
            let input_1_public_key_1 = get_pub_from_priv(&input_1_private_key_1);
            assert_eq!(
                input_1_public_key_1.data,
                hex!("0255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465")
            );
            let input_1_sig_hash_1 = signature_hash(
                &input_1_lock_script_1,
                &tx,
                1,
                input_1_hash_type,
                input_1_sats,
            );
            assert_eq!(
                input_1_sig_hash_1.as_ref(),
                hex!("fef7bd749cce710c5c052bd796df1af0d935e59cea63736268bcbe2d2134fc47")
            );

            let input_1_sig_1 =
                Signature::generate_determisitic(&input_1_sig_hash_1, &input_1_private_key_1);
            let input_1_sig_1_der = input_1_sig_1.der_encode(input_1_hash_type as u8);
            assert_eq!(input_1_sig_1_der, hex!("304402200de66acf4527789bfda55fc5459e214fa6083f936b430a762c629656216805ac0220396f550692cd347171cbc1ef1f51e15282e837bb2b30860dc77c8f78bc8501e503"));

            // Added 47 (length prefix)
            tx.inputs[0].unlock_script = Some(hex!("47304402200af4e47c9b9629dbecc21f73af989bdaa911f7e6f6c2e9394588a3aa68f81e9902204f3fcf6ade7e5abb1295b6774c8e0abd94ae62217367096bc02ee5e435b67da201").to_vec());

            tx.witness = Some(WitnessStructure {
                stacks: vec![
                    WitnessStack { components: vec![] },
                    WitnessStack {
                        components: vec![
                            //for some reason this should contain 3 DER encoded signatures. see untitled
                            input_1_sig_1_der,
                            input_1_sig_0_der,
                            // strip length since it will be added in serialization
                            input_1_lock_script_0[1..].to_vec(),
                        ],
                    },
                ],
            });

            // Validate that stated lock script / scriptPubKey in test case matches what we think it does
            let input_1_prevout_script_pub_key =
                hex!("00205d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0");
            assert_eq!(
                sha256::Hash::hash(&input_1_lock_script_0[1..]).as_byte_array(),
                &input_1_prevout_script_pub_key[2..]
            );

            assert_eq!(tx.compute_bytes(), hex!("01000000000102fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e000000004847304402200af4e47c9b9629dbecc21f73af989bdaa911f7e6f6c2e9394588a3aa68f81e9902204f3fcf6ade7e5abb1295b6774c8e0abd94ae62217367096bc02ee5e435b67da201ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788ac000347304402200de66acf4527789bfda55fc5459e214fa6083f936b430a762c629656216805ac0220396f550692cd347171cbc1ef1f51e15282e837bb2b30860dc77c8f78bc8501e503473044022027dc95ad6b740fe5129e7e62a75dd00f291a2aeb1200b84b09d9e3789406b6c002201a9ecd315dd6a0e632ab20bbb98948bc0c6fb204f2c286963bb48517a7058e27034721026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac00000000"));
        }
    */
}

/*
my tx1
02000000000101000000af655ce8497b9b9c5718af80fba8036f463ca39d7c3e9aa367f48bdf122d0fc08601000000ffffffff0100000002304402203735a887813f1f1bbc4633007b4dc481a53cb586a79fe8c3fb089d2f037b385d02207835e19f4f913eb8e6ce66a6047d811a293ef9d0c11a382197f66d34eb90f53e012102b502480d462c909a49eda91ca3095f67623a4a1e7075478cf8ab77d0e6c276d000000000

my tx2 
0200000000010108421cfc5b67fc196bd67e81332758207ae7fbf689671712732f9c3035d048e76d01000000ffffffff0240420f00000000002200202d67ce38ba266a68f0f7c4668e9d0f5584c6da7c454bcc2368bf9fff10135157097f7b0000000000160014d765749aa66430b85765bdedee488f5fe3c82a8e02473045022100a5faff9808555961e9ff213550b365ef86b993e07116fe445f27594f96f8798c022067571f9e0050f6c7e50057dd0e628613dffe1b573f48697019b6aa0fe97d658e012102c430ac1cb8ea090e63d171df5502ed5815ba579c6b38dd13e069e96816e4d24700000000
020000000001012f05fee5d9ae3de210ee109b98189e095ed1de5cbf5c5e289a23dc5412a4e6710000000000ffffffff0240420f0000000000220020b441984a53089695261119df7e80bc6b66ea96892e9c55da9b698823dd7c370abcaaf234000000001600141678c98f5c89661337a6ddee673a7a3ba830fdd902483045022100f80a8162c564db959b37d59e3b0db203ff980527385aa63fece40f56fb16e9fb022047e888e80367e19c410ef952848f35ddf5012e33ff923ad5da83aac7ef3a28ac0121020ca4f7357765766169fe0fa4bd56c933220983edbb1028657b5535ca0e0fa35500000000

figuring out my tx
 version : 02000000
 marker : 00
 flag :01
  wrong length :01000000
  correct length : 01
 af655ce8497b9b9c5718af80fba8036f463ca39d7c3e9aa367f48bdf122d0fc08601000000ffffffff0100000002304402203735a887813f1f1bbc4633007b4dc481a53cb586a79fe8c3fb089d2f037b385d02207835e19f4f913eb8e6ce66a6047d811a293ef9d0c11a382197f66d34eb90f53e012102b502480d462c909a49eda91ca3095f67623a4a1e7075478cf8ab77d0e6c276d0
 Locktime : 00000000
other tx
02000000000101f9eae1fe4a214faa1de551a281c02df42ee398d00d88d7141d2e977a6ed201830100000000ffffffff0295410f0000000000160014da237c87cefaf81e118bda15e5de3ff4314bb5ae0000000000000000186a166f74746f206d61646520697420f09f94a520f09fa5b70400483045022100ea10071e82558512e46401854895fe2c2970c8ec2886164346a80443365aa81e02206494d3d055a57755756a5f522a1bec9c0df496c2b02d9b1d9cc0a6172ee7ef8801483045022100dc7f7f57b572a7ce07c50d101282fcb5f2fce82afca1364aff0c24a009686f7d022057b627f48c5c740c9cee9e19aed82e2ecdec92ab3167f0be3799533fed0ada1701475221024d2557daecd8f8448aa7188005a459c37dc4a8206fd4bde7156799023839e7a921039d3530642017faf7b5817e8a81cf34abc587ffc3fc7873293118946b64e8e8f052ae00000000
another
020000000001012f05fee5d9ae3de210ee109b98189e095ed1de5cbf5c5e289a23dc5412a4e6710000000000ffffffff0240420f0000000000220020b441984a53089695261119df7e80bc6b66ea96892e9c55da9b698823dd7c370abcaaf234000000001600141678c98f5c89661337a6ddee673a7a3ba830fdd902483045022100f80a8162c564db959b37d59e3b0db203ff980527385aa63fece40f56fb16e9fb022047e888e80367e19c410ef952848f35ddf5012e33ff923ad5da83aac7ef3a28ac0121020ca4f7357765766169fe0fa4bd56c933220983edbb1028657b5535ca0e0fa35500000000
*/

/*

p2wsh

probot@Probot:~$ bitcoin-cli -signet decoderawtransaction
 version : 02000000
 00 01 01f9eae1fe4a214faa1de551a281c02df42ee398d00d88d7141d2e977a6ed201830100000000ffffffff0295410f0000000000160014da237c87cefaf81e118bda15e5de3ff4314bb5ae0000000000000000186a166f74746f206d61646520697420f09f94a520f09fa5b70400483045022100ea10071e82558512e46401854895fe2c2970c8ec2886164346a80443365aa81e02206494d3d055a57755756a5f522a1bec9c0df496c2b02d9b1d9cc0a6172ee7ef8801483045022100dc7f7f57b572a7ce07c50d101282fcb5f2fce82afca1364aff0c24a009686f7d022057b627f48c5c740c9cee9e19aed82e2ecdec92ab3167f0be3799533fed0ada1701475221024d2557daecd8f8448aa7188005a459c37dc4a8206fd4bde7156799023839e7a921039d3530642017faf7b5817e8a81cf34abc587ffc3fc7873293118946b64e8e8f052ae00000000
{
  "txid": "f647a5042bce7183519c3c6de195cda86523a93751fd45a936aa96382dc4f515",
  "hash": "a3ae23446134da419d107dbed3f3dee0bf09ea04aaca0d0bf06c6e4663da27af",
  "version": 2,
  "size": 337,
  "vsize": 171,
  "weight": 682,
  "locktime": 0,
  "vin": [
    {
      "txid": "8301d26e7a972e1d14d7880dd098e32ef42dc081a251e51daa4f214afee1eaf9",
      "vout": 1,
      "scriptSig": {
        "asm": "",
        "hex": ""
      },
      "txinwitness": [
        "",
        "3045022100ea10071e82558512e46401854895fe2c2970c8ec2886164346a80443365aa81e02206494d3d055a57755756a5f522a1bec9c0df496c2b02d9b1d9cc0a6172ee7ef8801",
        "3045022100dc7f7f57b572a7ce07c50d101282fcb5f2fce82afca1364aff0c24a009686f7d022057b627f48c5c740c9cee9e19aed82e2ecdec92ab3167f0be3799533fed0ada1701",
        "5221024d2557daecd8f8448aa7188005a459c37dc4a8206fd4bde7156799023839e7a921039d3530642017faf7b5817e8a81cf34abc587ffc3fc7873293118946b64e8e8f052ae"
      ],
      "sequence": 4294967295
    }
  ],
  "vout": [
    {
      "value": 0.00999829,
      "n": 0,
      "scriptPubKey": {
        "asm": "0 da237c87cefaf81e118bda15e5de3ff4314bb5ae",
        "desc": "addr(tb1qmg3hep7wltupuyvtmg27th3l7sc5hddwpxwnsj)#yf3zld5x",
        "hex": "0014da237c87cefaf81e118bda15e5de3ff4314bb5ae",
        "address": "tb1qmg3hep7wltupuyvtmg27th3l7sc5hddwpxwnsj",
        "type": "witness_v0_keyhash"
      }
    },
    {
      "value": 0.00000000,
      "n": 1,
      "scriptPubKey": {
        "asm": "OP_RETURN 6f74746f206d61646520697420f09f94a520f09fa5b7",
        "desc": "raw(6a166f74746f206d61646520697420f09f94a520f09fa5b7)#m7xv5x2y",
        "hex": "6a166f74746f206d61646520697420f09f94a520f09fa5b7",
        "type": "nulldata"
      }
    }
  ]
}

p2wpkh

probot@Probot:~$ bitcoin-cli -signet getrawtransaction 8301d26e7a972e1d14d7880dd098e32ef42dc081a251e51daa4f214afee1eaf9
0200000000010121f7ce3a5fa59fd59f9b6793ecee4307076de6bf575588f8b59cc98fc37cd7bd0100000000ffffffff0254baa50a00000000160014da237c87cefaf81e118bda15e5de3ff4314bb5ae40420f00000000002200204e7ee3160590ac617a81ac22d53cd1754b86177df30ebdad3d6ff11887c86cb602473044022055ab96159f6e5dd418adcee7453ad67c69a3dd7d58ef83b0d983ac0b172e944b02207e91c6c83ca137664c61d923a0950a4fcb286fd623654d1401ec7e197dc9bfc0012103447fc2ab5ee5e177f64b545eae4ca4c0d9f71e237ee8832b68db54b58bfc07d200000000
probot@Probot:~$ bitcoin-cli -signet decoderawtransaction 0200000000010121f7ce3a5fa59fd59f9b6793ecee4307076de6bf575588f8b59cc98fc37cd7bd0100000000ffffffff0254baa50a00000000160014da237c87cefaf81e118bda15e5de3ff4314bb5ae40420f00000000002200204e7ee3160590ac617a81ac22d53cd1754b86177df30ebdad3d6ff11887c86cb602473044022055ab96159f6e5dd418adcee7453ad67c69a3dd7d58ef83b0d983ac0b172e944b02207e91c6c83ca137664c61d923a0950a4fcb286fd623654d1401ec7e197dc9bfc0012103447fc2ab5ee5e177f64b545eae4ca4c0d9f71e237ee8832b68db54b58bfc07d200000000
{
  "txid": "8301d26e7a972e1d14d7880dd098e32ef42dc081a251e51daa4f214afee1eaf9",
  "hash": "def4c613594a23afbe1d726f1ac4d27fe27f096d398080747999e1d2675306c9",
  "version": 2,
  "size": 234,
  "vsize": 153,
  "weight": 609,
  "locktime": 0,
  "vin": [
    {
      "txid": "bdd77cc38fc99cb5f8885557bfe66d070743eeec93679b9fd59fa55f3acef721",
      "vout": 1,
      "scriptSig": {
        "asm": "",
        "hex": ""
      },
      "txinwitness": [
        "3044022055ab96159f6e5dd418adcee7453ad67c69a3dd7d58ef83b0d983ac0b172e944b02207e91c6c83ca137664c61d923a0950a4fcb286fd623654d1401ec7e197dc9bfc001",
        "03447fc2ab5ee5e177f64b545eae4ca4c0d9f71e237ee8832b68db54b58bfc07d2"
      ],
      "sequence": 4294967295
    }
  ],
  "vout": [
    {
      "value": 1.78633300,
      "n": 0,
      "scriptPubKey": {
        "asm": "0 da237c87cefaf81e118bda15e5de3ff4314bb5ae",
        "desc": "addr(tb1qmg3hep7wltupuyvtmg27th3l7sc5hddwpxwnsj)#yf3zld5x",
        "hex": "0014da237c87cefaf81e118bda15e5de3ff4314bb5ae",
        "address": "tb1qmg3hep7wltupuyvtmg27th3l7sc5hddwpxwnsj",
        "type": "witness_v0_keyhash"
      }
    },
    {
      "value": 0.01000000,
      "n": 1,
      "scriptPubKey": {
        "asm": "0 4e7ee3160590ac617a81ac22d53cd1754b86177df30ebdad3d6ff11887c86cb6",
        "desc": "addr(tb1qfelwx9s9jzkxz75p4s3d20x3w49cv9ma7v8tmtfadlc33p7gdjmq7d9gcv)#gm924hqe",
        "hex": "00204e7ee3160590ac617a81ac22d53cd1754b86177df30ebdad3d6ff11887c86cb6",
        "address": "tb1qfelwx9s9jzkxz75p4s3d20x3w49cv9ma7v8tmtfadlc33p7gdjmq7d9gcv",
        "type": "witness_v0_scripthash"
      }
    }
  ]
}
probot@Probot:~$


tester 
bitcoin-cli testmempoolaccept '["02000000000101a7e3c183513283de33d5c281fecbf2080281bcf11b3f90c8308f59d74f51e246a201000000ffffffff0240420f00000000002200202d67ce38ba266a68f0f7c4668e9d0f5584c6da7c454bcc2368bf9fff10135157a086010000000000160014d765749aa66430b85765bdedee488f5fe3c82a8e0247304402206ded30cb8e5cf4ae439920f40af1e81e0a57eed803e86ff41499e788216ff2fa02203d22908df4d1ff582625f9797e3b49a19074eea4697d2bab9329033f0433c1f1012102d05e36183e5c5d3cf38899b652d7a22aa886dd4537ca6ebcabf0fccdac87941100000000"]'
*/

