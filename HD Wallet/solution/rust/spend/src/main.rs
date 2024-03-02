extern crate balance;
use balance::{recover_wallet_state, EXTENDED_PRIVATE_KEY};

use spend::{spend_p2wpkh, spend_p2wsh};
fn main() {
    // // Default Bitcoin Core cookie path
    let cookie_filepath = "~/.bitcoin/signet/.cookie";

    let wallet_state = recover_wallet_state(EXTENDED_PRIVATE_KEY, cookie_filepath).unwrap();

    // check_signature();

    let (txid1, tx1) = spend_p2wpkh(&wallet_state).unwrap();
    let tx1_as_hex = hex::encode(tx1.clone());
    println!("{}", tx1_as_hex); 
    let tx2 = spend_p2wsh(&wallet_state, tx1).unwrap();
    let tx2_as_hex = hex::encode(tx2);
    println!("{}", tx2_as_hex); 

}
