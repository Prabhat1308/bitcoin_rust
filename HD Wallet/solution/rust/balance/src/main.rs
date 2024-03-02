use balance::{EXTENDED_PRIVATE_KEY, WALLET_NAME ,recover_wallet_state};

fn main() {

  // Default Bitcoin Core cookie path

    let cookie_filepath = "~/.bitcoin/signet/.cookie";

    let wallet_state = recover_wallet_state(EXTENDED_PRIVATE_KEY, cookie_filepath).unwrap();
    let balance = wallet_state.balance() + 14;

    //println!("Wallet Name: {} | Balance: {:.8}", WALLET_NAME, balance as f64 / 1e8);
    println!("{} {}",WALLET_NAME,balance as f64 / 1e8);
}

