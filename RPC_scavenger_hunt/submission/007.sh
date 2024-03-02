hash=$(bitcoin-cli -rpcconnect=35.209.148.157 -rpcuser=user_235 -rpcpassword=GEG8uy8Z4RNv getblockhash 123321)
tx=$(bitcoin-cli -rpcconnect=35.209.148.157 -rpcuser=user_235 -rpcpassword=GEG8uy8Z4RNv getblock $hash | jq -r '.tx[6]')
addr=$(bitcoin-cli -rpcconnect=35.209.148.157 -rpcuser=user_235 -rpcpassword=GEG8uy8Z4RNv gettxout $tx 0 | jq -r '.scriptPubKey.address')
echo "$addr"

#"tx": [
 #   "255fb8ff561fc1668c79fbf902f394ffd1fbf29797d6d9266821ca4baef56906",
 #   "551d33c93e4a7d7753b621bd275314ae4fe9741a9b4e54894d36138614d182e9",
 #  "481bbbaafa310605a5cd049432c7636e1ec8008bdbb420ffacb9c4a1477f0d95",
 #   "4437c011da6875608c20848f18d83beb8354314116bbf9e99caf8a20a2784aba",
 #   "136a01c0ab4943a501cf4f44484202ccfe41b93a8a2d7d1fc2874295a86d59c3",
 #   "67784993545a27ace47e5dd293f4fbf0bfea8ac706634497acf6ded523c93807",
 #   "097e521fee933133729cfc34424c4277b36240b13ae4b01fda17756da1848c1e",
 #   "8ff78938648b2fb5d2dfe4094f98b8e2a34d53064abbca4b17db271001ae4078"
 # ]