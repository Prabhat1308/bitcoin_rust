# What is the hash of block 654,321?

hash=$(bitcoin-cli -rpcconnect=35.209.148.157 -rpcuser=user_235 -rpcpassword=GEG8uy8Z4RNv getblockhash 654321)
echo "$hash"
