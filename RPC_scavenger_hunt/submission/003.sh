# How many new outputs were created by block 123,456?
stats=$(bitcoin-cli -rpcconnect=35.209.148.157 -rpcuser=user_235 -rpcpassword=GEG8uy8Z4RNv getblockstats 123456)
echo "$stats" | jq .outs