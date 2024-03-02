# Which tx in block 257,343 spends the coinbase output of block 256,128?
# 256128 hash = 0000000000000007440fc4df4d953acbf67ad26adb2d7dff7bee90318b41e6c6
# 257343 hash = 0000000000000004f3fb306baa0638ffc181bc6b9752f9325612559c04d57bf9
# tx[0] is the coinbase tx id
# tx[0] = 611c5a0972d28e421a2308cb2a2adb8f369bb003b96eb04a3ec781bf295b74bc

ihash=$(bitcoin-cli -rpcconnect=35.209.148.157 -rpcuser=user_235 -rpcpassword=GEG8uy8Z4RNv getblockhash 256128)
coinbaseTx=$(bitcoin-cli -rpcconnect=35.209.148.157 -rpcuser=user_235 -rpcpassword=GEG8uy8Z4RNv getblock $ihash | jq -r .tx[0])
# correct till here
fhash=$(bitcoin-cli -rpcconnect=35.209.148.157 -rpcuser=user_235 -rpcpassword=GEG8uy8Z4RNv getblockhash 257343)
tx_array=$(bitcoin-cli -rpcconnect=35.209.148.157 -rpcuser=user_235 -rpcpassword=GEG8uy8Z4RNv getblock $fhash | jq -r .tx)
# getting the array but in quotes

# get tx_array length
tx_array_length=$(echo $tx_array | jq length)

# loop through tx_array
for (( i=0; i<$tx_array_length; i++ )); do
    tx=$(echo $tx_array | jq -r .[$i])
    raw=$(bitcoin-cli -rpcconnect=35.209.148.157 -rpcuser=user_235 -rpcpassword=GEG8uy8Z4RNv getrawtransaction $tx)
    decoded=$(bitcoin-cli -rpcconnect=35.209.148.157 -rpcuser=user_235 -rpcpassword=GEG8uy8Z4RNv decoderawtransaction $raw)
    vin=$(echo $decoded | jq -r .vin)
    vin_length=$(echo $vin | jq length)
    for (( j=0; j<$vin_length; j++ )); do
        vin_txid=$(echo $vin | jq -r .[$j].txid)
        if [ "$vin_txid" == "$coinbaseTx" ]; then
            echo $tx
        fi
    done
done
