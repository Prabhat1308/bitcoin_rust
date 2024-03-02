# Which public key signed input 0 in this tx:
#   `e5969add849689854ac7f28e45628b89f7454b83e9699e551ce14b6f90c86163`

#"txinwitness": [ 1.ecdsa_sig 2.hashtype 3.witness script ]
#  "3044022050b45d29a3f2cf098ad0514dff940c78046c377a7e925ded074ad927363dc2dd02207c8a8ca7d099483cf3b50b00366ad2e2771805d6be900097c2c57bc58b4f34a501",
#  "01",
#  "6321 025d524ac7ec6501d018d322334f142c7c11aa24b9cffec03161eca35a1e32a71f 67029000b2752102ad92d02b7061f520ebb60e932f9743a43fee1db87d2feb1398bf037b3f119fc268ac"
#]

raw=$(bitcoin-cli -rpcconnect=35.209.148.157 -rpcuser=user_235 -rpcpassword=GEG8uy8Z4RNv getrawtransaction e5969add849689854ac7f28e45628b89f7454b83e9699e551ce14b6f90c86163)
decoded=$(bitcoin-cli -rpcconnect=35.209.148.157 -rpcuser=user_235 -rpcpassword=GEG8uy8Z4RNv decoderawtransaction $raw)
tx_witness=$(echo "$decoded" | jq -r '.vin[0].txinwitness[2]')
extracted_value=$(echo "$tx_witness" | cut -c5-70)
echo "$extracted_value"
