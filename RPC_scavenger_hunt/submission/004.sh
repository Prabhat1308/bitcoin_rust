# Using descriptors, compute the 100th taproot address derived from this extended public key:
#   `xpub6Cx5tvq6nACSLJdra1A6WjqTo1SgeUZRFqsX5ysEtVBMwhCCRa4kfgFqaT2o1kwL3esB1PsYr3CUdfRZYfLHJunNWUABKftK2NjHUtzDms2`

#bc1p3yrtpvv6czx63h2sxwmeep8q98h94w4288fc4cvrkqephalydfgszgacf9
addr=$(bitcoin-cli -rpcconnect=35.209.148.157 -rpcuser=user_235 -rpcpassword=GEG8uy8Z4RNv deriveaddresses "tr(xpub6Cx5tvq6nACSLJdra1A6WjqTo1SgeUZRFqsX5ysEtVBMwhCCRa4kfgFqaT2o1kwL3esB1PsYr3CUdfRZYfLHJunNWUABKftK2NjHUtzDms2/100)#5p2mg7zx" | tr -d '"' | sed 's/\[//;s/\]//')
echo "$addr"



