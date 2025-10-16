module github.com/dominant-strategies/ltcd/ltcutil

go 1.17

require (
	github.com/aead/siphash v1.0.1
	github.com/davecgh/go-spew v1.1.1
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1
	github.com/kkdai/bstream v1.0.0
	golang.org/x/crypto v0.7.0
	lukechampine.com/blake3 v1.2.1
)

require (
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f // indirect
	github.com/decred/dcrd/crypto/blake256 v1.0.0 // indirect
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	github.com/ltcsuite/secp256k1 v0.1.1 // indirect
	golang.org/x/sys v0.13.0 // indirect
)

replace github.com/dominant-strategies/ltcd/secp256k1_ltc => ../secp256k1_ltc
