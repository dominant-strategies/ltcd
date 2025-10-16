module github.com/dominant-strategies/ltcd/ltcutil/psbt

go 1.17

require (
	github.com/davecgh/go-spew v1.1.1
	github.com/stretchr/testify v1.8.3
	lukechampine.com/blake3 v1.2.1
)

require (
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f // indirect
	github.com/decred/dcrd/crypto/blake256 v1.0.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/ltcsuite/secp256k1 v0.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/crypto v0.7.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace (
	github.com/dominant-strategies/ltcd => ../..
	github.com/dominant-strategies/ltcd/ltcutil => ..
	github.com/dominant-strategies/ltcd/secp256k1_ltc => ../../secp256k1_ltc
)
