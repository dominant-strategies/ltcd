package secp256k1_ltc

/*
#cgo CFLAGS: -Isrc
#define USE_BASIC_CONFIG
#define ENABLE_MODULE_GENERATOR
#define ENABLE_MODULE_BULLETPROOF

// Rename all secp256k1 symbols to avoid conflicts with go-quai
#define secp256k1_context_create ltc_secp256k1_context_create
#define secp256k1_context_destroy ltc_secp256k1_context_destroy
#define secp256k1_context_randomize ltc_secp256k1_context_randomize
#define secp256k1_context_clone ltc_secp256k1_context_clone
#define secp256k1_context_preallocated_size ltc_secp256k1_context_preallocated_size
#define secp256k1_context_preallocated_clone_size ltc_secp256k1_context_preallocated_clone_size
#define secp256k1_context_preallocated_create ltc_secp256k1_context_preallocated_create
#define secp256k1_context_preallocated_clone ltc_secp256k1_context_preallocated_clone
#define secp256k1_context_preallocated_destroy ltc_secp256k1_context_preallocated_destroy
#define secp256k1_context_set_illegal_callback ltc_secp256k1_context_set_illegal_callback
#define secp256k1_context_set_error_callback ltc_secp256k1_context_set_error_callback
#define secp256k1_context_no_precomp ltc_secp256k1_context_no_precomp
#define secp256k1_bulletproof_generators_create ltc_secp256k1_bulletproof_generators_create
#define secp256k1_bulletproof_generators_destroy ltc_secp256k1_bulletproof_generators_destroy
#define secp256k1_bulletproof_rangeproof_prove ltc_secp256k1_bulletproof_rangeproof_prove
#define secp256k1_bulletproof_rangeproof_verify ltc_secp256k1_bulletproof_rangeproof_verify
#define secp256k1_pedersen_commitment_parse ltc_secp256k1_pedersen_commitment_parse
#define secp256k1_scratch_space_create ltc_secp256k1_scratch_space_create
#define secp256k1_scratch_space_destroy ltc_secp256k1_scratch_space_destroy
#define secp256k1_ecdsa_signature_parse_compact ltc_secp256k1_ecdsa_signature_parse_compact
#define secp256k1_ecdsa_signature_parse_der ltc_secp256k1_ecdsa_signature_parse_der
#define secp256k1_ecdsa_signature_serialize_der ltc_secp256k1_ecdsa_signature_serialize_der
#define secp256k1_ecdsa_signature_serialize_compact ltc_secp256k1_ecdsa_signature_serialize_compact
#define secp256k1_ecdsa_verify ltc_secp256k1_ecdsa_verify
#define secp256k1_ecdsa_signature_normalize ltc_secp256k1_ecdsa_signature_normalize
#define secp256k1_ecdsa_sign ltc_secp256k1_ecdsa_sign
#define secp256k1_ec_seckey_verify ltc_secp256k1_ec_seckey_verify
#define secp256k1_ec_pubkey_create ltc_secp256k1_ec_pubkey_create
#define secp256k1_ec_seckey_negate ltc_secp256k1_ec_seckey_negate
#define secp256k1_ec_privkey_negate ltc_secp256k1_ec_privkey_negate
#define secp256k1_ec_pubkey_negate ltc_secp256k1_ec_pubkey_negate
#define secp256k1_ec_seckey_tweak_add ltc_secp256k1_ec_seckey_tweak_add
#define secp256k1_ec_privkey_tweak_add ltc_secp256k1_ec_privkey_tweak_add
#define secp256k1_ec_pubkey_tweak_add ltc_secp256k1_ec_pubkey_tweak_add
#define secp256k1_ec_seckey_tweak_mul ltc_secp256k1_ec_seckey_tweak_mul
#define secp256k1_ec_privkey_tweak_mul ltc_secp256k1_ec_privkey_tweak_mul
#define secp256k1_ec_pubkey_tweak_mul ltc_secp256k1_ec_pubkey_tweak_mul
#define secp256k1_ec_pubkey_combine ltc_secp256k1_ec_pubkey_combine
#define secp256k1_nonce_function_default ltc_secp256k1_nonce_function_default
#define secp256k1_nonce_function_rfc6979 ltc_secp256k1_nonce_function_rfc6979
#define secp256k1_ec_pubkey_parse ltc_secp256k1_ec_pubkey_parse
#define secp256k1_ec_pubkey_serialize ltc_secp256k1_ec_pubkey_serialize

#include <string.h>
#include "basic-config.h"
#include "secp256k1.c"
#include "precomputed_ecmult.c"
#include "precomputed_ecmult_gen.c"
*/
import "C"

import (
	"crypto/rand"
	"sync"
)

type RangeProof [675]byte

var (
	mu sync.RWMutex

	context = C.secp256k1_context_create(
		C.SECP256K1_CONTEXT_SIGN | C.SECP256K1_CONTEXT_VERIFY)
	generators = C.secp256k1_bulletproof_generators_create(
		context, &C.secp256k1_generator_const_g, 256)
)

func makeRandomBytes() (b [32]byte) {
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return
}

func randomizeContext() {
	seed := makeRandomBytes()
	if C.secp256k1_context_randomize(context, (*C.uchar)(&seed[0])) != 1 {
		panic("secp256k1_context_randomize failed")
	}
}

func NewRangeProof(value uint64, blind [32]byte,
	message, extraData []byte) (proof RangeProof) {

	mu.Lock()
	defer mu.Unlock()
	randomizeContext()

	var (
		scratch      = C.secp256k1_scratch_space_create(context, 1<<28)
		proofLen     = C.size_t(len(proof))
		blindPtr     = C.CBytes(blind[:])
		blinds       = []*C.uchar{(*C.uchar)(blindPtr)}
		nonce        = makeRandomBytes()
		privateNonce = makeRandomBytes()
	)

	ret := C.secp256k1_bulletproof_rangeproof_prove(context,
		scratch, generators, (*C.uchar)(&proof[0]), &proofLen,
		nil, nil, nil, (*C.uint64_t)(&value), nil, &blinds[0], nil, 1,
		&C.secp256k1_generator_const_h, 64, (*C.uchar)(&nonce[0]),
		(*C.uchar)(&privateNonce[0]), (*C.uchar)(&extraData[0]),
		C.size_t(len(extraData)), (*C.uchar)(&message[0]))

	C.free(blindPtr)
	C.secp256k1_scratch_space_destroy(context, scratch)

	if ret != 1 {
		panic("secp256k1_bulletproof_rangeproof_prove failed")
	}
	return
}

func (proof *RangeProof) Verify(commit [33]byte, extraData []byte) bool {
	mu.RLock()
	defer mu.RUnlock()

	var (
		scratch = C.secp256k1_scratch_space_create(context, 1<<28)
		com     C.secp256k1_pedersen_commitment
	)

	ret := C.secp256k1_pedersen_commitment_parse(
		context, &com, (*C.uchar)(&commit[0]))
	if ret != 1 {
		panic("secp256k1_pedersen_commitment_parse failed")
	}

	ret = C.secp256k1_bulletproof_rangeproof_verify(context, scratch,
		generators, (*C.uchar)(&proof[0]), C.size_t(len(proof)),
		nil, &com, 1, 64, &C.secp256k1_generator_const_h,
		(*C.uchar)(&extraData[0]), C.size_t(len(extraData)))

	C.secp256k1_scratch_space_destroy(context, scratch)

	return ret == 1
}

func ReadRangeProof(bytes []byte) *RangeProof {
	if len(bytes) < 675 {
		return nil
	}

	// TODO: Check if valid format

	rangeProof := new(RangeProof)
	copy(rangeProof[:], bytes[0:675])
	return rangeProof
}
