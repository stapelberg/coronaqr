// This file is licensed MPL-2.0 (derived from github.com/veraison/go-cose)

package coronaqr

import (
	"crypto"

	"github.com/pkg/errors"
	"github.com/veraison/go-cose"
)

const contextSignature1 = "Signature1"

// buildAndMarshalSigStructure creates a Sig_structure, populates it
// with the appropriate fields, and marshals it to CBOR bytes
// Note that the signProtected parameter is ignored when ctxSignature is ContextSignature1.
func buildAndMarshalSigStructure(ctxSignature string, bodyProtected, signProtected, external, payload []byte) (ToBeSigned []byte, err error) {
	// 1.  Create a Sig_structure and populate it with the appropriate fields.
	//
	// Sig_structure = [
	//     context : "Signature" / "Signature1" / "CounterSignature",
	//     body_protected : empty_or_serialized_map,
	//     ? sign_protected : empty_or_serialized_map,
	//     external_aad : bstr,
	//     payload : bstr
	// ]
	sigStructure := []interface{}{
		ctxSignature,
		bodyProtected, // message.headers.EncodeProtected(),
	}

	// The protected attributes from the signer structure field are omitted
	// for the COSE_Sign1 signature structure.
	if ctxSignature != contextSignature1 {
		// message.signatures[0].headers.EncodeProtected()
		sigStructure = append(sigStructure, signProtected)
	}
	sigStructure = append(sigStructure, external)
	sigStructure = append(sigStructure, payload)

	// 2.  Create the value ToBeSigned by encoding the Sig_structure to a
	//     byte string, using the encoding described in Section 14.
	ToBeSigned, err = cose.Marshal(sigStructure)
	if err != nil {
		return nil, errors.Errorf("Error marshaling Sig_structure: %s", err)
	}
	return ToBeSigned, nil
}

func sigStructure(protectedEncoded, payload []byte) ([]byte, error) {
	return buildAndMarshalSigStructure(
		contextSignature1,
		protectedEncoded,
		nil,      // ignored: protected attributes from the signer structure field are not used in Sign1.
		[]byte{}, // external is always empty
		payload)
}

var ErrUnavailableHashFunc = errors.New("hash function is not available")

func hashSigStructure(ToBeSigned []byte, hash crypto.Hash) (digest []byte, err error) {
	if !hash.Available() {
		return nil, ErrUnavailableHashFunc
	}
	hasher := hash.New()
	_, _ = hasher.Write(ToBeSigned) // Write() on hash never fails
	return hasher.Sum(nil), nil
}
