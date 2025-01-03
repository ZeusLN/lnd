package lndmobile

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/BoltzExchange/boltz-client/boltz"
)

func leaf(script string) txscript.TapLeaf {
	decoded, _ := hex.DecodeString(script)
	return txscript.TapLeaf{
		LeafVersion: txscript.BaseLeafVersion,
		Script:      decoded,
	}
}

func CreateClaimTransaction(endpoint string, id string, claimLeaf string, refundLeaf string, privateKey string, servicePubKey string, transactionHash string, pubNonce string) error {
	swapTree := &boltz.SwapTree{
		ClaimLeaf:  leaf(claimLeaf),
		RefundLeaf: leaf(refundLeaf),
	}

	// Decode the hex string to bytes
	privKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		fmt.Printf("Failed to decode hex string: %v", err)
	}

	// Create the private key using btcec
	keys, _ := btcec.PrivKeyFromBytes(privKeyBytes)

	// Decode the hex string to bytes
	servicePubKeyBytes, err := hex.DecodeString(servicePubKey)
	if err != nil {
		return fmt.Errorf("Error decoding service public key hex: %s", err)
	}
    
	// Parse the public key
	servicePubKeyFormatted, err := secp256k1.ParsePubKey(servicePubKeyBytes)
	if err != nil {
		return fmt.Errorf("Error parsing service public key %s", err)
	}

	if err := swapTree.Init(false, false, keys, servicePubKeyFormatted); err != nil {
		return fmt.Errorf("Error initializing swap tree %s", err)
	}

	session, err := boltz.NewSigningSession(swapTree)
	partial, err := session.Sign([]byte(transactionHash), []byte(pubNonce))
	if err != nil {
		return fmt.Errorf("could not create partial signature: %s", err)
	}

	boltzApi := &boltz.Api{URL: endpoint}
	if err := boltzApi.SendSwapClaimSignature(id, partial); err != nil {
		return fmt.Errorf("could not send partial signature to Boltz: %s", err)
	}

	return nil
}