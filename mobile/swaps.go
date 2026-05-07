package lndmobile

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"

	"github.com/BoltzExchange/boltz-client/v2/pkg/boltz"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func leaf(script string) txscript.TapLeaf {
	decoded, _ := hex.DecodeString(script)
	return txscript.TapLeaf{
		LeafVersion: txscript.BaseLeafVersion,
		Script:      decoded,
	}
}

func parseSwapKeys(privateKey, servicePubKey string) (*btcec.PrivateKey, *btcec.PublicKey, error) {
	privKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("decode private key hex: %w", err)
	}
	keys, _ := btcec.PrivKeyFromBytes(privKeyBytes)

	servicePubKeyBytes, err := hex.DecodeString(servicePubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("decode service pub key hex: %w", err)
	}

	servicePub, err := secp256k1.ParsePubKey(servicePubKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse service pub key: %w", err)
	}

	return keys, servicePub, nil
}

// buildFee returns an exact-sats Fee when minerFee > 0, otherwise falls back
// to a sats/vbyte rate. boltz.Fee.IsValid() requires exactly one to be set.
func buildFee(feeRate, minerFee int32) boltz.Fee {
	if minerFee > 0 {
		sats := uint64(minerFee)
		return boltz.Fee{Sats: &sats}
	}
	satPerVbyte := float64(feeRate)
	return boltz.Fee{SatsPerVbyte: &satPerVbyte}
}

func broadcastTx(txHex string, isTestnet bool) (string, error) {
	broadcastUrl := "https://mempool.space/api/tx"
	if isTestnet {
		broadcastUrl = "https://mempool.space/testnet/api/tx"
	}

	req, err := http.NewRequest("POST", broadcastUrl, bytes.NewBufferString(txHex))
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send HTTP request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("non-200 response: %d, body: %s", resp.StatusCode, string(body))
	}

	return string(body), nil
}

func CreateClaimTransaction(endpoint string, id string, claimLeaf string, refundLeaf string, privateKey string, servicePubKey string, transactionHash string, pubNonce string) error {
	keys, servicePubKeyFormatted, err := parseSwapKeys(privateKey, servicePubKey)
	if err != nil {
		return err
	}

	swapTree := &boltz.SwapTree{
		ClaimLeaf:  leaf(claimLeaf),
		RefundLeaf: leaf(refundLeaf),
	}
	if err := swapTree.Init(boltz.CurrencyBtc, false, keys, servicePubKeyFormatted); err != nil {
		return fmt.Errorf("Error initializing swap tree %s", err)
	}

	session, err := boltz.NewSigningSession(swapTree)
	if err != nil {
		return fmt.Errorf("could not create signing session: %s", err)
	}
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

func CreateReverseClaimTransaction(endpoint string, id string, claimLeaf string, refundLeaf string, privateKey string, servicePubKey string, preimageHex string, transactionHex string, lockupAddress string, destinationAddress string, feeRate int32, minerFee int32, isTestnet bool) error {
	network := boltz.MainNet
	if isTestnet {
		network = boltz.TestNet
	}

	boltzApi := &boltz.Api{URL: endpoint}

	keys, servicePubKeyFormatted, err := parseSwapKeys(privateKey, servicePubKey)
	if err != nil {
		return err
	}

	swapTree := &boltz.SwapTree{
		ClaimLeaf:  leaf(claimLeaf),
		RefundLeaf: leaf(refundLeaf),
	}
	if err := swapTree.Init(boltz.CurrencyBtc, false, keys, servicePubKeyFormatted); err != nil {
		return fmt.Errorf("Error initializing swap tree %s", err)
	}

	lockupTransaction, err := boltz.NewTxFromHex(boltz.CurrencyBtc, transactionHex, nil)
	if err != nil {
		return fmt.Errorf("Error constructing lockup tx %s", err)
	}

	vout, _, err := lockupTransaction.FindVout(network, lockupAddress)
	if err != nil {
		return fmt.Errorf("Error finding vout %s", err)
	}

	preimage, err := hex.DecodeString(preimageHex)
	if err != nil {
		return fmt.Errorf("Error decoding preimage hex string: %w", err)
	}

	claimTransaction, _, err := boltz.ConstructTransaction(
		network,
		boltz.CurrencyBtc,
		[]boltz.OutputDetails{
			{
				SwapId:            id,
				SwapType:          boltz.ReverseSwap,
				Address:           destinationAddress,
				LockupTransaction: lockupTransaction,
				Vout:              vout,
				Preimage:          preimage,
				PrivateKey:        keys,
				SwapTree:          swapTree,
				Cooperative:       true,
			},
		},
		buildFee(feeRate, minerFee),
		boltzApi,
	)
	if err != nil {
		return fmt.Errorf("could not create claim transaction: %w", err)
	}

	txHex, err := claimTransaction.Serialize()
	if err != nil {
		return fmt.Errorf("could not serialize claim transaction: %w", err)
	}

	body, err := broadcastTx(txHex, isTestnet)
	if err != nil {
		return err
	}

	fmt.Printf("Transaction broadcasted successfully: %s\n", body)

	return nil
}

func CreateRefundTransaction(endpoint string, id string, claimLeaf string, refundLeaf string, transactionHex string, privateKey string, servicePubKey string, feeRate int32, minerFee int32, timeoutBlockHeight int32, destinationAddress string, lockupAddress string, cooperative bool, isTestnet bool) (string, error) {
	network := boltz.MainNet
	if isTestnet {
		network = boltz.TestNet
	}

	boltzApi := &boltz.Api{URL: endpoint}

	keys, servicePubKeyFormatted, err := parseSwapKeys(privateKey, servicePubKey)
	if err != nil {
		return "", err
	}

	swapTree := &boltz.SwapTree{
		ClaimLeaf:  leaf(claimLeaf),
		RefundLeaf: leaf(refundLeaf),
	}
	if err := swapTree.Init(boltz.CurrencyBtc, false, keys, servicePubKeyFormatted); err != nil {
		return "", fmt.Errorf("error initializing swap tree %s", err)
	}

	lockupTransaction, err := boltz.NewTxFromHex(boltz.CurrencyBtc, transactionHex, nil)
	if err != nil {
		return "", fmt.Errorf("error constructing lockup tx %v", err)
	}

	vout, _, err := lockupTransaction.FindVout(network, lockupAddress)
	if err != nil {
		return "", fmt.Errorf("error finding vout %s", err)
	}

	refundTransaction, _, err := boltz.ConstructTransaction(
		network,
		boltz.CurrencyBtc,
		[]boltz.OutputDetails{
			{
				SwapId:             id,
				SwapType:           boltz.NormalSwap,
				Address:            destinationAddress,
				LockupTransaction:  lockupTransaction,
				Vout:               vout,
				Preimage:           []byte{},
				PrivateKey:         keys,
				TimeoutBlockHeight: uint32(timeoutBlockHeight),
				SwapTree:           swapTree,
				Cooperative:        cooperative,
			},
		},
		buildFee(feeRate, minerFee),
		boltzApi,
	)
	if err != nil {
		return "", fmt.Errorf("could not create refund transaction: %w", err)
	}

	txHex, err := refundTransaction.Serialize()
	if err != nil {
		return "", fmt.Errorf("could not serialize refund transaction: %w", err)
	}

	body, err := broadcastTx(txHex, isTestnet)
	if err != nil {
		return "", err
	}

	fmt.Printf("Transaction broadcasted successfully: %s\n", body)

	return body, nil
}
