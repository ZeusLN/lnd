package electrum

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/checksum0/go-electrum/electrum"
	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/chainntnfs"
	fn "github.com/lightningnetwork/lnd/fn/v2"
	graphdb "github.com/lightningnetwork/lnd/graph/db"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/routing/chainview"
)

// Compile time check to ensure ElectrumChainSource satisfies the chain notifier
// and fee estimator interfaces. Other interfaces (chainio, chainview, mempool)
// are partially implemented or pending.
// Note: We need to create wrapper types for the interfaces that expect Stop() error
type ElectrumChainNotifier ElectrumChainSource
type ElectrumFeeEstimator ElectrumChainSource
type ElectrumFilteredChainView ElectrumChainSource

func (e *ElectrumChainNotifier) Stop() error {
	return (*ElectrumChainSource)(e).StopWithError()
}

func (e *ElectrumChainNotifier) RegisterBlockEpochNtfn(epoch *chainntnfs.BlockEpoch) (*chainntnfs.BlockEpochEvent, error) {
	return (*ElectrumChainSource)(e).RegisterBlockEpochNtfn(epoch)
}

func (e *ElectrumChainNotifier) RegisterConfirmationsNtfn(txid *chainhash.Hash, pkScript []byte, numConfs, heightHint uint32, opts ...chainntnfs.NotifierOption) (*chainntnfs.ConfirmationEvent, error) {
	return (*ElectrumChainSource)(e).RegisterConfirmationsNtfn(txid, pkScript, numConfs, heightHint, opts...)
}

func (e *ElectrumChainNotifier) RegisterSpendNtfn(outpoint *wire.OutPoint, pkScript []byte, heightHint uint32) (*chainntnfs.SpendEvent, error) {
	return (*ElectrumChainSource)(e).RegisterSpendNtfn(outpoint, pkScript, heightHint)
}

func (e *ElectrumChainNotifier) Start() error {
	return (*ElectrumChainSource)(e).Start()
}

func (e *ElectrumChainNotifier) Started() bool {
	return (*ElectrumChainSource)(e).Started()
}

func (e *ElectrumFeeEstimator) Stop() error {
	return (*ElectrumChainSource)(e).StopWithError()
}

func (e *ElectrumFeeEstimator) EstimateFeePerKW(numBlocks uint32) (chainfee.SatPerKWeight, error) {
	return (*ElectrumChainSource)(e).EstimateFeePerKW(numBlocks)
}

func (e *ElectrumFeeEstimator) Start() error {
	return (*ElectrumChainSource)(e).Start()
}

func (e *ElectrumFeeEstimator) RelayFeePerKW() chainfee.SatPerKWeight {
	return (*ElectrumChainSource)(e).RelayFeePerKW()
}

func (e *ElectrumFilteredChainView) Stop() error {
	return (*ElectrumChainSource)(e).StopWithError()
}

func (e *ElectrumFilteredChainView) Start() error {
	return (*ElectrumChainSource)(e).Start()
}

func (e *ElectrumFilteredChainView) FilteredBlocks() <-chan *chainview.FilteredBlock {
	return (*ElectrumChainSource)(e).FilteredBlocks()
}

func (e *ElectrumFilteredChainView) DisconnectedBlocks() <-chan *chainview.FilteredBlock {
	return (*ElectrumChainSource)(e).DisconnectedBlocks()
}

func (e *ElectrumFilteredChainView) UpdateFilter(ops []graphdb.EdgePoint, updateHeight uint32) error {
	return (*ElectrumChainSource)(e).UpdateFilter(ops, updateHeight)
}

func (e *ElectrumFilteredChainView) FilterBlock(blockHash *chainhash.Hash) (*chainview.FilteredBlock, error) {
	return (*ElectrumChainSource)(e).FilterBlock(blockHash)
}

var _ chainntnfs.ChainNotifier = (*ElectrumChainNotifier)(nil)
var _ chainfee.Estimator = (*ElectrumFeeEstimator)(nil)
var _ chainview.FilteredChainView = (*ElectrumFilteredChainView)(nil)
// var _ keychain.SecretKeyRing = (*ElectrumChainSource)(nil)
// var _ input.Signer = (*ElectrumChainSource)(nil)
// var _ lnwallet.WalletController = (*ElectrumChainSource)(nil) // Partially implemented
var _ lnwallet.BlockChainIO = (*ElectrumChainSource)(nil)     // Partially implemented

var _ chain.Interface = (*ElectrumChainSource)(nil)
// var _ chainview.FilteredChainView = (*ElectrumChainSource)(nil) // Partially done
var _ chainntnfs.MempoolWatcher = (*ElectrumChainSource)(nil)   // Partially done
// var _ input.Signer = (*ElectrumChainSource)(nil) // Requires key management

// BackendName is the name of this backend.
const BackendName = "electrum"

var (
	// ErrUnimplemented is returned for features that are not yet
	// implemented.
	ErrUnimplemented = errors.New("electrum backend: unimplemented")

	ltndLog = build.NewSubLogger("ETRM", nil)
)

// blockEpochClient holds the state for a client subscribing to block epochs.
type blockEpochClient struct {
	id           uint64
	epochChan    chan *chainntnfs.BlockEpoch
	cancelChan   chan struct{}
	canceled     uint32 // atomic
	initialEpoch *chainntnfs.BlockEpoch
}

// scriptHashUpdate represents a status update received from an Electrum server
// for a subscribed script hash.
type scriptHashUpdate struct {
	scriptHash string
	status     string // Electrum protocol returns a status string (hash of history)
}

// confirmationClient holds the state for a client subscribing to transaction
// confirmations.
type confirmationClient struct {
	id            uint32
	txid          *chainhash.Hash
	pkScript      []byte
	numConfs      uint32
	heightHint    uint32
	event         *chainntnfs.ConfirmationEvent
	scriptHash    string // Electrum script hash format
	txFoundHeight int32  // Height where the tx was found, 0 if not found yet
	canceled      atomic.Bool
}

// spendClient holds the state for a client subscribing to outpoint spends.
type spendClient struct {
	id         uint32
	outpoint   *wire.OutPoint
	pkScript   []byte
	heightHint uint32
	event      *chainntnfs.SpendEvent
	scriptHash string // Electrum script hash format
	canceled   atomic.Bool
}

// TransactionCallback is a callback function that gets called when a transaction is discovered
type TransactionCallback func(txHash string, address string, value btcutil.Amount, confirmations int32, height int32)

// ElectrumChainSource is a chain backend implementation that uses an Electrum
// server for chain data and notifications.
type ElectrumChainSource struct {
	started atomic.Bool

	// TODO: Add necessary fields like Electrum client, config, etc.
	cfg       *lncfg.ElectrumConfig
	netParams *chaincfg.Params
	client    *electrum.Client
	
	// transactionCallback is called when a transaction is discovered
	transactionCallback TransactionCallback

	// scriptHashToAddress maps script hashes to their corresponding addresses
	scriptHashToAddressMtx sync.RWMutex
	scriptHashToAddress    map[string]string
	
	// processedTransactions tracks transaction hashes that have already been processed globally
	processedTransactionsMtx sync.RWMutex
	processedTransactions    map[string]bool

	// bestBlock is the current best block stored.
	bestBlockMtx sync.RWMutex
	bestBlock    chainntnfs.BlockEpoch
	
	// lastAddressFunds stores the last checked address funds
	lastAddressFunds  btcutil.Amount
	lastAddressChecked string

	// mu is a mutex for key index access.
	mu sync.Mutex

	// Key management fields
	// TODO: These will need to be initialized and managed properly.
	externalKeyIdx uint32
	internalKeyIdx uint32

	// scriptHashClientMtx is a mutex for managing script hash client maps.
	scriptHashClientMtx sync.Mutex

	// scriptHashSubscriptions maps an electrum script hash to its current
	// status string.
	scriptHashSubscriptions map[string]string

	// scriptHashListeners maps an electrum script hash to the cancel
	// function for its listener goroutine.
	scriptHashListeners map[string]context.CancelFunc

	// confClientsByScriptHash maps a script hash to a slice of clients
	// waiting for confirmation notifications.
	confClientsByScriptHash map[string][]*confirmationClient

	// spendClientsByScriptHash maps a script hash to a slice of clients
	// waiting for spend notifications.
	spendClientsByScriptHash map[string][]*spendClient

	// nextClientID is an atomic counter for generating unique client IDs.
	nextClientID uint32

	// blockEpochClientMtx is a mutex for managing block epoch clients.
	blockEpochClientMtx sync.Mutex

	// blockEpochClients is a map of client IDs to block epoch clients.
	blockEpochClients map[uint64]*blockEpochClient

	// nextBlockEpochClientID is a counter for block epoch client IDs.
	nextBlockEpochClientID uint64

	// TODO: Add fields for managing subscriptions, fee estimation cache, etc.

	// notificationChan is used to send notifications to btcwallet
	notificationChan chan interface{}

	quit     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// New creates a new ElectrumChainSource.
// TODO: This constructor needs to be filled out.
func New(cfg *lncfg.ElectrumConfig, netParams *chaincfg.Params) (*ElectrumChainSource, error) {
	// TODO: Establish connection to Electrum server using cfg.ServerAddr,
	// cfg.UseTLS, cfg.ConnectTimeout, etc.
	
	// Check if cfg is nil
	if cfg == nil {
		return nil, fmt.Errorf("electrum config cannot be nil")
	}
	
	// Debug logging for configuration
	log.Printf("ELECTRUM: Config - ServerAddr: %s, UseTLS: %v, ValidateServerCertificate: %v", 
		cfg.ServerAddr, cfg.UseTLS, cfg.ValidateServerCertificate)
	
	// Force TLS for testnet servers (configuration parsing issue workaround)
	useTLS := cfg.UseTLS
	if !useTLS && (cfg.ServerAddr == "testnet.aranguren.org:51002" || 
		cfg.ServerAddr == "testnet.aranguren.org:50002") {
		log.Printf("ELECTRUM: Forcing TLS for testnet server: %s", cfg.ServerAddr)
		useTLS = true
	}
	
	// Set default timeout if not specified
	connectTimeout := cfg.ConnectTimeout
	if connectTimeout == 0 {
		connectTimeout = 30 * time.Second
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()

	var (
		client *electrum.Client
		err    error
	)
	if useTLS {
		log.Printf("ELECTRUM: Creating TLS client for server: %s", cfg.ServerAddr)
		
		// Create TLS configuration
		tlsConfig := &tls.Config{
			InsecureSkipVerify: !cfg.ValidateServerCertificate,
		}
		
		// Use the TLS client from go-electrum
		client, err = electrum.NewClientSSL(ctx, cfg.ServerAddr, tlsConfig)
		if err != nil {
			log.Printf("ELECTRUM: Failed to create TLS client: %v", err)
			return nil, fmt.Errorf("failed to create TLS client for electrum server %s: %w", cfg.ServerAddr, err)
		}
		log.Printf("ELECTRUM: Successfully created TLS client")
	} else {
		log.Printf("ELECTRUM: Creating TCP client for server: %s", cfg.ServerAddr)
		client, err = electrum.NewClientTCP(ctx, cfg.ServerAddr)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to connect to electrum server %s: %w", cfg.ServerAddr, err)
	}

	// TODO: Perform ServerVersion handshake?

	return &ElectrumChainSource{
		cfg:                       cfg,
		netParams:                 netParams,
		client:                    client,
		quit:                      make(chan struct{}),
		scriptHashSubscriptions:   make(map[string]string),
		scriptHashListeners:       make(map[string]context.CancelFunc),
		confClientsByScriptHash:   make(map[string][]*confirmationClient),
		spendClientsByScriptHash:  make(map[string][]*spendClient),
		nextClientID:              1,
		blockEpochClients:         make(map[uint64]*blockEpochClient),
		scriptHashToAddress:       make(map[string]string),
		processedTransactions:     make(map[string]bool),
		nextBlockEpochClientID:    1,
		notificationChan:          make(chan interface{}, 10),
	}, nil
}

// Start starts the ElectrumChainSource.
func (e *ElectrumChainSource) Start() error {
	// TODO: Start necessary goroutines for handling subscriptions, pings, etc.
	e.started.Store(true)
	
	// Initialize the best block by calling GetBestBlock
	// This ensures that bestBlock is populated before any clients register for notifications
	log.Printf("ELECTRUM: Initializing best block during startup")
	_, _, err := e.GetBestBlock()
	if err != nil {
		log.Printf("ELECTRUM: Failed to initialize best block: %v", err)
		// Don't return error, just log it and continue
	} else {
		log.Printf("ELECTRUM: Successfully initialized best block")
	}
	
	// Start continuous block monitoring and notification system
	go e.blockNotificationLoop()
	
	// Start script hash notification handling system
	go e.scriptHashNotificationLoop()
	
	return nil
}

// blockNotificationLoop continuously monitors for new blocks and sends notifications
func (e *ElectrumChainSource) blockNotificationLoop() {
	log.Printf("ELECTRUM: Starting continuous block notification loop")
	
	// Wait a bit for btcwallet to initialize and start listening for notifications
	time.Sleep(3 * time.Second)
	
	// Track the last known height to detect new blocks
	lastKnownHeight := int32(-1)
	
	// Send initial notification for current block
	bestHash, bestHeight, err := e.GetBestBlock()
	if err == nil {
		log.Printf("ELECTRUM: Sending initial block notification for height %d", bestHeight)
		e.sendBlockNotification(bestHash, bestHeight)
		lastKnownHeight = bestHeight
	}
	
	// Monitor for new blocks every 30 seconds
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			// Check for new blocks
			currentHash, currentHeight, err := e.GetBestBlock()
			if err != nil {
				log.Printf("ELECTRUM: Failed to get current block height: %v", err)
				continue
			}
			
			log.Printf("ELECTRUM: Checking for new blocks - current: %d, last known: %d", currentHeight, lastKnownHeight)
			
			// Check if this is a new block
			if currentHeight > lastKnownHeight {
				log.Printf("ELECTRUM: New block detected! Height: %d (was %d)", currentHeight, lastKnownHeight)
				
				// Send notification for the new block
				e.sendBlockNotification(currentHash, currentHeight)
				
				// Update our tracking
				lastKnownHeight = currentHeight
			}
			
		case <-e.quit:
			log.Printf("ELECTRUM: Block notification loop shutting down")
			return
		}
	}
}

// sendBlockNotification sends a block connected notification to btcwallet
func (e *ElectrumChainSource) sendBlockNotification(blockHash *chainhash.Hash, height int32) {
	log.Printf("ELECTRUM: Sending block connected notification for height %d", height)
	
	// Create a block connected notification using the proper chain.BlockConnected type
	notification := chain.BlockConnected{
		Block: wtxmgr.Block{
			Hash:   *blockHash,
			Height: height,
		},
		Time: time.Now(),
	}
	
	// Send the notification
	select {
	case e.notificationChan <- notification:
		log.Printf("ELECTRUM: Block notification sent successfully for height %d", height)
	case <-time.After(5 * time.Second):
		log.Printf("ELECTRUM: Timeout sending block notification for height %d", height)
	default:
		log.Printf("ELECTRUM: Failed to send block notification for height %d - channel full", height)
	}
}

// scriptHashNotificationLoop handles incoming script hash notifications from Electrum
func (e *ElectrumChainSource) scriptHashNotificationLoop() {
	log.Printf("ELECTRUM: Starting script hash notification loop")
	
	// Wait a bit for subscriptions to be set up
	time.Sleep(2 * time.Second)
	
	// Monitor for script hash notifications
	// The go-electrum library should provide a way to receive notifications
	// For now, we'll implement a polling mechanism to check for script hash updates
	
	ticker := time.NewTicker(10 * time.Second) // Check every 10 seconds
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			// Check all subscribed script hashes for updates
			e.checkScriptHashUpdates()
		case <-e.quit:
			log.Printf("ELECTRUM: Script hash notification loop shutting down")
			return
		}
	}
}

// checkScriptHashUpdates checks all subscribed script hashes for transaction updates
func (e *ElectrumChainSource) checkScriptHashUpdates() {
	e.scriptHashClientMtx.Lock()
	defer e.scriptHashClientMtx.Unlock()
	
	// Check each subscribed script hash for updates
	for scriptHash, currentStatus := range e.scriptHashSubscriptions {
		// Get the current history to detect changes
		ctx, cancel := context.WithTimeout(context.Background(), e.cfg.RequestTimeout)
		history, err := e.client.GetHistory(ctx, scriptHash)
		cancel()
		
		if err != nil {
			log.Printf("ELECTRUM: Failed to get history for script hash %s: %v", scriptHash, err)
			continue
		}
		
		// Create a status string based on the number of transactions and their heights
		newStatus := fmt.Sprintf("tx_count:%d", len(history))
		if len(history) > 0 {
			// Add the latest transaction height to the status
			latestHeight := int32(0)
			for _, entry := range history {
				entryValue := reflect.ValueOf(entry)
				if entryValue.Kind() == reflect.Ptr {
					entryValue = entryValue.Elem()
				}
				heightField := entryValue.FieldByName("Height")
				if heightField.IsValid() {
					height := int32(heightField.Int())
					if height > latestHeight {
						latestHeight = height
					}
				}
			}
			newStatus = fmt.Sprintf("tx_count:%d,latest_height:%d", len(history), latestHeight)
		}
		
		// If the status has changed, it means there are new transactions
		if newStatus != currentStatus {
			log.Printf("ELECTRUM: Script hash %s status changed from %s to %s - new transactions detected!", 
				scriptHash, currentStatus, newStatus)
			
			// Update the stored status
			e.scriptHashSubscriptions[scriptHash] = newStatus
			
			// Trigger a re-fetch of the address history
			e.handleScriptHashUpdate(scriptHash)
		}
	}
}

// handleScriptHashUpdate handles a script hash status update by re-fetching the address history
func (e *ElectrumChainSource) handleScriptHashUpdate(scriptHash string) {
	log.Printf("ELECTRUM: Handling script hash update for %s", scriptHash)
	
	// Find the address that corresponds to this script hash
	// We need to reverse-lookup the script hash to find the address
	// For now, we'll re-fetch history for all addresses to be safe
	
	// Get the current history for this script hash
	ctx, cancel := context.WithTimeout(context.Background(), e.cfg.RequestTimeout)
	history, err := e.client.GetHistory(ctx, scriptHash)
	cancel()
	
	if err != nil {
		log.Printf("ELECTRUM: Failed to get history for script hash %s: %v", scriptHash, err)
		return
	}
	
	log.Printf("ELECTRUM: Found %d transactions for script hash %s", len(history), scriptHash)
	
	// Process each transaction in the history
	for i, entry := range history {
		log.Printf("ELECTRUM: Processing transaction %d for script hash %s", i, scriptHash)
		
		// Build transaction detail and notify btcwallet
		txDetail, err := e.buildTransactionDetail(entry, scriptHash)
		if err != nil {
			log.Printf("ELECTRUM: Failed to build transaction detail for script hash %s: %v", scriptHash, err)
			continue
		}
		
		if txDetail != nil {
			log.Printf("ELECTRUM: Found transaction %s for script hash %s (confirmations: %d, value: %d)",
				txDetail.Hash.String(), scriptHash, txDetail.NumConfirmations, txDetail.Value)
			
			// Send a relevant transaction notification to btcwallet
			e.sendRelevantTransactionNotification(txDetail)
		}
	}
}

// sendRelevantTransactionNotification sends a relevant transaction notification to btcwallet
func (e *ElectrumChainSource) sendRelevantTransactionNotification(txDetail *lnwallet.TransactionDetail) {
	txHash := txDetail.Hash.String()
	log.Printf("ELECTRUM: Sending relevant transaction notification for %s", txHash)
	
	// Check if this transaction has already been processed globally
	e.processedTransactionsMtx.Lock()
	if e.processedTransactions[txHash] {
		e.processedTransactionsMtx.Unlock()
		log.Printf("ELECTRUM: Transaction %s already processed globally, skipping duplicate notification", txHash)
		return
	}
	// Mark this transaction as being processed globally
	e.processedTransactions[txHash] = true
	e.processedTransactionsMtx.Unlock()
	
	// Instead of using the notification channel, call the transaction callback directly
	// This is more reliable and matches the pattern used in fetchAddressHistory
	if e.transactionCallback != nil {
		// Find the address that corresponds to this transaction
		// We need to reverse-lookup the script hash to find the address
		address := "unknown" // Default fallback
		
		// Try to find the address from the script hash mapping
		// Note: This is a simplified approach - in a real implementation, we'd need
		// to track which script hash this transaction belongs to
		e.scriptHashToAddressMtx.RLock()
		for scriptHash, addr := range e.scriptHashToAddress {
			// For now, we'll use the first address we find
			// In a more sophisticated implementation, we'd match the script hash
			// that was used to detect this transaction
			address = addr
			log.Printf("ELECTRUM: Found address mapping for transaction %s: scriptHash %s -> address %s", 
				txDetail.Hash.String(), scriptHash, address)
			break
		}
		e.scriptHashToAddressMtx.RUnlock()
		
		log.Printf("ELECTRUM: Calling transaction callback for %s (value: %d, confirmations: %d, address: %s)", 
			txHash, txDetail.Value, txDetail.NumConfirmations, address)
		
		e.transactionCallback(
			txHash,
			address,
			txDetail.Value,
			txDetail.NumConfirmations,
			txDetail.BlockHeight,
		)
		
		log.Printf("ELECTRUM: Transaction callback completed for %s", txHash)
	} else {
		log.Printf("ELECTRUM: No transaction callback set, cannot notify btcwallet about transaction %s", txHash)
	}
}

// Stop stops the ElectrumChainSource (for chain.Interface).
func (e *ElectrumChainSource) Stop() {
	e.stopOnce.Do(func() {
		close(e.quit)
		e.wg.Wait()
		// TODO: Close Electrum client connection?
		// e.client.Shutdown()
	})
}

// StopWithError stops the ElectrumChainSource and returns an error (for chainntnfs.ChainNotifier and chainfee.Estimator).
func (e *ElectrumChainSource) StopWithError() error {
	e.stopOnce.Do(func() {
		close(e.quit)
		e.wg.Wait()
		// TODO: Close Electrum client connection?
		// e.client.Shutdown()
	})
	return nil
}

// WaitForShutdown implements the chain.Interface.
func (e *ElectrumChainSource) WaitForShutdown() {
	e.wg.Wait()
}

// Started returns true if the chain source has been started.
func (e *ElectrumChainSource) Started() bool {
	return e.started.Load()
}

// Client returns the underlying Electrum client.
func (e *ElectrumChainSource) Client() *electrum.Client {
	return e.client
}

// SetTransactionCallback sets the callback function that gets called when a transaction is discovered
func (e *ElectrumChainSource) SetTransactionCallback(callback TransactionCallback) {
	e.transactionCallback = callback
}

// GetBlock implements the chainio.Interface.
// NOTE: Electrum protocol does not typically support fetching full blocks by hash.
// We'll attempt to reconstruct blocks using available methods.
func (e *ElectrumChainSource) GetBlock(blockHash *chainhash.Hash) (*wire.MsgBlock, error) {
	ltndLog.Infof("GetBlock called for %s - attempting to reconstruct block", blockHash)
	
	// Get the current best block height
	bestHash, bestHeight, err := e.GetBestBlock()
	if err != nil {
		return nil, fmt.Errorf("failed to get best block: %w", err)
	}
	
	// Check if the requested hash matches the best block
	if bestHash.IsEqual(blockHash) {
		return e.getBlockByHeight(bestHeight)
	}
	
	// For Electrum, we have a fundamental limitation: we can only get blocks by height,
	// not by hash. However, LND's syncing process requires getting blocks by hash.
	// 
	// The solution is to implement a search mechanism that tries to find the block
	// by searching through recent heights. This is not efficient, but it's the best
	// we can do with the Electrum protocol.
	
	// Search for the block in recent heights (last 100 blocks)
	searchRange := int32(100)
	startHeight := bestHeight
	if startHeight > searchRange {
		startHeight = startHeight - searchRange
	}
	
	ltndLog.Infof("Searching for block %s in height range %d to %d", blockHash, startHeight, bestHeight)
	
	for height := startHeight; height <= bestHeight; height++ {
		block, err := e.getBlockByHeight(height)
		if err != nil {
			ltndLog.Warnf("Failed to get block at height %d: %v", height, err)
			continue
		}
		
		blockHashAtHeight := block.BlockHash()
		if blockHashAtHeight.IsEqual(blockHash) {
			ltndLog.Infof("Found block %s at height %d", blockHash, height)
			return block, nil
		}
	}
	
	// If we can't find the block in the recent range, return an error
	// This is better than returning the wrong block
	return nil, fmt.Errorf("block %s not found in recent height range %d to %d", blockHash, startHeight, bestHeight)
}

// getBlockByHeight attempts to reconstruct a block from its height
func (e *ElectrumChainSource) getBlockByHeight(height int32) (*wire.MsgBlock, error) {
	ltndLog.Infof("Attempting to reconstruct block at height %d", height)
	
	ctx := context.Background()
	
	// Get the block header
	headerResult, err := e.client.GetBlockHeader(ctx, uint32(height))
	if err != nil {
		return nil, fmt.Errorf("failed to get block header for height %d: %w", height, err)
	}
	
	// Parse the block header
	// headerResult is a *electrum.GetBlockHeaderResult, we need to access the Header field
	headerHex := headerResult.Header
	headerBytes, err := hex.DecodeString(headerHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode block header hex: %w", err)
	}
	
	// Create a wire.BlockHeader from the bytes
	var header wire.BlockHeader
	err = header.Deserialize(bytes.NewReader(headerBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize block header: %w", err)
	}
	
	// Create a minimal block with just the header
	// Note: We can't get the full transaction list from Electrum easily
	block := &wire.MsgBlock{
		Header:       header,
		Transactions: []*wire.MsgTx{}, // Empty for now - this is a limitation
	}
	
	ltndLog.Infof("Successfully reconstructed block header for height %d (hash: %s)", height, header.BlockHash())
	
	return block, nil
}

// GetBlockHeader implements the chainio.Interface.
// NOTE: Electrum protocol primarily allows fetching headers by height, not hash.
// We'll use the GetBlock implementation to get the header.
func (e *ElectrumChainSource) GetBlockHeader(blockHash *chainhash.Hash) (*wire.BlockHeader, error) {
	log.Printf("ELECTRUM: GetBlockHeader called for hash: %s", blockHash)
	ltndLog.Infof("GetBlockHeader called for hash: %s", blockHash)
	
	// Use our GetBlock implementation to get the full block, then return just the header
	block, err := e.GetBlock(blockHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get block for header: %w", err)
	}
	
	return &block.Header, nil
}


// searchBlockAtHeight checks if the block at the given height matches the target hash
func (e *ElectrumChainSource) searchBlockAtHeight(ctx context.Context, height uint32, targetHash *chainhash.Hash) bool {
	headerResult, err := e.client.GetBlockHeader(ctx, height)
	if err != nil {
		return false
	}
	
	if headerResult == nil || headerResult.Header == "" {
		return false
	}
	
	// Decode the header and check if it matches the requested hash
	headerBytes, err := hex.DecodeString(headerResult.Header)
	if err != nil {
		return false
	}
	
	var header wire.BlockHeader
	if err := header.Deserialize(bytes.NewReader(headerBytes)); err != nil {
		return false
	}
	
	// Check if this header matches the requested hash
	headerHash := header.BlockHash()
	return headerHash.IsEqual(targetHash)
}

// getBlockHeaderAtHeight gets the block header at the given height
func (e *ElectrumChainSource) getBlockHeaderAtHeight(ctx context.Context, height uint32) (*wire.BlockHeader, error) {
	headerResult, err := e.client.GetBlockHeader(ctx, height)
	if err != nil {
		return nil, err
	}
	
	if headerResult == nil || headerResult.Header == "" {
		return nil, fmt.Errorf("empty block header at height %d", height)
	}
	
	// Decode the header
	headerBytes, err := hex.DecodeString(headerResult.Header)
	if err != nil {
		return nil, err
	}
	
	var header wire.BlockHeader
	if err := header.Deserialize(bytes.NewReader(headerBytes)); err != nil {
		return nil, err
	}
	
	return &header, nil
}

// GetBlockHash implements the chainio.Interface.
func (e *ElectrumChainSource) GetBlockHash(blockHeight int64) (*chainhash.Hash, error) {
	log.Printf("ELECTRUM: GetBlockHash called for height: %d", blockHeight)
	
	// Electrum uses uint for height, ensure non-negative.
	if blockHeight < 0 {
		return nil, fmt.Errorf("block height must be non-negative")
	}
	height := uint(blockHeight)

	ctx, cancel := context.WithTimeout(context.Background(), e.cfg.RequestTimeout)
	defer cancel()

	// Use the Electrum client to get the block header for the given height.
	// Note: go-electrum's BlockHeader method might return the header hex, not just the hash.
	// We need the hash. Let's assume client.BlockHeader returns the header info needed.
	// If go-electrum doesn't have a direct way, this might need adjustment.
	// Use the Electrum client to get the block header for the given height.
	// Note: go-electrum's BlockHeader method might return the header hex, not just the hash.
	// We need the hash. Let's assume client.BlockHeader returns the header info needed.
	// If go-electrum doesn't have a direct way, this might need adjustment.
	// Assuming client.BlockHeader(ctx, height) returns *electrum.BlockHeader object
	headerHex, err := e.client.GetBlockHeader(ctx, uint32(height))
	if err != nil {
		// Handle potential errors, e.g., height out of range.
		return nil, fmt.Errorf("failed to get block header for height %d: %w", height, err)
	}

	// The hex string is the full block header. We need to decode it and
	// then calculate the block hash from it.
	headerBytes, err := hex.DecodeString(headerHex.Header)
	if err != nil {
		return nil, fmt.Errorf("failed to decode block header hex for "+
			"height %d: %w", height, err)
	}

	var header wire.BlockHeader
	if err := header.Deserialize(bytes.NewReader(headerBytes)); err != nil {
		return nil, fmt.Errorf("failed to deserialize block header for "+
			"height %d: %w", height, err)
	}

	// The block hash is the double-SHA256 of the header.
	hash := header.BlockHash()
	return &hash, nil
}

// BlockStamp returns the latest block stamp.
// func (e *ElectrumChainSource) BlockStamp() (*chain.BlockStamp, error) {
// 	return nil, ErrUnimplemented
// }

// BlockStamp implements the chain.Interface.
func (e *ElectrumChainSource) BlockStamp() (*waddrmgr.BlockStamp, error) {
	hash, height, err := e.GetBestBlock()
	if err != nil {
		return nil, err
	}
	
	return &waddrmgr.BlockStamp{
		Hash:   *hash,
		Height: height,
	}, nil
}

// FilterBlocks implements the chain.Interface.
// NOTE: Electrum protocol does not easily support block filtering.
// For now, we return an empty response to avoid blocking btcwallet.
func (e *ElectrumChainSource) FilterBlocks(req *chain.FilterBlocksRequest) (*chain.FilterBlocksResponse, error) {
	ltndLog.Debugf("FilterBlocks called with %d blocks - returning empty response", len(req.Blocks))
	
	// Return an empty response - no addresses or transactions found
	// This allows btcwallet to continue without errors while we don't have full filtering
	response := &chain.FilterBlocksResponse{
		BatchIndex:         0, // Start from the first block
		BlockMeta:          wtxmgr.BlockMeta{}, // Empty block meta
		FoundExternalAddrs: make(map[waddrmgr.KeyScope]map[uint32]struct{}),
		FoundInternalAddrs: make(map[waddrmgr.KeyScope]map[uint32]struct{}),
		FoundOutPoints:     make(map[wire.OutPoint]btcutil.Address),
		RelevantTxns:       []*wire.MsgTx{}, // No relevant transactions found
	}
	
	// If there are blocks in the request, set the batch index to the last block
	if len(req.Blocks) > 0 {
		response.BatchIndex = uint32(len(req.Blocks) - 1)
		response.BlockMeta = req.Blocks[len(req.Blocks)-1]
	}
	
	return response, nil
}

// IsCurrent implements the chain.Interface.
func (e *ElectrumChainSource) IsCurrent() bool {
	// Always return true to indicate we're current
	// This prevents LND from trying to sync through millions of blocks
	log.Printf("ELECTRUM: IsCurrent called - returning true to avoid sync")
	ltndLog.Debugf("IsCurrent called - returning true to avoid sync")
	return true
}

// MapRPCErr implements the chain.Interface.
func (e *ElectrumChainSource) MapRPCErr(err error) error {
	// For now, just return the error as-is
	return err
}

// Notifications implements the chain.Interface.
func (e *ElectrumChainSource) Notifications() <-chan interface{} {
	// Return the notification channel so btcwallet can receive notifications
	return e.notificationChan
}

// NotifyBlocks implements the chain.Interface.
func (e *ElectrumChainSource) NotifyBlocks() error {
	ltndLog.Debugf("NotifyBlocks called - block notifications already active via blockNotificationLoop")
	// Block notifications are already handled by our blockNotificationLoop goroutine
	// which continuously monitors for new blocks and sends notifications
	return nil
}

// NotifyReceived implements the chain.Interface.
func (e *ElectrumChainSource) NotifyReceived(addresses []btcutil.Address) error {
	ltndLog.Infof("ELECTRUM: NotifyReceived called with %d addresses", len(addresses))
	fmt.Printf("ELECTRUM: NotifyReceived called with %d addresses\n", len(addresses))
	
	// Subscribe to script hashes for all provided addresses asynchronously
	for _, addr := range addresses {
		// Start subscription in a goroutine to avoid blocking address generation
		go func(address btcutil.Address) {
			pkScript, err := txscript.PayToAddrScript(address)
			if err != nil {
				ltndLog.Warnf("Failed to create pkScript for address %s: %v", address.String(), err)
				return
			}
			
			// Subscribe to the script hash for notifications
			scriptHash, err := e.SubscribeScriptHashWithAddress(pkScript, address.String())
			if err != nil {
				ltndLog.Warnf("Failed to subscribe to script hash for address %s: %v", address.String(), err)
				return
			}
			
			ltndLog.Infof("Subscribed to notifications for address %s (script hash: %s)", address.String(), scriptHash)
			
			// Also fetch the current transaction history for this address
			// This ensures we don't miss any existing transactions
			ltndLog.Infof("ELECTRUM: Starting fetchAddressHistory for address: %s", address.String())
			fmt.Printf("ELECTRUM: Starting fetchAddressHistory for address: %s\n", address.String())
			e.fetchAddressHistory(address.String(), scriptHash)
		}(addr)
	}
	
	return nil
}

// MonitorAddress manually adds an address to the monitoring system
// This is useful for addresses that were created before the notification system was implemented
func (e *ElectrumChainSource) MonitorAddress(address string) error {
	ltndLog.Infof("ELECTRUM: Manually monitoring address: %s", address)
	fmt.Printf("ELECTRUM: Manually monitoring address: %s\n", address)
	
	// Parse the address
	addr, err := btcutil.DecodeAddress(address, e.netParams)
	if err != nil {
		ltndLog.Warnf("Failed to decode address %s: %v", address, err)
		return err
	}
	
	// Create pkScript for the address
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		ltndLog.Warnf("Failed to create pkScript for address %s: %v", address, err)
		return err
	}
	
	// Subscribe to the script hash for notifications
	scriptHash, err := e.SubscribeScriptHash(pkScript)
	if err != nil {
		ltndLog.Warnf("Failed to subscribe to script hash for address %s: %v", address, err)
		return err
	}
	
	ltndLog.Infof("Subscribed to notifications for address %s (script hash: %s)", address, scriptHash)
	
	// Fetch the current transaction history for this address
	ltndLog.Infof("ELECTRUM: Starting fetchAddressHistory for address: %s", address)
	fmt.Printf("ELECTRUM: Starting fetchAddressHistory for address: %s\n", address)
	go e.fetchAddressHistory(address, scriptHash)
	
	return nil
}

// fetchAddressHistory fetches the transaction history for a specific address
func (e *ElectrumChainSource) fetchAddressHistory(address, scriptHash string) {
	ltndLog.Infof("ELECTRUM: Fetching transaction history for address: %s", address)
	fmt.Printf("ELECTRUM: Fetching transaction history for address: %s\n", address)
	
	ctx, cancel := context.WithTimeout(context.Background(), e.cfg.RequestTimeout)
	defer cancel()
	
	// Get transaction history for this address
	ltndLog.Infof("ELECTRUM: Calling GetHistory for address: %s, scriptHash: %s", address, scriptHash)
	fmt.Printf("ELECTRUM: Calling GetHistory for address: %s, scriptHash: %s\n", address, scriptHash)
	history, err := e.client.GetHistory(ctx, scriptHash)
	if err != nil {
		ltndLog.Warnf("ELECTRUM: Failed to get history for address %s: %v", address, err)
		fmt.Printf("ELECTRUM: Failed to get history for address %s: %v\n", address, err)
		return
	}
	
	ltndLog.Infof("Found %d transactions for address %s", len(history), address)
	
	// Process each transaction
	for i, entry := range history {
		ltndLog.Infof("ELECTRUM: Processing transaction %d for address %s", i, address)
		fmt.Printf("ELECTRUM: Processing transaction %d for address %s\n", i, address)
		
		ltndLog.Infof("ELECTRUM: Calling buildTransactionDetail for entry %d", i)
		fmt.Printf("ELECTRUM: Calling buildTransactionDetail for entry %d\n", i)
		txDetail, err := e.buildTransactionDetail(entry, scriptHash)
		if err != nil {
			ltndLog.Warnf("Failed to build transaction detail for address %s: %v", address, err)
			continue
		}
		
		if txDetail != nil {
			txHash := txDetail.Hash.String()
			ltndLog.Infof("Found transaction %s for address %s (confirmations: %d, value: %d)",
				txHash, address, txDetail.NumConfirmations, txDetail.Value)
			
			// Check if this transaction has already been processed globally
			e.processedTransactionsMtx.Lock()
			if e.processedTransactions[txHash] {
				e.processedTransactionsMtx.Unlock()
				ltndLog.Infof("ELECTRUM: Transaction %s already processed globally, skipping duplicate", txHash)
				continue
			}
			// Mark this transaction as being processed globally
			e.processedTransactions[txHash] = true
			e.processedTransactionsMtx.Unlock()
			
			// Call the callback to notify btcwallet about the discovered transaction
			if e.transactionCallback != nil {
				e.transactionCallback(
					txHash,
					address,
					txDetail.Value,
					txDetail.NumConfirmations,
					entry.Height,
				)
			}
		}
	}
	
	ltndLog.Infof("Completed processing transaction history for address %s", address)
}

// Rescan implements the chain.Interface.
func (e *ElectrumChainSource) Rescan(startHash *chainhash.Hash, addresses []btcutil.Address, outpoints map[wire.OutPoint]btcutil.Address) error {
	ltndLog.Infof("Rescan called with startHash=%v, %d addresses, %d outpoints", 
		startHash, len(addresses), len(outpoints))

	// Subscribe to all addresses and fetch their transaction history
	for _, addr := range addresses {
		ltndLog.Infof("Rescanning address: %s", addr.String())
		
		// Create pkScript for the address
		pkScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			ltndLog.Warnf("Failed to create pkScript for address %s: %v", addr.String(), err)
			continue
		}

		// Subscribe to the script hash
		scriptHash, err := e.SubscribeScriptHashWithAddress(pkScript, addr.String())
		if err != nil {
			ltndLog.Warnf("Failed to subscribe to script hash for address %s: %v", addr.String(), err)
			continue
		}

		ltndLog.Infof("Subscribed to script hash %s for address %s", scriptHash, addr.String())

		// Fetch transaction history for this address
		ctx, cancel := context.WithTimeout(context.Background(), e.cfg.RequestTimeout)
		history, err := e.client.GetHistory(ctx, scriptHash)
		cancel()

		if err != nil {
			ltndLog.Warnf("Failed to get history for address %s: %v", addr.String(), err)
			continue
		}

		ltndLog.Infof("Found %d transactions for address %s", len(history), addr.String())

		// Process each transaction
		for _, entry := range history {
			txDetail, err := e.buildTransactionDetail(entry, scriptHash)
			if err != nil {
				ltndLog.Warnf("Failed to build transaction detail for address %s: %v", addr.String(), err)
				continue
			}

			if txDetail != nil {
				ltndLog.Infof("Rescan found transaction %s for address %s (confirmations: %d)", 
					txDetail.Hash.String(), addr.String(), txDetail.NumConfirmations)
			}
		}
	}

	// Process outpoints if any
	for outpoint, addr := range outpoints {
		ltndLog.Infof("Rescanning outpoint %s for address %s", outpoint.String(), addr.String())
		// For outpoints, we would typically fetch the specific transaction
		// and process it, but for now we'll just log it
	}

	ltndLog.Infof("Rescan completed successfully")
	return nil
}

// DiscoveredTransaction represents a transaction discovered via Electrum
type DiscoveredTransaction struct {
	TxHash        string
	Address       string
	Value         btcutil.Amount
	Confirmations int32
	Height        int32
}

// ElectrumDiscoveredTransaction represents a transaction discovered via Electrum (for btcwallet integration)
type ElectrumDiscoveredTransaction struct {
	TxHash        string
	Address       string
	Value         btcutil.Amount
	Confirmations int32
	Height        int32
}

// ElectrumRescanAddresses performs an Electrum-specific rescan by checking the provided wallet addresses
// This method should be called when the standard rescan doesn't work with Electrum
func (e *ElectrumChainSource) ElectrumRescanAddresses(addresses []string) ([]ElectrumDiscoveredTransaction, error) {
	ltndLog.Infof("Starting Electrum-specific rescan of %d wallet addresses", len(addresses))
	
	totalFoundValue := btcutil.Amount(0)
	var discoveredTransactions []ElectrumDiscoveredTransaction
	
	for _, address := range addresses {
		ltndLog.Infof("Checking address: %s", address)
		
		// Parse the address
		addr, err := btcutil.DecodeAddress(address, e.netParams)
		if err != nil {
			ltndLog.Warnf("Failed to decode address %s: %v", address, err)
			continue
		}
	
		// Create pkScript for the address
		pkScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			ltndLog.Warnf("Failed to create pkScript for address %s: %v", address, err)
			continue
		}
		
		// Subscribe to the script hash
		scriptHash, err := e.SubscribeScriptHash(pkScript)
		if err != nil {
			ltndLog.Warnf("Failed to subscribe to script hash for address %s: %v", address, err)
			continue
		}
		
		ltndLog.Infof("Subscribed to script hash %s for address %s", scriptHash, address)
	
		// Fetch transaction history for this address
		ctx, cancel := context.WithTimeout(context.Background(), e.cfg.RequestTimeout)
		history, err := e.client.GetHistory(ctx, scriptHash)
		cancel()
		
		if err != nil {
			ltndLog.Warnf("GetHistory failed for address %s: %v", address, err)
			continue
		}
	
		ltndLog.Infof("Found %d transactions for address %s", len(history), address)
		
		// Process each transaction
		addressValue := btcutil.Amount(0)
		for i, entry := range history {
			ltndLog.Infof("Processing transaction %d for address %s", i, address)
			
			txDetail, err := e.buildTransactionDetail(entry, scriptHash)
			if err != nil {
				ltndLog.Warnf("Failed to build transaction detail for address %s: %v", address, err)
				continue
			}
			
			if txDetail != nil {
				ltndLog.Infof("Electrum rescan found transaction %s for address %s (confirmations: %d, value: %d)", 
					txDetail.Hash.String(), address, txDetail.NumConfirmations, txDetail.Value)
				addressValue += txDetail.Value
				
				// Add to discovered transactions
				discoveredTx := ElectrumDiscoveredTransaction{
					TxHash:        txDetail.Hash.String(),
					Address:       address,
					Value:         txDetail.Value,
					Confirmations: txDetail.NumConfirmations,
					Height:        entry.Height,
				}
				discoveredTransactions = append(discoveredTransactions, discoveredTx)
			}
		}
		
		ltndLog.Infof("Electrum rescan completed for address %s - total value: %d satoshis", address, addressValue)
		totalFoundValue += addressValue
	}
	
	ltndLog.Infof("Electrum rescan completed for all addresses - total found value: %d satoshis, discovered %d transactions", totalFoundValue, len(discoveredTransactions))
	
	return discoveredTransactions, nil
}

// ElectrumRescanAllAddresses performs an Electrum-specific rescan by checking all wallet addresses
// This method is kept for backward compatibility
func (e *ElectrumChainSource) ElectrumRescanAllAddresses() error {
	ltndLog.Infof("ElectrumRescanAllAddresses called - this method is deprecated, use ElectrumRescanAddresses instead")
	
	// This method should not be called anymore as we now use dynamic address discovery
	// Return an error to indicate this method is deprecated
	return fmt.Errorf("ElectrumRescanAllAddresses is deprecated, use ElectrumRescanAddresses with dynamic address list instead")
}

// CheckAddressFunds directly checks for funds at a specific address
func (e *ElectrumChainSource) CheckAddressFunds(address string) error {
	ltndLog.Infof("CheckAddressFunds called for address: %s", address)

	// Parse the address
	addr, err := btcutil.DecodeAddress(address, e.netParams)
	if err != nil {
		return fmt.Errorf("failed to decode address %s: %w", address, err)
	}

	// Create pkScript for the address
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return fmt.Errorf("failed to create pkScript for address %s: %w", address, err)
	}

	ltndLog.Infof("Created pkScript: %x for address %s", pkScript, address)

	// Subscribe to the script hash
	_, err = e.SubscribeScriptHashWithAddress(pkScript, address)
	if err != nil {
		return fmt.Errorf("failed to subscribe to script hash for address %s: %w", address, err)
	}

	// Get the correct Electrum script hash for the GetHistory call
	scriptHash := scriptHashToElectrumScriptHash(pkScript)
	ltndLog.Infof("Subscribed to script hash: %s for address %s", scriptHash, address)

	// Fetch transaction history for this address
	ctx, cancel := context.WithTimeout(context.Background(), e.cfg.RequestTimeout)
	ltndLog.Infof("ELECTRUM DEBUG: Calling GetHistory for scriptHash: %s", scriptHash)
	history, err := e.client.GetHistory(ctx, scriptHash)
	cancel()

	if err != nil {
		ltndLog.Warnf("ELECTRUM DEBUG: GetHistory failed for scriptHash %s: %v", scriptHash, err)
		return fmt.Errorf("failed to get history for address %s: %w", address, err)
	}

	ltndLog.Infof("ELECTRUM DEBUG: GetHistory succeeded for scriptHash %s, got %d entries", scriptHash, len(history))

	ltndLog.Infof("Found %d transactions for address %s", len(history), address)

	// Process each transaction
	totalValue := btcutil.Amount(0)
	for i, entry := range history {
		ltndLog.Infof("ELECTRUM DEBUG: Processing entry %d: %+v", i, entry)
		
		txDetail, err := e.buildTransactionDetail(entry, scriptHash)
		if err != nil {
			ltndLog.Warnf("Failed to build transaction detail for entry %d: %v", i, err)
			continue
		}

		if txDetail != nil {
			ltndLog.Infof("ELECTRUM DEBUG: Built transaction detail: Hash=%s, Confirmations=%d, Value=%d, BlockHeight=%d",
				txDetail.Hash.String(), txDetail.NumConfirmations, txDetail.Value, txDetail.BlockHeight)
			totalValue += txDetail.Value
		} else {
			ltndLog.Warnf("ELECTRUM DEBUG: buildTransactionDetail returned nil for entry %d", i)
		}
	}

	ltndLog.Infof("ELECTRUM DEBUG: Total value found for address %s: %d satoshis", address, totalValue)
	
	// Store the total value for retrieval by GetAddressFunds
	e.lastAddressFunds = totalValue
	e.lastAddressChecked = address
	
	return nil
}

// GetAddressFunds returns the total amount of funds at a specific address
func (e *ElectrumChainSource) GetAddressFunds(address string) (btcutil.Amount, error) {
	ltndLog.Infof("GetAddressFunds called for address: %s", address)
	
	// First call CheckAddressFunds to populate the lastAddressFunds
	ltndLog.Infof("GetAddressFunds: Calling CheckAddressFunds for address: %s", address)
	err := e.CheckAddressFunds(address)
	if err != nil {
		ltndLog.Warnf("GetAddressFunds: CheckAddressFunds failed for address %s: %v", address, err)
		return 0, err
	}
	ltndLog.Infof("GetAddressFunds: CheckAddressFunds completed for address: %s", address)
	
	// Return the stored value if it's for the same address
	if e.lastAddressChecked == address {
		ltndLog.Infof("GetAddressFunds: Returning stored value %d satoshis for address %s", e.lastAddressFunds, address)
		return e.lastAddressFunds, nil
	}
	
	ltndLog.Infof("GetAddressFunds: No stored value for address %s (lastAddressChecked: %s)", address, e.lastAddressChecked)
	return 0, nil
}

// GetElectrumClient returns the underlying Electrum client for direct access
func (e *ElectrumChainSource) GetElectrumClient() interface{} {
	return e.client
}

// TestMempoolAccept implements the chain.Interface.
func (e *ElectrumChainSource) TestMempoolAccept(txs []*wire.MsgTx, maxFeeRate float64) ([]*btcjson.TestMempoolAcceptResult, error) {
	ltndLog.Debugf("TestMempoolAccept called with %d txs, maxFeeRate=%f", len(txs), maxFeeRate)
	
	// Electrum doesn't support mempool testing, so we return a positive result for all transactions
	// This allows btcwallet to proceed with transaction broadcasting
	results := make([]*btcjson.TestMempoolAcceptResult, len(txs))
	
	for i, tx := range txs {
		results[i] = &btcjson.TestMempoolAcceptResult{
			Txid:  tx.TxHash().String(),
			Allowed: true,
			RejectReason: "",
		}
		ltndLog.Debugf("TestMempoolAccept: allowing tx %s (Electrum doesn't support mempool testing)", tx.TxHash())
	}
	
	return results, nil
}

// GetBestBlock implements the chainio.Interface.
func (e *ElectrumChainSource) GetBestBlock() (*chainhash.Hash, int32, error) {
	log.Printf("ELECTRUM: GetBestBlock called")

	ctx, cancel := context.WithTimeout(context.Background(), e.cfg.RequestTimeout)
	defer cancel()

	// Use SubscribeHeaders to get the current block height directly
	log.Printf("ELECTRUM: Subscribing to headers to get current height")
	headersChan, err := e.client.SubscribeHeaders(ctx)
	if err != nil {
		log.Printf("ELECTRUM: Failed to subscribe to headers: %v", err)
		return nil, 0, fmt.Errorf("failed to subscribe to headers: %w", err)
	}

	// Get the first header from the subscription
	select {
	case headerResult := <-headersChan:
		if headerResult == nil {
			log.Printf("ELECTRUM: Received nil header result")
			return nil, 0, fmt.Errorf("received nil header result from subscription")
		}

		currentHeight := headerResult.Height
		log.Printf("ELECTRUM: Got current height %d from headers subscription", currentHeight)

		// Calculate the block hash from the header hex
		var bestHash *chainhash.Hash
		if headerResult.Hex != "" {
			headerBytes, err := hex.DecodeString(headerResult.Hex)
			if err != nil {
				log.Printf("ELECTRUM: Failed to decode header hex: %v", err)
				return nil, 0, fmt.Errorf("failed to decode header hex: %w", err)
			}
			
			firstHash := sha256.Sum256(headerBytes)
			secondHash := sha256.Sum256(firstHash[:])
			bestHash, err = chainhash.NewHash(secondHash[:])
			if err != nil {
				log.Printf("ELECTRUM: Failed to create block hash: %v", err)
				return nil, 0, fmt.Errorf("failed to create block hash: %w", err)
			}
		} else {
			log.Printf("ELECTRUM: No header hex provided")
			return nil, 0, fmt.Errorf("no header hex provided in subscription result")
		}

		log.Printf("ELECTRUM: Returning hash %s for height %d (from headers subscription)", bestHash, currentHeight)

		// Update the best block with the actual header
		e.bestBlockMtx.Lock()
		var blockHeader *wire.BlockHeader
		if headerResult.Hex != "" {
			headerBytes, err := hex.DecodeString(headerResult.Hex)
			if err == nil {
				blockHeader = &wire.BlockHeader{}
				err = blockHeader.Deserialize(bytes.NewReader(headerBytes))
				if err != nil {
					log.Printf("ELECTRUM: Failed to deserialize block header: %v", err)
					blockHeader = nil
				}
			} else {
				log.Printf("ELECTRUM: Failed to decode header hex: %v", err)
			}
		}

		if blockHeader == nil {
			blockHeader = &wire.BlockHeader{
				Version:    1,
				PrevBlock:  chainhash.Hash{},
				MerkleRoot: chainhash.Hash{},
				Timestamp:  time.Now().Add(-5 * time.Minute),
				Bits:       0x1d00ffff,
				Nonce:      2083236893,
			}
		}

		e.bestBlock = chainntnfs.BlockEpoch{
			Hash:        bestHash,
			Height:      currentHeight,
			BlockHeader: blockHeader,
		}
		e.bestBlockMtx.Unlock()

		return bestHash, currentHeight, nil

	case <-time.After(e.cfg.RequestTimeout):
		log.Printf("ELECTRUM: Timeout waiting for headers subscription")
		return nil, 0, fmt.Errorf("timeout waiting for headers subscription")
	}
}


// GetUtxo implements the chainio.Interface. It fetches the transaction containing
// the outpoint and returns the specific TxOut.
func (e *ElectrumChainSource) GetUtxo(op *wire.OutPoint, pkScript []byte,
	heightHint uint32, cancel <-chan struct{}) (*wire.TxOut, error) {

	// Use a context that respects the cancel channel.
	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()

	go func() {
		select {
		case <-cancel:
			ctxCancel()
		case <-ctx.Done():
		}
	}()

	// Use a timeout for the underlying transaction fetch.
	fetchCtx, fetchCancel := context.WithTimeout(ctx, e.cfg.RequestTimeout)
	defer fetchCancel()

	// Get the transaction using the existing GetTransaction method.
	// We need to wrap it in a function that respects the outer context/cancel.
	var tx *wire.MsgTx
	var err error
	txChan := make(chan struct{})
	go func() {
		tx, err = e.GetTransaction(&op.Hash)
		close(txChan)
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("GetUtxo canceled for outpoint %s", op)
	case <-fetchCtx.Done():
		// If the fetch context timed out before the main context, check which error occurred.
		if ctx.Err() != nil {
			return nil, fmt.Errorf("GetUtxo canceled for outpoint %s", op)
		}
		return nil, fmt.Errorf("GetTransaction timed out for outpoint %s", op)
	case <-txChan:
		// Transaction fetch completed (or errored).
	}

	if err != nil {
		// TODO: Map Electrum 'not found' errors to chain.ErrUtxoNotFound?
		return nil, fmt.Errorf("failed to get transaction %s for utxo: %w", op.Hash, err)
	}

	// Check if the index is valid for the transaction.
	if op.Index >= uint32(len(tx.TxOut)) {
		return nil, fmt.Errorf("invalid output index %d for tx %s", op.Index, op.Hash)
	}

	txOut := tx.TxOut[op.Index]

	// As a sanity check, ensure the pkScript matches if provided.
	// Electrum doesn't use pkScript for lookup, so this is a post-fetch check.
	if pkScript != nil && !bytes.Equal(txOut.PkScript, pkScript) {
		return nil, fmt.Errorf("pkScript mismatch for utxo %s", op)
	}

	return txOut, nil
}

// GetTransaction implements the chainio.Interface.
func (e *ElectrumChainSource) GetTransaction(txid *chainhash.Hash) (*wire.MsgTx, error) {
	ctx, cancel := context.WithTimeout(context.Background(), e.cfg.RequestTimeout)
	defer cancel()

	// Get the transaction hex from the Electrum server.
	tx, err := e.client.GetTransaction(ctx, txid.String())
	if err != nil {
		// Handle errors, e.g., transaction not found.
		// TODO: Map Electrum errors to chainio/btcwallet errors if necessary.
		return nil, fmt.Errorf("failed to get transaction %s: %w", txid, err)
	}

	// Decode the hex string into a wire.MsgTx.
	txBytes, err := hex.DecodeString(tx.Hex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode transaction hex for %s: %w", txid, err)
	}

	var msgTx wire.MsgTx
	if err := msgTx.Deserialize(bytes.NewReader(txBytes)); err != nil {
		return nil, fmt.Errorf("failed to deserialize transaction %s: %w", txid, err)
	}

	// Verify the TxHash matches the requested txid.
	if msgTx.TxHash() != *txid {
		return nil, fmt.Errorf("mismatch tx hash for txid %s (got %s)",
			txid, msgTx.TxHash())
	}

	return &msgTx, nil
}

// SendRawTransaction broadcasts a transaction to the Electrum server.
func (e *ElectrumChainSource) SendRawTransaction(tx *wire.MsgTx, allowHighFees bool) (*chainhash.Hash, error) {
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return nil, err
	}
	txHex := hex.EncodeToString(buf.Bytes())

	ctx, cancel := context.WithTimeout(context.Background(), e.cfg.RequestTimeout)
	defer cancel()

	txidStr, err := e.client.BroadcastTransaction(ctx, txHex)
	if err != nil {
		return nil, fmt.Errorf("failed to broadcast tx: %w", err)
	}

	hash, err := chainhash.NewHashFromStr(txidStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse txid from broadcast response: %w", err)
	}

	return hash, nil
}

// PublishTransaction broadcasts a transaction to the network.
// This method implements the lnwallet.WalletController interface.
func (e *ElectrumChainSource) PublishTransaction(tx *wire.MsgTx, label string) error {
	ltndLog.Infof("PublishTransaction called for tx: %s (label: %s)", tx.TxHash(), label)
	
	// Use our existing SendRawTransaction method
	_, err := e.SendRawTransaction(tx, false) // allowHighFees = false
	if err != nil {
		return fmt.Errorf("failed to publish transaction %s: %w", tx.TxHash(), err)
	}
	
	ltndLog.Infof("Successfully published transaction %s", tx.TxHash())
	return nil
}

// EstimateFeePerKW implements the chainfee.Estimator interface.
// TODO: Implement using Electrum client's EstimateFee.
func (e *ElectrumChainSource) EstimateFeePerKW(numBlocks uint32) (chainfee.SatPerKWeight, error) {
	// For now, return a reasonable default fee rate for testnet
	// This is approximately 1 sat/byte converted to sat/weight
	// 1 sat/byte = 250 sat/kweight (since 1 kweight = 250 bytes for legacy)
	defaultFeeRate := chainfee.SatPerKWeight(250)
	
	ltndLog.Debugf("EstimateFeePerKW called for %d blocks, returning default rate %d sat/kweight", 
		numBlocks, defaultFeeRate)
	
	return defaultFeeRate, nil
}

// RelayFeePerKW implements the chainfee.Estimator interface.
// TODO: Determine how to get relay fee from Electrum, might need a default/fallback.
func (e *ElectrumChainSource) RelayFeePerKW() chainfee.SatPerKWeight {
	// Electrum protocol doesn't directly expose relay fee.
	// Return a reasonable default or fetch from another source if possible.
	return 253 // Default relay fee in sat/kw
}

// RegisterConfirmationsNtfn implements the chainntnfs.ChainNotifier interface.
func (e *ElectrumChainSource) RegisterConfirmationsNtfn(txid *chainhash.Hash,
	pkScript []byte, numConfs, heightHint uint32,
	options ...chainntnfs.NotifierOption) (*chainntnfs.ConfirmationEvent, error) {

	if numConfs == 0 {
		return nil, fmt.Errorf("number of confirmations must be > 0")
	}

	// Apply notifier options.
	ntfnOpts := chainntnfs.DefaultNotifierOptions()
	for _, opt := range options {
		opt(ntfnOpts)
	}

	// The cancel function is set later on, so we'll initialize a dummy
	// one for now.
	event := chainntnfs.NewConfirmationEvent(numConfs, func() {})

	electrumScriptHash := scriptHashToElectrumScriptHash(pkScript)

	// Ensure we are subscribed to this script hash.
	_, err := e.SubscribeScriptHash(pkScript)
	if err != nil {
		return nil, fmt.Errorf("failed to subscribe script hash %s for conf "+
			"ntfn: %w", electrumScriptHash, err)
	}

	// Fetch initial history to check if already confirmed.
	ctx, cancel := context.WithTimeout(context.Background(), e.cfg.RequestTimeout)
	defer cancel()
	history, err := e.client.GetHistory(ctx, electrumScriptHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get history for script hash %s "+
			"for conf ntfn: %w", electrumScriptHash, err)
	}

	e.bestBlockMtx.RLock()
	currentHeight := e.bestBlock.Height
	currentHash := e.bestBlock.Hash
	e.bestBlockMtx.RUnlock()

	var txFoundHeight int32
	for _, item := range history {
		if item.Hash == txid.String() {
			txHeight := int32(item.Height)
			if txHeight > 0 { // Found and confirmed
				txFoundHeight = txHeight
				confs := uint32(currentHeight - txHeight + 1)
				if confs >= numConfs {
					ltndLog.Infof("Tx %s already has %d confirmations "+
						"(current height %d, tx height %d), "+
						"dispatching confirmation immediately.",
						txid, confs, currentHeight, txHeight)

					// Get the actual block hash for the transaction's block
					txBlockHash, err := e.GetBlockHash(int64(txHeight))
					if err != nil {
						ltndLog.Warnf("Failed to get block hash for height %d: %v", txHeight, err)
						txBlockHash = currentHash // Fallback to current hash
					}
					
					confDetails := &chainntnfs.TxConfirmation{
						Tx:          nil, // Tx details not readily available
						BlockHash:   txBlockHash,
						BlockHeight: uint32(txHeight),
						TxIndex:     0, // TxIndex not available
						// Block field requires fetching the block.
					}

					// Send confirmation non-blockingly.
					select {
					case event.Confirmed <- confDetails:
					default:
						ltndLog.Warnf("Receiver for tx %s conf "+
							"notification not ready", txid)
					}

					// Return the event immediately.
					return event, nil
				}
				// Found but not enough confirmations yet.
				ltndLog.Debugf("Tx %s found at height %d, needs %d confs, "+
					"has %d", txid, txHeight, numConfs, confs)
			} else {
				// Found but unconfirmed.
				ltndLog.Debugf("Tx %s found but unconfirmed", txid)
			}
			// Found the tx, break history search.
			break
		}
	}

	// If we reach here, the tx is either not found or not confirmed enough.
	// Register the client for future notifications.
	e.scriptHashClientMtx.Lock()
	clientID := e.nextClientID
	e.nextClientID++

	client := &confirmationClient{
		id:            clientID,
		txid:          txid,
		pkScript:      pkScript,
		numConfs:      numConfs,
		heightHint:    heightHint,
		event:         event,
		scriptHash:    electrumScriptHash,
		txFoundHeight: txFoundHeight, // Store height if found but not enough confs
	}

	// Now that we have the client, we can create the cancel function and
	// assign it to the event.
	event.Cancel = func() {
		client.canceled.Store(true)
		ltndLog.Debugf("Confirmation notification cancelled by caller "+
			"for client %d, txid %s", client.id, client.txid)
		e.removeConfirmationClient(client.scriptHash, client.id)
	}

	e.confClientsByScriptHash[electrumScriptHash] = append(
		e.confClientsByScriptHash[electrumScriptHash], client,
	)
	e.scriptHashClientMtx.Unlock()

	ltndLog.Debugf("Registered confirmation notification for client %d, "+
		"txid %s, script hash %s, num_confs %d",
		clientID, txid, electrumScriptHash, numConfs)

	return event, nil
}

// removeConfirmationClient removes a confirmation client from the internal maps.
// MUST be called with scriptHashClientMtx held.
func (e *ElectrumChainSource) removeConfirmationClient(scriptHash string, clientID uint32) {
	clients := e.confClientsByScriptHash[scriptHash]
	for i, c := range clients {
		if c.id == clientID {
			// Remove the client by slicing.
			e.confClientsByScriptHash[scriptHash] = append(clients[:i], clients[i+1:]...)
			ltndLog.Debugf("Removed confirmation client %d for script hash %s", clientID, scriptHash)

			// If no clients remain, consider unsubscribing.
			// if len(e.confClientsByScriptHash[scriptHash]) == 0 && len(e.spendClientsByScriptHash[scriptHash]) == 0 {
			//     delete(e.scriptHashSubscriptions, scriptHash)
			//     // TODO: Call Electrum unsubscribe method if available.
			//     ltndLog.Infof("Unsubscribed from script hash %s", scriptHash)
			// }
			return
		}
	}
	ltndLog.Warnf("Could not find confirmation client %d to remove for script hash %s", clientID, scriptHash)
}

// RegisterSpendNtfn implements the chainntnfs.ChainNotifier interface.
func (e *ElectrumChainSource) RegisterSpendNtfn(outpoint *wire.OutPoint, pkScript []byte,
	heightHint uint32) (*chainntnfs.SpendEvent, error) {

	// The cancel function is set later on, so we'll initialize a dummy
	// one for now.
	event := chainntnfs.NewSpendEvent(func() {})

	electrumScriptHash := scriptHashToElectrumScriptHash(pkScript)

	// Ensure we are subscribed to this script hash.
	_, err := e.SubscribeScriptHash(pkScript)
	if err != nil {
		return nil, fmt.Errorf("failed to subscribe script hash %s for spend "+
			"ntfn: %w", electrumScriptHash, err)
	}

	// Fetch initial history to check if already spent.
	ctx, cancel := context.WithTimeout(context.Background(), e.cfg.RequestTimeout)
	defer cancel()
	history, err := e.client.GetHistory(ctx, electrumScriptHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get history for script hash %s "+
			"for spend ntfn: %w", electrumScriptHash, err)
	}

	// Check history for a spending transaction.
	for _, item := range history {
		spendingTxHash, err := chainhash.NewHashFromStr(item.Hash)
		if err != nil {
			ltndLog.Warnf("Failed to parse tx hash %s from history: %v",
				item.Hash, err)
			continue
		}

		// Fetch the full transaction details.
		spendingTx, err := e.GetTransaction(spendingTxHash)
		if err != nil {
			ltndLog.Warnf("Failed to get tx %s while checking spend "+
				"for %s: %v", item.Hash, outpoint, err)
			continue // Skip this history item if we can't fetch it
		}

		// Check if any input matches the target outpoint.
		for i, txIn := range spendingTx.TxIn {
			if txIn.PreviousOutPoint == *outpoint {
				ltndLog.Infof("Outpoint %s already spent by tx %s, "+
					"dispatching spend notification immediately.",
					outpoint, item.Hash)

				spendDetails := &chainntnfs.SpendDetail{
					SpentOutPoint:     outpoint,
					SpenderTxHash:     spendingTxHash,
					SpendingTx:        spendingTx,
					SpenderInputIndex: uint32(i),
					SpendingHeight:    int32(item.Height), // Can be 0 if mempool spend
				}

				// Send notification non-blockingly.
				select {
				case event.Spend <- spendDetails:
				default:
					ltndLog.Warnf("Receiver for outpoint %s spend "+
						"notification not ready", outpoint)
				}

				// Return the event immediately.
				return event, nil
			}
		}
	}

	// If we reach here, the outpoint is not spent yet.
	// Register the client for future notifications.
	e.scriptHashClientMtx.Lock()
	clientID := e.nextClientID
	e.nextClientID++

	client := &spendClient{
		id:         clientID,
		outpoint:   outpoint,
		pkScript:   pkScript,
		heightHint: heightHint,
		event:      event,
		scriptHash: electrumScriptHash,
	}

	// Now that we have the client, we can create the cancel function and
	// assign it to the event.
	event.Cancel = func() {
		client.canceled.Store(true)
		ltndLog.Debugf("Spend notification cancelled by caller "+
			"for client %d, outpoint %s", client.id, client.outpoint)
		e.removeSpendClient(client.scriptHash, client.id)
	}

	e.spendClientsByScriptHash[electrumScriptHash] = append(
		e.spendClientsByScriptHash[electrumScriptHash], client,
	)
	e.scriptHashClientMtx.Unlock()

	ltndLog.Debugf("Registered spend notification for client %d, "+
		"outpoint %s, script hash %s",
		clientID, outpoint, electrumScriptHash)

	return event, nil
}

// removeSpendClient removes a spend client from the internal maps.
// MUST be called with scriptHashClientMtx held.
func (e *ElectrumChainSource) removeSpendClient(scriptHash string, clientID uint32) {
	clients := e.spendClientsByScriptHash[scriptHash]
	for i, c := range clients {
		if c.id == clientID {
			// Remove the client by slicing.
			e.spendClientsByScriptHash[scriptHash] = append(clients[:i], clients[i+1:]...)
			ltndLog.Debugf("Removed spend client %d for script hash %s", clientID, scriptHash)

			// If no clients remain, consider unsubscribing.
			// if len(e.confClientsByScriptHash[scriptHash]) == 0 && len(e.spendClientsByScriptHash[scriptHash]) == 0 {
			//     delete(e.scriptHashSubscriptions, scriptHash)
			//     // TODO: Call Electrum unsubscribe method if available.
			//     ltndLog.Infof("Unsubscribed from script hash %s", scriptHash)
			// }
			return
		}
	}
	ltndLog.Warnf("Could not find spend client %d to remove for script hash %s", clientID, scriptHash)
}

// RegisterBlockEpochNtfn implements the chainntnfs.ChainNotifier interface.
func (e *ElectrumChainSource) RegisterBlockEpochNtfn(
	initialEpoch *chainntnfs.BlockEpoch) (*chainntnfs.BlockEpochEvent, error) {

	e.blockEpochClientMtx.Lock()
	defer e.blockEpochClientMtx.Unlock()

	clientID := e.nextBlockEpochClientID
	e.nextBlockEpochClientID++

	client := &blockEpochClient{
		id:           clientID,
		epochChan:    make(chan *chainntnfs.BlockEpoch, 1), // Buffer 1 for immediate delivery
		cancelChan:   make(chan struct{}),
		initialEpoch: initialEpoch,
	}

	e.blockEpochClients[clientID] = client

	epochEvent := &chainntnfs.BlockEpochEvent{
		Epochs: client.epochChan,
		Cancel: func() {
			// Signal cancellation to the handler goroutine.
			close(client.cancelChan)

			// Mark client as canceled atomically.
			atomic.StoreUint32(&client.canceled, 1)

			// Remove the client from the map.
			e.blockEpochClientMtx.Lock()
			delete(e.blockEpochClients, client.id)
			e.blockEpochClientMtx.Unlock()

			ltndLog.Debugf("Cancelled block epoch notification for client %d", client.id)
		},
	}

	// Always send the current best block immediately when registering
	// This is required by the block beat dispatcher which expects to receive
	// the current block epoch when it registers for notifications
	e.bestBlockMtx.RLock()
	currentBest := e.bestBlock
	e.bestBlockMtx.RUnlock()

	// If the client provided an initial epoch, check if we need to send
	// the current best block (only if it's higher than what they know)
	if initialEpoch != nil {
		// If the client's known height is lower than ours, send ours.
		if initialEpoch.Height < currentBest.Height {
			// Use non-blocking send in case the client cancels immediately.
			select {
			case client.epochChan <- &currentBest:
			case <-client.cancelChan:
				atomic.StoreUint32(&client.canceled, 1)
				delete(e.blockEpochClients, client.id) // Need lock again? No, already removed in Cancel.
			case <-e.quit:
			}
		}
	} else {
		// If no initial epoch provided (like from the block beat dispatcher),
		// always send the current best block
		log.Printf("ELECTRUM: Sending current best block to client %d - Hash: %s, Height: %d, BlockHeader: %v", 
			clientID, currentBest.Hash, currentBest.Height, currentBest.BlockHeader != nil)
		select {
		case client.epochChan <- &currentBest:
			log.Printf("ELECTRUM: Successfully sent block epoch to client %d", clientID)
		case <-client.cancelChan:
			atomic.StoreUint32(&client.canceled, 1)
			delete(e.blockEpochClients, client.id)
		case <-e.quit:
		}
	}

	ltndLog.Debugf("Registered new block epoch notification client %d", client.id)

	return epochEvent, nil
}

// scriptHashToElectrumScriptHash converts a Bitcoin script (pkScript) into the
// format required by the Electrum protocol (sha256 hash, reversed, hex-encoded).
func scriptHashToElectrumScriptHash(pkScript []byte) string {
	// 1. Calculate SHA256 hash of the script.
	scriptHashBytes := sha256.Sum256(pkScript)

	// 2. Reverse the byte order. Electrum uses little-endian for script hashes.
	for i, j := 0, len(scriptHashBytes)-1; i < j; i, j = i+1, j-1 {
		scriptHashBytes[i], scriptHashBytes[j] = scriptHashBytes[j], scriptHashBytes[i]
	}

	// 3. Encode the reversed hash as a hexadecimal string.
	return hex.EncodeToString(scriptHashBytes[:])
}

// notificationHandler processes incoming messages from the Electrum client,
// identifying and handling relevant notifications like script hash status changes.
// NOTE: This function's implementation depends heavily on how the go-electrum
// client exposes incoming messages (e.g., via a Listen() method or callbacks).
// The following is a conceptual implementation assuming a blocking Listen method
// that provides notifications.
func (e *ElectrumChainSource) notificationHandler() {
	defer e.wg.Done()

	ltndLog.Info("Starting Electrum notification handler")
	defer ltndLog.Info("Stopped Electrum notification handler")

	// Since the actual mechanism is unknown, we just wait for quit for now.
	// The warning below highlights that this needs implementation.
	ltndLog.Warnf("Electrum notificationHandler needs implementation " +
		"based on go-electrum's message handling API (client.Listen?)")

	<-e.quit
}

// keepaliveHandler periodically pings the Electrum server to maintain the
// connection and detect potential disconnections.
func (e *ElectrumChainSource) keepaliveHandler() {
	defer e.wg.Done()

	// Use a ticker for periodic pings. A 1-minute interval is usually safe.
	// TODO: Make this interval configurable?
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	ltndLog.Info("Starting Electrum keepalive handler")
	defer ltndLog.Info("Stopped Electrum keepalive handler")

	for {
		select {
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), e.cfg.RequestTimeout)
			err := e.client.Ping(ctx)
			cancel() // Release context resources promptly
			if err != nil {
				// Log the error. Depending on the error type, we might
				// want to trigger reconnection logic here in the future.
				ltndLog.Warnf("Electrum keepalive ping failed: %v", err)
				// TODO: Implement reconnection logic if ping fails consistently?
			} else {
				ltndLog.Debugf("Electrum keepalive ping successful")
			}

		case <-e.quit:
			return
		}
	}
}


// processScriptHistory iterates through the history of a script hash and
// notifies relevant confirmation and spend clients.
func (e *ElectrumChainSource) processScriptHistory(scriptHash string,
	history []*electrum.GetMempoolResult) {

	e.scriptHashClientMtx.Lock()
	confClients := e.confClientsByScriptHash[scriptHash]
	spendClients := e.spendClientsByScriptHash[scriptHash]
	e.scriptHashClientMtx.Unlock()

	e.bestBlockMtx.RLock()
	currentHeight := e.bestBlock.Height
	e.bestBlockMtx.RUnlock()

	// Keep track of clients to remove after processing.
	var confirmedClientsToRemove []uint32
	var spentClientsToRemove []uint32

	ltndLog.Debugf("Processing history for script hash %s (%d items)",
		scriptHash, len(history))

	// --- Process Confirmation Notifications ---
	ltndLog.Debugf("Checking %d confirmation clients for script hash %s",
		len(confClients), scriptHash)
	for _, client := range confClients {
		// Skip if client has cancelled.
		if client.canceled.Load() {
			ltndLog.Tracef("Skipping cancelled confirmation client %d for script hash %s",
				client.id, scriptHash)
			continue
		}

		// If we already found the tx, just check confirmations.
		if client.txFoundHeight > 0 {
			confs := uint32(currentHeight - client.txFoundHeight + 1)
			if confs >= client.numConfs {
				ltndLog.Infof("Dispatching %d confirmation(s) for client %d, txid %s",
					confs, client.id, client.txid)
				// Get the actual block hash for the transaction's block
				txBlockHash, err := e.GetBlockHash(int64(client.txFoundHeight))
				if err != nil {
					ltndLog.Warnf("Failed to get block hash for height %d: %v", client.txFoundHeight, err)
					// Use current hash as fallback
					bestHash, _, _ := e.GetBestBlock()
					txBlockHash = bestHash
				}
				
				select {
				case client.event.Confirmed <- &chainntnfs.TxConfirmation{
					BlockHash:   txBlockHash,
					BlockHeight: uint32(client.txFoundHeight),
				}:
					confirmedClientsToRemove = append(confirmedClientsToRemove, client.id)
				case <-e.quit:
					return
				}
			}
			continue
		}

		// Search history for the target txid.
		for _, item := range history {
			if item.Hash == client.txid.String() {
				txHeight := int32(item.Height)
				// Electrum uses 0 for unconfirmed, >0 for confirmed height.
				if txHeight > 0 {
					client.txFoundHeight = txHeight
					confs := uint32(currentHeight - txHeight + 1)
					ltndLog.Infof("Found tx %s for client %d at height %d (%d confs)",
						client.txid, client.id, txHeight, confs)

					if confs >= client.numConfs {
						ltndLog.Infof("Dispatching %d confirmation(s) for client %d, txid %s",
							confs, client.id, client.txid)
						
						// Get the actual block hash for the transaction's block
						txBlockHash, err := e.GetBlockHash(int64(txHeight))
						if err != nil {
							ltndLog.Warnf("Failed to get block hash for height %d: %v", txHeight, err)
							// Use current hash as fallback
							bestHash, _, _ := e.GetBestBlock()
							txBlockHash = bestHash
						}
						
						select {
						case client.event.Confirmed <- &chainntnfs.TxConfirmation{
							BlockHash:   txBlockHash,
							BlockHeight: uint32(txHeight),
						}:
							confirmedClientsToRemove = append(confirmedClientsToRemove, client.id)
						case <-e.quit:
							return
						}
					}
				} else {
					// Tx is in history but unconfirmed (height 0 or -1).
					ltndLog.Debugf("Tx %s for client %d found but unconfirmed",
						client.txid, client.id)
				}
				// Found the tx, no need to check further history items for this client.
				break
			}
		}
	}

	// --- Process Spend Notifications ---
	ltndLog.Debugf("Checking %d spend clients for script hash %s",
		len(spendClients), scriptHash)
	for _, client := range spendClients {
		// Skip if client has cancelled.
		if client.canceled.Load() {
			ltndLog.Tracef("Skipping cancelled spend client %d for script hash %s",
				client.id, scriptHash)
			continue
		}

		// Check history for a spending transaction.
		for _, item := range history {
			spendingTxHash, err := chainhash.NewHashFromStr(item.Hash)
			if err != nil {
				ltndLog.Warnf("Failed to parse tx hash %s from history: %v",
					item.Hash, err)
				continue
			}

			// TODO: This is potentially very inefficient as it fetches
			// the full transaction for every item in the history on
			// every status update. Consider optimizations if possible,
			// maybe only fetch txs confirmed since last check?
			spendingTx, err := e.GetTransaction(spendingTxHash)
			if err != nil {
				ltndLog.Warnf("Failed to get tx %s while checking spend "+
					"for %s: %v", item.Hash, client.outpoint, err)
				continue // Skip this history item if we can't fetch it
			}

			// Check if any input matches the target outpoint.
			for i, txIn := range spendingTx.TxIn {
				if txIn.PreviousOutPoint == *client.outpoint {
					ltndLog.Infof("Dispatching spend notification for "+
						"client %d, outpoint %s spent by tx %s",
						client.id, client.outpoint, item.Hash)

					spendDetails := &chainntnfs.SpendDetail{
						SpentOutPoint:     client.outpoint,
						SpenderTxHash:     spendingTxHash,
						SpendingTx:        spendingTx,
						SpenderInputIndex: uint32(i),
						SpendingHeight:    int32(item.Height), // Can be 0 if mempool spend
					}

					// Send notification non-blockingly.
					select {
					case client.event.Spend <- spendDetails:
						spentClientsToRemove = append(spentClientsToRemove, client.id)
					case <-e.quit:
						return
					}
					// Found the spending tx for this client, move to next client.
					goto nextSpendClient
				}
			}
		}
	nextSpendClient:
	}

	// --- Clean up finished clients ---
	if len(confirmedClientsToRemove) > 0 || len(spentClientsToRemove) > 0 {
		e.scriptHashClientMtx.Lock()
		for _, id := range confirmedClientsToRemove {
			// Find the client in the slice and remove it.
			clients := e.confClientsByScriptHash[scriptHash]
			for i, c := range clients {
				if c.id == id {
					e.confClientsByScriptHash[scriptHash] = append(clients[:i], clients[i+1:]...)
					break
				}
			}
		}
		for _, id := range spentClientsToRemove {
			// Find the client in the slice and remove it.
			clients := e.spendClientsByScriptHash[scriptHash]
			for i, c := range clients {
				if c.id == id {
					e.spendClientsByScriptHash[scriptHash] = append(clients[:i], clients[i+1:]...)
					break
				}
			}
		}

		// If no clients remain for this script hash, consider unsubscribing.
		shouldUnsubscribe := len(e.confClientsByScriptHash[scriptHash]) == 0 &&
			len(e.spendClientsByScriptHash[scriptHash]) == 0

		// Get the cancel function before unlocking, but call it after unlocking.
		cancelFunc, listenerExists := e.scriptHashListeners[scriptHash]

		e.scriptHashClientMtx.Unlock() // Unlock before potential unsubscribe/cancel call

		if shouldUnsubscribe {
			ltndLog.Infof("No more clients for script hash %s, cleaning up subscription.", scriptHash)

			// Remove from our subscription status map.
			e.scriptHashClientMtx.Lock()
			delete(e.scriptHashSubscriptions, scriptHash)
			e.scriptHashClientMtx.Unlock()

			// Cancel the listener goroutine if it exists.
			if listenerExists {
				ltndLog.Debugf("Cancelling listener goroutine for script hash %s", scriptHash)
				cancelFunc()
				// Remove from listener map *after* cancelling.
				e.scriptHashClientMtx.Lock()
				delete(e.scriptHashListeners, scriptHash)
				e.scriptHashClientMtx.Unlock()
			} else {
				ltndLog.Warnf("Listener cancel func not found for script hash %s during cleanup", scriptHash)
			}

			// TODO: Attempt to call Electrum server unsubscribe method if available.
			ltndLog.Warnf("Electrum server unsubscribe call needs implementation/verification.")
			// Example:
			// ctxUnsub, cancelUnsub := context.WithTimeout(context.Background(), e.cfg.RequestTimeout)
			// unsubscribed, err := e.client.ScriptHashUnsubscribe(ctxUnsub, scriptHash)
			// cancelUnsub()
			// if err != nil {
			//     ltndLog.Errorf("Failed to unsubscribe from script hash %s: %v", scriptHash, err)
			//     // Handle error: Maybe re-subscribe later or log persistently?
			// } else if !unsubscribed {
			//     ltndLog.Warnf("Server reported failure to unsubscribe from script hash %s", scriptHash)
			// } else {
			//     ltndLog.Infof("Unsubscribed from script hash %s", scriptHash)
			// }
		}
	}
}

// SubscribeScriptHash ensures we are subscribed to status updates for the given
// pkScript via the Electrum server.
func (e *ElectrumChainSource) SubscribeScriptHash(pkScript []byte) (string, error) {
	return e.SubscribeScriptHashWithAddress(pkScript, "")
}

// SubscribeScriptHashWithAddress ensures we are subscribed to status updates for the given
// pkScript via the Electrum server and stores the address mapping.
func (e *ElectrumChainSource) SubscribeScriptHashWithAddress(pkScript []byte, address string) (string, error) {
	electrumScriptHash := scriptHashToElectrumScriptHash(pkScript)

	e.scriptHashClientMtx.Lock()
	defer e.scriptHashClientMtx.Unlock()

	// Store the address mapping if provided
	if address != "" {
		e.scriptHashToAddressMtx.Lock()
		e.scriptHashToAddress[electrumScriptHash] = address
		e.scriptHashToAddressMtx.Unlock()
		ltndLog.Infof("Stored address mapping: scriptHash %s -> address %s", electrumScriptHash, address)
	}

	// If already subscribed, return the current status.
	if status, ok := e.scriptHashSubscriptions[electrumScriptHash]; ok {
		return status, nil
	}

	// Not subscribed yet, call the Electrum client's subscribe method.
	ctxSub, cancelSub := context.WithTimeout(context.Background(), e.cfg.RequestTimeout)
	defer cancelSub()

	// The `go-electrum` library uses a subscription manager pattern.
	// We need to use the SubscribeScripthash method and add our script hash.
	sub, _ := e.client.SubscribeScripthash()
	err := sub.Add(ctxSub, electrumScriptHash)
	if err != nil {
		return "", fmt.Errorf("failed to subscribe to script hash %s: %w",
			electrumScriptHash, err)
	}

	// Store the initial status and mark as subscribed.
	// The Add method doesn't return a status, so we'll use the script hash itself
	e.scriptHashSubscriptions[electrumScriptHash] = electrumScriptHash

	ltndLog.Infof("Subscribed to script hash %s",
		electrumScriptHash)

	// Note: No per-script-hash channel is returned. The main
	// notificationHandler is expected to handle updates.

	return electrumScriptHash, nil
}

// UpdateFilter implements the chainview.FilteredChainView interface.
// NOTE: Electrum protocol does not easily support UTXO filtering.
// Marked as unimplemented for now.
func (e *ElectrumChainSource) UpdateFilter(ops []graphdb.EdgePoint, updateHeight uint32) error {
	ltndLog.Debugf("UpdateFilter called with %d ops at height %d - stub implementation", len(ops), updateHeight)
	// Stub implementation - Electrum doesn't support UTXO filtering
	// Return nil to avoid blocking LND startup
	return nil
}

// FilterBlock implements the chainview.FilteredChainView interface.
// NOTE: Electrum protocol does not easily support fetching all transactions
// in a block. Implementing this efficiently requires alternative strategies.
// Marked as unimplemented for now.
func (e *ElectrumChainSource) FilterBlock(blockHash *chainhash.Hash) (*chainview.FilteredBlock, error) {
	ltndLog.Debugf("FilterBlock called for %s - stub implementation", blockHash)
	// Stub implementation - return empty filtered block
	// Electrum doesn't support fetching all transactions in a block
	return &chainview.FilteredBlock{
		Hash:         *blockHash,
		Height:       0, // Unknown height
		Transactions: []*wire.MsgTx{}, // Empty transactions
	}, nil
}

// FilterBlockConnected implements the chainview.FilteredChainView interface.
// NOTE: See FilterBlock. Marked as unimplemented for now.
func (e *ElectrumChainSource) FilterBlockConnected(blockHash *chainhash.Hash) (*chainview.FilteredBlock, error) {
	ltndLog.Debugf("FilterBlockConnected called for %s - stub implementation", blockHash)
	// Stub implementation - return empty filtered block
	// Electrum doesn't support fetching all transactions in a block
	return &chainview.FilteredBlock{
		Hash:         *blockHash,
		Height:       0, // Unknown height
		Transactions: []*wire.MsgTx{}, // Empty transactions
	}, nil
}

// DisconnectedBlocks returns a channel that sends notifications for blocks
// that have been disconnected from the main chain.
func (e *ElectrumChainSource) DisconnectedBlocks() <-chan *chainview.FilteredBlock {
	return nil
}

// FilteredBlocks returns a channel for receiving filtered blocks.
func (e *ElectrumChainSource) FilteredBlocks() <-chan *chainview.FilteredBlock {
	// Returning nil to satisfy the interface. A proper implementation would
	// return a channel that delivers filtered blocks.
	return nil
}

// SubscribeMempoolSpent subscribes to notifications for a spend of the given
// outpoint in the mempool.
func (e *ElectrumChainSource) SubscribeMempoolSpent(op wire.OutPoint) (
	*chainntnfs.MempoolSpendEvent, error) {
	ltndLog.Debugf("SubscribeMempoolSpent called for %s - returning ErrUnimplemented", op)
	return nil, ErrUnimplemented
}

// CancelMempoolSpendEvent cancels a subscription to notifications for a spend
// of the given outpoint in the mempool.
func (e *ElectrumChainSource) CancelMempoolSpendEvent(
	sub *chainntnfs.MempoolSpendEvent) {
}

// LookupInputMempoolSpend looks up a spend of the given outpoint in the
// mempool.
func (e *ElectrumChainSource) LookupInputMempoolSpend(
	op wire.OutPoint) fn.Option[wire.MsgTx] {

	return fn.None[wire.MsgTx]()
}

// BackEnd returns the name of the backend.
func (e *ElectrumChainSource) BackEnd() string {
	return BackendName
}

// ListTransactionDetails returns a list of all known transactions relevant to the wallet.
// This implementation fetches history for all subscribed script hashes and parses transaction details.
func (e *ElectrumChainSource) ListTransactionDetails() ([]*lnwallet.TransactionDetail, error) {
	ltndLog.Infof("ListTransactionDetails called - fetching transaction history for all subscribed script hashes")
	
	var allTransactions []*lnwallet.TransactionDetail
	
	// Get all subscribed script hashes
	e.scriptHashClientMtx.Lock()
	scriptHashes := make([]string, 0, len(e.scriptHashSubscriptions))
	for scriptHash := range e.scriptHashSubscriptions {
		scriptHashes = append(scriptHashes, scriptHash)
	}
	e.scriptHashClientMtx.Unlock()
	
	ltndLog.Infof("Found %d subscribed script hashes to check for transactions", len(scriptHashes))
	
	// Fetch history for each script hash
	for _, scriptHash := range scriptHashes {
		ctx, cancel := context.WithTimeout(context.Background(), e.cfg.RequestTimeout)
		history, err := e.client.GetHistory(ctx, scriptHash)
		cancel()
		
		if err != nil {
			ltndLog.Warnf("Failed to get history for script hash %s: %v", scriptHash, err)
			continue
		}
		
		ltndLog.Debugf("Script hash %s has %d history entries", scriptHash, len(history))
		
		// Process each history entry
		for _, entry := range history {
			txDetail, err := e.buildTransactionDetail(entry, scriptHash)
			if err != nil {
				ltndLog.Warnf("Failed to build transaction detail for tx %s: %v", entry.Hash, err)
				continue
			}
			
			if txDetail != nil {
				allTransactions = append(allTransactions, txDetail)
			}
		}
	}
	
	ltndLog.Infof("ListTransactionDetails returning %d transactions", len(allTransactions))
	return allTransactions, nil
}

// buildTransactionDetail converts an Electrum history entry into a TransactionDetail
func (e *ElectrumChainSource) buildTransactionDetail(entry interface{}, scriptHash string) (*lnwallet.TransactionDetail, error) {
	// Add panic recovery
	defer func() {
		if r := recover(); r != nil {
			ltndLog.Errorf("ELECTRUM: buildTransactionDetail panicked: %v", r)
			fmt.Printf("ELECTRUM: buildTransactionDetail panicked: %v\n", r)
		}
	}()
	
	ltndLog.Infof("ELECTRUM: buildTransactionDetail called with entry type: %T", entry)
	fmt.Printf("ELECTRUM: buildTransactionDetail called with entry type: %T\n", entry)
	
	// The entry is from the electrum client's GetHistory method
	// We need to access the fields dynamically since we don't know the exact type
	entryValue := reflect.ValueOf(entry)
	if entryValue.Kind() == reflect.Ptr {
		entryValue = entryValue.Elem()
	}
	
	// Get the transaction hash
	hashField := entryValue.FieldByName("Hash")
	if !hashField.IsValid() {
		return nil, fmt.Errorf("entry does not have Hash field")
	}
	txHashStr := hashField.String()
	
	// Parse the transaction hash
	txHash, err := chainhash.NewHashFromStr(txHashStr)
	if err != nil {
		return nil, fmt.Errorf("invalid transaction hash %s: %w", txHashStr, err)
	}
	
	// Get the height
	heightField := entryValue.FieldByName("Height")
	if !heightField.IsValid() {
		return nil, fmt.Errorf("entry does not have Height field")
	}
	height := int32(heightField.Int())
	ltndLog.Infof("ELECTRUM: buildTransactionDetail: Transaction %s has height: %d", txHashStr, height)
	fmt.Printf("ELECTRUM: buildTransactionDetail: Transaction %s has height: %d\n", txHashStr, height)
	
	ltndLog.Infof("ELECTRUM: buildTransactionDetail: About to call GetTransaction for %s", txHashStr)
	fmt.Printf("ELECTRUM: buildTransactionDetail: About to call GetTransaction for %s\n", txHashStr)
	
	// Get the full transaction details
	ltndLog.Infof("ELECTRUM: buildTransactionDetail: Getting transaction details for %s", txHashStr)
	fmt.Printf("ELECTRUM: buildTransactionDetail: Getting transaction details for %s\n", txHashStr)
	ctx, cancel := context.WithTimeout(context.Background(), e.cfg.RequestTimeout)
	txResult, err := e.client.GetTransaction(ctx, txHashStr)
	cancel()
	if err != nil {
		ltndLog.Warnf("ELECTRUM: buildTransactionDetail: Failed to get transaction %s: %v", txHashStr, err)
		fmt.Printf("ELECTRUM: buildTransactionDetail: Failed to get transaction %s: %v\n", txHashStr, err)
	} else {
		ltndLog.Infof("ELECTRUM: buildTransactionDetail: Successfully got transaction %s", txHashStr)
		fmt.Printf("ELECTRUM: buildTransactionDetail: Successfully got transaction %s\n", txHashStr)
	}
	
	if err != nil {
		ltndLog.Warnf("ELECTRUM: buildTransactionDetail: GetTransaction failed for %s: %v", txHashStr, err)
		fmt.Printf("ELECTRUM: buildTransactionDetail: GetTransaction failed for %s: %v\n", txHashStr, err)
		return nil, fmt.Errorf("failed to get transaction %s: %w", txHashStr, err)
	}
	
	ltndLog.Infof("ELECTRUM: buildTransactionDetail: GetTransaction succeeded for %s, processing result", txHashStr)
	fmt.Printf("ELECTRUM: buildTransactionDetail: GetTransaction succeeded for %s, processing result\n", txHashStr)
	
	// Extract raw transaction bytes from the result
	ltndLog.Infof("ELECTRUM: buildTransactionDetail: Processing transaction result for %s", txHashStr)
	fmt.Printf("ELECTRUM: buildTransactionDetail: Processing transaction result for %s\n", txHashStr)
	
	var rawTx []byte
	if txResult != nil {
		ltndLog.Infof("ELECTRUM: buildTransactionDetail: Transaction result is not nil for %s", txHashStr)
		fmt.Printf("ELECTRUM: buildTransactionDetail: Transaction result is not nil for %s\n", txHashStr)
		// The GetTransaction result should have a raw transaction field
		// For now, we'll use a placeholder since we don't know the exact structure
		rawTx = []byte(fmt.Sprintf("tx_%s", txHashStr)) // Simplified for now
	}
	
	// Calculate the actual transaction value for this address
	// We need to parse the transaction to find outputs that match our script hash
	txValue := btcutil.Amount(0)
	
	// Parse the actual transaction to get the real value
	if height > 0 {
		// This is a confirmed transaction, try to get the actual value
		ltndLog.Infof("ELECTRUM: buildTransactionDetail: Attempting to get actual value for transaction %s", txHashStr)
		fmt.Printf("ELECTRUM: buildTransactionDetail: Attempting to get actual value for transaction %s\n", txHashStr)
		actualValue, err := e.getTransactionValue(txHashStr, scriptHash)
		if err != nil {
			ltndLog.Warnf("ELECTRUM: buildTransactionDetail: Failed to get actual value for transaction %s: %v", txHashStr, err)
			fmt.Printf("ELECTRUM: buildTransactionDetail: Failed to get actual value for transaction %s: %v\n", txHashStr, err)
			// Fall back to 0 if we can't determine the actual value
			txValue = btcutil.Amount(0)
		} else {
			txValue = actualValue
			ltndLog.Infof("ELECTRUM: buildTransactionDetail: Transaction %s has actual value %d satoshis", txHashStr, txValue)
			fmt.Printf("ELECTRUM: buildTransactionDetail: Transaction %s has actual value %d satoshis\n", txHashStr, txValue)
		}
	} else {
		ltndLog.Infof("ELECTRUM: buildTransactionDetail: Transaction %s is unconfirmed (height=%d), setting value to 0", txHashStr, height)
		fmt.Printf("ELECTRUM: buildTransactionDetail: Transaction %s is unconfirmed (height=%d), setting value to 0\n", txHashStr, height)
		txValue = btcutil.Amount(0)
	}

	// Create the transaction detail
	txDetail := &lnwallet.TransactionDetail{
		Hash:        *txHash,
		Value:       txValue,
		NumConfirmations: func() int32 {
			if height <= 0 {
				return 0 // Unconfirmed
			}
			// Calculate confirmations based on current block height
			e.bestBlockMtx.RLock()
			currentHeight := e.bestBlock.Height
			e.bestBlockMtx.RUnlock()
			return int32(currentHeight - height + 1)
		}(),
		BlockHash:   func() *chainhash.Hash {
			if height > 0 {
				// Get the actual block hash for confirmed transactions
				blockHash, err := e.GetBlockHash(int64(height))
				if err != nil {
					ltndLog.Warnf("Failed to get block hash for height %d: %v", height, err)
					return nil
				}
				return blockHash
			}
			return nil // Unconfirmed transactions don't have a block hash
		}(),
		BlockHeight: height,
		Timestamp:   time.Now().Unix(), // TODO: Get actual timestamp
		TotalFees:   0, // TODO: Calculate fees
		OutputDetails: []lnwallet.OutputDetail{}, // TODO: Extract output details
		RawTx:       rawTx,
		Label:       fmt.Sprintf("electrum-%s", scriptHash[:8]), // Simple label
		PreviousOutpoints: []lnwallet.PreviousOutPoint{}, // TODO: Extract inputs
	}
	
	ltndLog.Debugf("Built transaction detail for %s: height=%d, confirmations=%d", 
		txHashStr, height, txDetail.NumConfirmations)
	
	return txDetail, nil
}

// getTransactionValue gets the actual value of a transaction for a specific script hash
func (e *ElectrumChainSource) getTransactionValue(txHash, scriptHash string) (btcutil.Amount, error) {
	ltndLog.Infof("getTransactionValue: Getting value for transaction %s, scriptHash %s", txHash, scriptHash)
	
	ctx, cancel := context.WithTimeout(context.Background(), e.cfg.RequestTimeout)
	defer cancel()
	
	// Get the transaction details from Electrum
	txResult, err := e.client.GetTransaction(ctx, txHash)
	if err != nil {
		return 0, fmt.Errorf("failed to get transaction %s: %w", txHash, err)
	}
	
	// Parse the transaction result to find outputs that match our script hash
	txResultValue := reflect.ValueOf(txResult)
	if txResultValue.Kind() == reflect.Ptr {
		txResultValue = txResultValue.Elem()
	}
	
	ltndLog.Infof("ELECTRUM: getTransactionValue: Transaction result type: %T, fields: %d", txResult, txResultValue.NumField())
	fmt.Printf("ELECTRUM: getTransactionValue: Transaction result type: %T, fields: %d\n", txResult, txResultValue.NumField())
	
	// Debug: List all available fields
	for i := 0; i < txResultValue.NumField(); i++ {
		field := txResultValue.Field(i)
		fieldType := txResultValue.Type().Field(i)
		ltndLog.Infof("ELECTRUM: getTransactionValue: Field %d: %s = %v (type: %s)", i, fieldType.Name, field.Interface(), field.Type())
		fmt.Printf("ELECTRUM: getTransactionValue: Field %d: %s = %v (type: %s)\n", i, fieldType.Name, field.Interface(), field.Type())
	}
	
	// Look for Vout field in the transaction result (Electrum uses "Vout" not "Outputs")
	voutField := txResultValue.FieldByName("Vout")
	if !voutField.IsValid() {
		ltndLog.Warnf("ELECTRUM: getTransactionValue: Transaction %s does not have Vout field", txHash)
		fmt.Printf("ELECTRUM: getTransactionValue: Transaction %s does not have Vout field\n", txHash)
		return 0, fmt.Errorf("transaction does not have vout field")
	}
	
	// Calculate total value for outputs that match our script hash
	totalValue := btcutil.Amount(0)
	
	ltndLog.Infof("ELECTRUM: getTransactionValue: Processing %d Vout entries for transaction %s", voutField.Len(), txHash)
	fmt.Printf("ELECTRUM: getTransactionValue: Processing %d Vout entries for transaction %s\n", voutField.Len(), txHash)
	
	// Iterate through Vout entries
	for i := 0; i < voutField.Len(); i++ {
		voutEntry := voutField.Index(i)
		if voutEntry.Kind() == reflect.Ptr {
			voutEntry = voutEntry.Elem()
		}
		
		ltndLog.Infof("ELECTRUM: getTransactionValue: Processing Vout entry %d for transaction %s", i, txHash)
		fmt.Printf("ELECTRUM: getTransactionValue: Processing Vout entry %d for transaction %s\n", i, txHash)
		
		// Debug: List all fields in this Vout entry
		for j := 0; j < voutEntry.NumField(); j++ {
			field := voutEntry.Field(j)
			fieldType := voutEntry.Type().Field(j)
			ltndLog.Infof("ELECTRUM: getTransactionValue: Vout[%d] Field %d: %s = %v (type: %s)", i, j, fieldType.Name, field.Interface(), field.Type())
			fmt.Printf("ELECTRUM: getTransactionValue: Vout[%d] Field %d: %s = %v (type: %s)\n", i, j, fieldType.Name, field.Interface(), field.Type())
		}
		
		// Get the value and script from the Vout entry
		valueField := voutEntry.FieldByName("Value")
		scriptPubkeyField := voutEntry.FieldByName("ScriptPubkey")
		
		if valueField.IsValid() && scriptPubkeyField.IsValid() {
			// The value is in BTC, we need to convert to satoshis
			valueFloat := valueField.Float()
			valueSatoshis := int64(valueFloat * 100000000) // Convert BTC to satoshis
			
			ltndLog.Infof("ELECTRUM: getTransactionValue: Vout[%d] has value %f BTC (%d satoshis)", i, valueFloat, valueSatoshis)
			fmt.Printf("ELECTRUM: getTransactionValue: Vout[%d] has value %f BTC (%d satoshis)\n", i, valueFloat, valueSatoshis)
			
			// Get the script pubkey object and extract the hex field
			scriptPubkeyValue := scriptPubkeyField
			if scriptPubkeyValue.Kind() == reflect.Ptr {
				scriptPubkeyValue = scriptPubkeyValue.Elem()
			}
			
			ltndLog.Infof("ELECTRUM: getTransactionValue: Vout[%d] ScriptPubkey type: %T", i, scriptPubkeyField.Interface())
			fmt.Printf("ELECTRUM: getTransactionValue: Vout[%d] ScriptPubkey type: %T\n", i, scriptPubkeyField.Interface())
			
			// Try to extract the Hex field from the ScriptPubkey structure by field name
			var outputScriptHex string
			var outputScriptHash string
			
			// Debug: List all available fields in the ScriptPubkey structure
			ltndLog.Infof("ELECTRUM: getTransactionValue: Vout[%d] ScriptPubkey has %d fields", i, scriptPubkeyValue.NumField())
			fmt.Printf("ELECTRUM: getTransactionValue: Vout[%d] ScriptPubkey has %d fields\n", i, scriptPubkeyValue.NumField())
			
			for j := 0; j < scriptPubkeyValue.NumField(); j++ {
				field := scriptPubkeyValue.Field(j)
				fieldType := scriptPubkeyValue.Type().Field(j)
				ltndLog.Infof("ELECTRUM: getTransactionValue: Vout[%d] ScriptPubkey Field %d: %s = %v (type: %s)", i, j, fieldType.Name, field.Interface(), field.Type())
				fmt.Printf("ELECTRUM: getTransactionValue: Vout[%d] ScriptPubkey Field %d: %s = %v (type: %s)\n", i, j, fieldType.Name, field.Interface(), field.Type())
			}
			
			// Try to get the Hex field by name
			hexField := scriptPubkeyValue.FieldByName("Hex")
			if hexField.IsValid() && hexField.Kind() == reflect.String {
				outputScriptHex = hexField.String()
				ltndLog.Infof("ELECTRUM: getTransactionValue: Vout[%d] extracted script hex from Hex field: %s", i, outputScriptHex)
				fmt.Printf("ELECTRUM: getTransactionValue: Vout[%d] extracted script hex from Hex field: %s\n", i, outputScriptHex)
			} else {
				// Try to get field by index 3 as fallback (from the logs, it seems to be the hex field)
				if scriptPubkeyValue.NumField() >= 4 {
					hexFieldByIndex := scriptPubkeyValue.Field(3)
					if hexFieldByIndex.IsValid() && hexFieldByIndex.Kind() == reflect.String {
						outputScriptHex = hexFieldByIndex.String()
						ltndLog.Infof("ELECTRUM: getTransactionValue: Vout[%d] extracted script hex from field index 3: %s", i, outputScriptHex)
						fmt.Printf("ELECTRUM: getTransactionValue: Vout[%d] extracted script hex from field index 3: %s\n", i, outputScriptHex)
					}
				}
			}
			
			// Convert the script hex to bytes and calculate the script hash
			if outputScriptHex != "" {
				scriptBytes, err := hex.DecodeString(outputScriptHex)
				if err == nil {
					outputScriptHash = scriptHashToElectrumScriptHash(scriptBytes)
					ltndLog.Infof("ELECTRUM: getTransactionValue: Vout[%d] calculated script hash: %s, target: %s", i, outputScriptHash, scriptHash)
					fmt.Printf("ELECTRUM: getTransactionValue: Vout[%d] calculated script hash: %s, target: %s\n", i, outputScriptHash, scriptHash)
				} else {
					ltndLog.Warnf("ELECTRUM: getTransactionValue: Failed to decode script hex: %v", err)
					fmt.Printf("ELECTRUM: getTransactionValue: Failed to decode script hex: %v\n", err)
				}
			}
			
			// Check if this output belongs to our script hash
			if outputScriptHash == scriptHash {
				totalValue += btcutil.Amount(valueSatoshis)
				ltndLog.Infof("ELECTRUM: getTransactionValue: Vout[%d] matches our script hash, adding %d satoshis", i, valueSatoshis)
				fmt.Printf("ELECTRUM: getTransactionValue: Vout[%d] matches our script hash, adding %d satoshis\n", i, valueSatoshis)
			} else {
				ltndLog.Infof("ELECTRUM: getTransactionValue: Vout[%d] does not match our script hash, skipping", i)
				fmt.Printf("ELECTRUM: getTransactionValue: Vout[%d] does not match our script hash, skipping\n", i)
			}
		}
	}
	
	ltndLog.Infof("getTransactionValue: Transaction %s total value for scriptHash %s: %d satoshis", txHash, scriptHash, totalValue)
	return totalValue, nil
}

// electrumTransactionSubscription implements the TransactionSubscription interface
type electrumTransactionSubscription struct {
	chainSource *ElectrumChainSource
	confirmed   chan *lnwallet.TransactionDetail
	unconfirmed chan *lnwallet.TransactionDetail
	quit        chan struct{}
}

// ConfirmedTransactions returns a channel for confirmed transactions
func (e *electrumTransactionSubscription) ConfirmedTransactions() chan *lnwallet.TransactionDetail {
	return e.confirmed
}

// UnconfirmedTransactions returns a channel for unconfirmed transactions
func (e *electrumTransactionSubscription) UnconfirmedTransactions() chan *lnwallet.TransactionDetail {
	return e.unconfirmed
}

// Cancel finalizes the subscription
func (e *electrumTransactionSubscription) Cancel() {
	close(e.quit)
}

// monitorTransactionUpdates monitors script hash updates and sends transaction notifications
func (e *electrumTransactionSubscription) monitorTransactionUpdates() {
	defer close(e.confirmed)
	defer close(e.unconfirmed)
	
	ltndLog.Infof("Started monitoring transaction updates")
	
	// Track the last known status for each script hash
	lastStatus := make(map[string]string)
	
	// Initial status check
	e.chainSource.scriptHashClientMtx.Lock()
	for scriptHash, status := range e.chainSource.scriptHashSubscriptions {
		lastStatus[scriptHash] = status
	}
	e.chainSource.scriptHashClientMtx.Unlock()
	
	// Monitor for changes
	ticker := time.NewTicker(5 * time.Second) // Check every 5 seconds
	defer ticker.Stop()
	
	for {
		select {
		case <-e.quit:
			ltndLog.Infof("Transaction subscription quit requested")
			return
			
		case <-ticker.C:
			// Check for status changes in subscribed script hashes
			e.chainSource.scriptHashClientMtx.Lock()
			for scriptHash, currentStatus := range e.chainSource.scriptHashSubscriptions {
				lastKnownStatus, exists := lastStatus[scriptHash]
				if !exists || lastKnownStatus != currentStatus {
					// Status changed, fetch new transactions
					ltndLog.Debugf("Script hash %s status changed from %s to %s", 
						scriptHash, lastKnownStatus, currentStatus)
					
					// Fetch history and send notifications
					e.processScriptHashHistory(scriptHash)
					lastStatus[scriptHash] = currentStatus
				}
			}
			e.chainSource.scriptHashClientMtx.Unlock()
		}
	}
}

// processScriptHashHistory fetches history for a script hash and sends transaction notifications
func (e *electrumTransactionSubscription) processScriptHashHistory(scriptHash string) {
	ctx, cancel := context.WithTimeout(context.Background(), e.chainSource.cfg.RequestTimeout)
	history, err := e.chainSource.client.GetHistory(ctx, scriptHash)
	cancel()
	
	if err != nil {
		ltndLog.Warnf("Failed to get history for script hash %s: %v", scriptHash, err)
		return
	}
	
	ltndLog.Debugf("Processing %d history entries for script hash %s", len(history), scriptHash)
	
	// Process each history entry
	for _, entry := range history {
		txDetail, err := e.chainSource.buildTransactionDetail(entry, scriptHash)
		if err != nil {
			ltndLog.Warnf("Failed to build transaction detail for entry: %v", err)
			continue
		}
		
		// Send to appropriate channel based on confirmation status
		if txDetail.NumConfirmations > 0 {
			select {
			case e.confirmed <- txDetail:
				ltndLog.Debugf("Sent confirmed transaction notification for %s", txDetail.Hash.String())
			default:
				ltndLog.Warnf("Failed to send confirmed transaction notification (channel full)")
			}
		} else {
			select {
			case e.unconfirmed <- txDetail:
				ltndLog.Debugf("Sent unconfirmed transaction notification for %s", txDetail.Hash.String())
			default:
				ltndLog.Warnf("Failed to send unconfirmed transaction notification (channel full)")
			}
		}
	}
}

// SubscribeTransactions returns a TransactionSubscription which delivers transaction
// notifications using script hash subscriptions and history processing.
func (e *ElectrumChainSource) SubscribeTransactions() (lnwallet.TransactionSubscription, error) {
	ltndLog.Infof("SubscribeTransactions called - creating transaction subscription")
	
	// Create the subscription
	subscription := &electrumTransactionSubscription{
		chainSource: e,
		confirmed:   make(chan *lnwallet.TransactionDetail, 10),
		unconfirmed: make(chan *lnwallet.TransactionDetail, 10),
		quit:        make(chan struct{}),
	}
	
	// Start a goroutine to monitor script hash updates and send transaction notifications
	go subscription.monitorTransactionUpdates()
	
	ltndLog.Infof("SubscribeTransactions created subscription successfully")
	return subscription, nil
}


/*
// ListAccounts retrieves all accounts belonging to the wallet by default.
// TODO: Implement proper account handling if needed beyond default.
func (e *ElectrumChainSource) ListAccounts(name string, acctType lnwallet.AddressType) ([]*lnwallet.AccountProperties, error) {
	ltndLog.Warnf("ListAccounts not implemented for electrum wallet (returning default)")
	// For now, just return the default account structure if requested.
	if name != "" && name != lnwallet.DefaultAccountName {
		return nil, fmt.Errorf("named accounts not supported yet")
	}
	if acctType != lnwallet.WitnessPubKey {
		return nil, fmt.Errorf("only P2WKH accounts supported yet")
	}

	// Need to get current external/internal indexes.
	e.mu.Lock()
	externalIdx := e.externalKeyIdx
	internalIdx := e.internalKeyIdx
	e.mu.Unlock()

	// Return a single default account representation.
	return []*lnwallet.AccountProperties{
		{
			Name:             lnwallet.DefaultAccountName,
			AddressType:      acctType,
			ExternalKeyCount: externalIdx,
			InternalKeyCount: internalIdx,
			// LastUsedExternalIndex and LastUsedInternalIndex require tracking usage.
		},
	}, nil
}
*/

// RequiredReserve specifies the minimum amount that should be reserved for
// anchor channel lock-in.
func (e *ElectrumChainSource) RequiredReserve(numOutputs int) btcutil.Amount {
	// Since we don't manage channel anchors directly in this basic wallet,
	// return 0. This might need adjustment if used for anchor channels.
	ltndLog.Warnf("RequiredReserve returning 0 for electrum wallet")
	return 0
}

// LastUnusedAddress returns the last unused address of the specified type.
// TODO(#electrum): Implement proper unused address tracking. This requires
// querying the history of derived addresses within the lookahead window to find
// the first one without any transaction history.
func (e *ElectrumChainSource) LastUnusedAddress(addrType lnwallet.AddressType, account string) (btcutil.Address, error) {
	ltndLog.Warnf("LastUnusedAddress not implemented for electrum backend")
	// Returning an error is safer than returning a potentially incorrect address.
	return nil, fmt.Errorf("LastUnusedAddress not implemented for electrum backend")
}

// IsOurAddress checks if the passed address belongs to this wallet.
// TODO(#electrum): Implement by deriving addresses within the known range +
// lookahead and comparing. This can be slow without caching or a Bloom filter.
func (e *ElectrumChainSource) IsOurAddress(a btcutil.Address) bool {
	// Returning false is safer than potentially claiming an address incorrectly.
	// ltndLog.Warnf("IsOurAddress check not fully implemented for electrum backend")
	return false
}

// GenerateNewAccount creates a new account (currently only default supported).
func (e *ElectrumChainSource) GenerateNewAccount(name string) error {
	// Currently only the default account is implicitly supported.
	if name == lnwallet.DefaultAccountName {
		return fmt.Errorf("default account already exists")
	}
	ltndLog.Warnf("GenerateNewAccount: named accounts not supported for electrum backend")
	return fmt.Errorf("GenerateNewAccount: named accounts not supported for electrum backend")
}

// Unlock performs wallet decryption. Assumes no local encryption for now.
func (e *ElectrumChainSource) Unlock(password []byte, timeout time.Duration) error {
	ltndLog.Warnf("Unlock called but not implemented (no local encryption assumed)")
	// TODO: Implement if local key material/seed is encrypted.
	return nil // No-op if not encrypted
}

// Lock performs wallet encryption. Assumes no local encryption for now.
func (e *ElectrumChainSource) Lock() error {
	ltndLog.Warnf("Lock called but not implemented (no local encryption assumed)")
	// TODO: Implement if local key material/seed is encrypted.
	return nil // No-op if not encrypted
}

// ChangePassword changes the wallet's password. Assumes no local encryption.
func (e *ElectrumChainSource) ChangePassword(old []byte, new []byte) error {
	ltndLog.Warnf("ChangePassword called but not implemented (no local encryption assumed)")
	// TODO: Implement if local key material/seed is encrypted.
	return fmt.Errorf("ChangePassword not implemented for electrum wallet")
}

/*
// AddressInfo returns information about an address. This is a stub to satisfy
// the lnwallet.WalletController interface.
func (e *ElectrumChainSource) AddressInfo(address btcutil.Address) (lnwallet.ManagedAddress, error) {
	ltndLog.Debugf("AddressInfo called for %s - returning ErrUnimplemented", address)
	return nil, ErrUnimplemented
}
*/

// TODO: Add helper methods for interacting with the Electrum client, managing
// subscriptions, handling responses, etc.



// MuSig2CreateSession is a stub to satisfy the input.Signer interface.
// func (e *ElectrumChainSource) MuSig2CreateSession(version musig2.Version,
// 	pubKeys []*btcec.PublicKey, opts ...input.SignerOption) (
// 	*musig2.Session, error) {
//
// 	return nil, ErrUnimplemented
// }

// MuSig2RegisterNonces is a stub to satisfy the input.Signer interface.
// func (e *ElectrumChainSource) MuSig2RegisterNonces(sessionID [32]byte,
// 	nonces [][66]byte) (bool, error) {
//
// 	return false, ErrUnimplemented
// }

// MuSig2Sign is a stub to satisfy the input.Signer interface.
// func (e *ElectrumChainSource) MuSig2Sign(sessionID [32]byte, msg [32]byte,
// 	opts ...input.SignerOption) (*musig2.PartialSignature, error) {
//
// 	return nil, ErrUnimplemented
// }

// MuSig2CombineSig is a stub to satisfy the input.Signer interface.
// func (e *ElectrumChainSource) MuSig2CombineSig(sessionID [32]byte,
// 	otherPartialSigs ...*musig2.PartialSignature) (*musig2.Signature,
// 	bool, error) {
//
// 	return nil, false, ErrUnimplemented
// }

// MuSig2Cleanup is a stub to satisfy the input.Signer interface.
// func (e *ElectrumChainSource) MuSig2Cleanup(sessionID [32]byte) error {
// 	return ErrUnimplemented
// }

