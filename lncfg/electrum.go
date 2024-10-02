package lncfg

// Electrum holds the configuration options for the daemon's connection to
// electrum.
//
//nolint:lll
type Electrum struct {
	Host string `long:"host" description:"Electrum host to connect to."`
}
