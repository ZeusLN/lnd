module github.com/lightningnetwork/lnd

require (
	github.com/BoltzExchange/boltz-client v1.2.8-0.20241217064837-ea3afc0fc447
	github.com/NebulousLabs/go-upnp v0.0.0-20180202185039-29b680b06c82
	github.com/Yawning/aez v0.0.0-20211027044916-e49e68abd344
	github.com/andybalholm/brotli v1.0.4
	github.com/breez/breez v0.0.0-20240503132701-33b83b83c2fe
	github.com/btcsuite/btcd v0.24.3-0.20240921052913-67b8efd3ba53
	github.com/btcsuite/btcd/btcec/v2 v2.3.4
	github.com/btcsuite/btcd/btcutil v1.1.5
	github.com/btcsuite/btcd/btcutil/psbt v1.1.8
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f
	github.com/btcsuite/btcwallet v0.16.10-0.20240912233857-ffb143c77cc5
	github.com/btcsuite/btcwallet/wallet/txauthor v1.3.5
	github.com/btcsuite/btcwallet/wallet/txrules v1.2.2
	github.com/btcsuite/btcwallet/walletdb v1.4.4
	github.com/btcsuite/btcwallet/wtxmgr v1.5.4
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf
	github.com/davecgh/go-spew v1.1.1
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0
	github.com/gabstv/go-bsdiff v1.0.5
	github.com/go-errors/errors v1.4.2
	github.com/golang/protobuf v1.5.4
	github.com/gorilla/websocket v1.5.0
	github.com/grpc-ecosystem/go-grpc-middleware v1.3.0
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.22.0
	github.com/jackc/pgx/v4 v4.18.2
	github.com/jackpal/gateway v1.0.5
	github.com/jackpal/go-nat-pmp v0.0.0-20170405195558-28a68d0c24ad
	github.com/jedib0t/go-pretty/v6 v6.2.7
	github.com/jessevdk/go-flags v1.5.0
	github.com/jrick/logrotate v1.1.2
	github.com/kkdai/bstream v1.0.0
	github.com/lightninglabs/chantools v0.13.5
	github.com/lightninglabs/lightning-node-connect v0.3.1-alpha
	github.com/lightninglabs/lightning-terminal v0.10.5-alpha
	github.com/lightninglabs/neutrino v0.16.1-0.20240425105051-602843d34ffd
	github.com/lightninglabs/neutrino/cache v1.1.2
	github.com/lightningnetwork/lightning-onion v1.2.1-0.20240712235311-98bd56499dfb
	github.com/lightningnetwork/lnd/cert v1.2.2
	github.com/lightningnetwork/lnd/clock v1.1.1
	github.com/lightningnetwork/lnd/fn v1.2.3
	github.com/lightningnetwork/lnd/healthcheck v1.2.5
	github.com/lightningnetwork/lnd/kvdb v1.4.10
	github.com/lightningnetwork/lnd/queue v1.1.1
	github.com/lightningnetwork/lnd/sqldb v1.0.4
	github.com/lightningnetwork/lnd/ticker v1.1.1
	github.com/lightningnetwork/lnd/tlv v1.2.6
	github.com/lightningnetwork/lnd/tor v1.1.3
	github.com/ltcsuite/ltcd v0.22.1-beta
	github.com/miekg/dns v1.1.50
	github.com/prometheus/client_golang v1.14.0
	github.com/stretchr/testify v1.9.0
	github.com/tv42/zbase32 v0.0.0-20220222190657-f76a9fc892fa
	github.com/urfave/cli v1.22.9
	go.etcd.io/bbolt v1.3.11
	go.etcd.io/etcd/client/pkg/v3 v3.5.7
	go.etcd.io/etcd/client/v3 v3.5.7
	golang.org/x/crypto v0.31.0
	golang.org/x/exp v0.0.0-20240325151524-a685a6edb6d8
	golang.org/x/mobile v0.0.0-20190719004257-d2bd2a29d028
	golang.org/x/net v0.27.0
	golang.org/x/sync v0.10.0
	golang.org/x/term v0.27.0
	golang.org/x/time v0.3.0
	google.golang.org/grpc v1.65.0
	google.golang.org/protobuf v1.34.2
	gopkg.in/macaroon-bakery.v2 v2.3.0
	gopkg.in/macaroon.v2 v2.1.0
	pgregory.net/rapid v1.1.0
)

require (
	dario.cat/mergo v1.0.0 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20230124172434-306776ec8161 // indirect
	github.com/Microsoft/go-winio v0.6.1 // indirect
	github.com/NebulousLabs/fastrand v0.0.0-20181203155948-6fb6489aac4e // indirect
	github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5 // indirect
	github.com/aead/chacha20 v0.0.0-20180709150244-8b13a72661da // indirect
	github.com/aead/siphash v1.0.1 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/btcsuite/btcwallet/wallet/txsizes v1.2.5 // indirect
	github.com/btcsuite/go-socks v0.0.0-20170105172521-4720035b7bfd // indirect
	github.com/btcsuite/websocket v0.0.0-20150119174127-31079b680792 // indirect
	github.com/btcsuite/winsvc v1.0.0 // indirect
	github.com/cenkalti/backoff/v4 v4.2.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/containerd/continuity v0.3.0 // indirect
	github.com/coreos/go-semver v0.3.1 // indirect
	github.com/coreos/go-systemd/v22 v22.5.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.0.1 // indirect
	github.com/decred/dcrd/lru v1.1.2 // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/cli v27.1.1+incompatible // indirect
	github.com/docker/docker v27.1.1+incompatible // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/dsnet/compress v0.0.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fatih/color v1.15.0 // indirect
	github.com/fergusstrange/embedded-postgres v1.25.0 // indirect
	github.com/fsnotify/fsnotify v1.5.4 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-macaroon-bakery/macaroonpb v1.0.0 // indirect
	github.com/go-viper/mapstructure/v2 v2.0.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.1 // indirect
	github.com/golang-migrate/migrate/v4 v4.17.0 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway v1.16.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/jackc/chunkreader/v2 v2.0.1 // indirect
	github.com/jackc/pgconn v1.14.3 // indirect
	github.com/jackc/pgerrcode v0.0.0-20240316143900-6e2875d9b438 // indirect
	github.com/jackc/pgio v1.0.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgproto3/v2 v2.3.3 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/jackc/pgtype v1.14.0 // indirect
	github.com/jackc/pgx/v5 v5.6.0 // indirect
	github.com/jackc/puddle v1.3.0 // indirect
	github.com/jackc/puddle/v2 v2.2.1 // indirect
	github.com/jonboulle/clockwork v0.3.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/compress v1.16.0 // indirect
	github.com/lib/pq v1.10.9 // indirect
	github.com/lightninglabs/faraday v0.2.11-alpha // indirect
	github.com/lightninglabs/gozmq v0.0.0-20191113021534-d20a764486bf // indirect
	github.com/lightninglabs/lightning-node-connect/hashmailrpc v1.0.2 // indirect
	github.com/lightninglabs/loop/looprpc v1.0.0 // indirect
	github.com/lightninglabs/loop/swapserverrpc v1.0.11 // indirect
	github.com/lightninglabs/pool/auctioneerrpc v1.1.2 // indirect
	github.com/lightninglabs/pool/poolrpc v1.0.0 // indirect
	github.com/lightninglabs/taproot-assets v0.2.3 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.13 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/term v0.5.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/ncruces/go-strftime v0.1.9 // indirect
	github.com/onsi/gomega v1.26.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.2 // indirect
	github.com/opencontainers/runc v1.1.14 // indirect
	github.com/ory/dockertest/v3 v3.10.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.3.0 // indirect
	github.com/prometheus/common v0.39.0 // indirect
	github.com/prometheus/procfs v0.9.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	github.com/rogpeppe/fastuuid v1.2.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/sirupsen/logrus v1.9.2 // indirect
	github.com/soheilhy/cmux v0.1.5 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/syndtr/goleveldb v1.0.1-0.20210819022825-2ae1ddf74ef7 // indirect
	github.com/tmc/grpc-websocket-proxy v0.0.0-20220101234140-673ab2c3ae75 // indirect
	github.com/vulpemventures/fastsha256 v0.0.0-20160815193821-637e65642941 // indirect
	github.com/vulpemventures/go-elements v0.5.3 // indirect
	github.com/vulpemventures/go-secp256k1-zkp v1.1.6 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20180127040702-4e3ac2762d5f // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8 // indirect
	github.com/xiang90/probing v0.0.0-20221125231312-a49e3df8f510 // indirect
	gitlab.com/yawning/bsaes.git v0.0.0-20190805113838-0a714cd429ec // indirect
	go.etcd.io/etcd/api/v3 v3.5.7 // indirect
	go.etcd.io/etcd/client/v2 v2.305.7 // indirect
	go.etcd.io/etcd/pkg/v3 v3.5.7 // indirect
	go.etcd.io/etcd/raft/v3 v3.5.7 // indirect
	go.etcd.io/etcd/server/v3 v3.5.7 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.46.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.53.0 // indirect
	go.opentelemetry.io/otel v1.28.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.22.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.22.0 // indirect
	go.opentelemetry.io/otel/metric v1.28.0 // indirect
	go.opentelemetry.io/otel/sdk v1.22.0 // indirect
	go.opentelemetry.io/otel/trace v1.28.0 // indirect
	go.opentelemetry.io/proto/otlp v1.0.0 // indirect
	go.uber.org/atomic v1.10.0 // indirect
	go.uber.org/multierr v1.9.0 // indirect
	go.uber.org/zap v1.24.0 // indirect
	golang.org/x/mod v0.17.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	golang.org/x/tools v0.21.1-0.20240508182429-e35e4ccd0d2d // indirect
	google.golang.org/genproto v0.0.0-20231016165738-49dd2c1f3d0b // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240814211410-ddb44dafa142 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240814211410-ddb44dafa142 // indirect
	gopkg.in/errgo.v1 v1.0.1 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	modernc.org/gc/v3 v3.0.0-20240107210532-573471604cb6 // indirect
	modernc.org/libc v1.49.3 // indirect
	modernc.org/mathutil v1.6.0 // indirect
	modernc.org/memory v1.8.0 // indirect
	modernc.org/sqlite v1.29.10 // indirect
	modernc.org/strutil v1.2.0 // indirect
	modernc.org/token v1.1.0 // indirect
	nhooyr.io/websocket v1.8.7 // indirect
	sigs.k8s.io/yaml v1.3.0 // indirect
)

// This replace is for https://github.com/advisories/GHSA-25xm-hr59-7c27
replace github.com/ulikunitz/xz => github.com/ulikunitz/xz v0.5.11

// This replace is for
// https://deps.dev/advisory/OSV/GO-2021-0053?from=%2Fgo%2Fgithub.com%252Fgogo%252Fprotobuf%2Fv1.3.1
replace github.com/gogo/protobuf => github.com/gogo/protobuf v1.3.2

// We want to format raw bytes as hex instead of base64. The forked version
// allows us to specify that as an option.
replace google.golang.org/protobuf => github.com/lightninglabs/protobuf-go-hex-display v1.30.0-hex-display

// Speedloader
replace github.com/breez/breez => github.com/djkazic/breez v0.0.8

replace github.com/btcsuite/btcwallet => github.com/ZeusLN/btcwallet v1.7.2-m

replace github.com/btcsuite/btcwallet/walletdb => github.com/djkazic/btcwallet/walletdb v1.7.2

// Neutrino high latency perf
replace github.com/lightninglabs/neutrino => github.com/djkazic/neutrino v0.16.1-6

// Temporary replace until the next version of sqldb is taged.
replace github.com/lightningnetwork/lnd/sqldb => ./sqldb

// If you change this please also update .github/pull_request_template.md,
// docs/INSTALL.md and GO_IMAGE in lnrpc/gen_protos_docker.sh.
go 1.23.0

retract v0.0.2
