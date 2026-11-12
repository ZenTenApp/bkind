// A relay that only serves NIP-04 direct messages: Kind 4, plus the two utility
// kinds needed to make a message deletable (NIP-09) and to erase an identity
// (NIP-62). Everything is authenticated, everything expires, and a message is only
// ever readable by its author and its recipient.
//
// The policy set is data, not code, and it is keyed by kind: it comes from
// policies.DefaultConfig, optionally overridden by the JSON file named in
// BKIND_CONFIG (or BKIND_CONFIG_JSON), then by BKIND_KINDS, then by flags. See
// policies.Config for the fields.
//
// See docs/cookbook/dm-only-relay.md for the reasoning behind each policy,
// docs/cookbook/deploying.md for running it on a server, and
// docs/cookbook/docker.md for the container path.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ZenTenApp/bkind"
	"github.com/ZenTenApp/bkind/policies"
	badgerdb "github.com/dgraph-io/badger/v4"
	"github.com/fiatjaf/eventstore/badger"
	"github.com/fiatjaf/eventstore/slicestore"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip40"
)

// defaultSweepInterval is a process setting, not part of the policy set: the policy
// set itself lives in policies/default.json, embedded at build time, and everything
// about what the relay accepts is that document. The log level and format are
// process settings for the same reason — they say where this process talks, not
// what it serves.
const defaultSweepInterval = 5 * time.Minute

type config struct {
	addr          string
	serviceURL    string
	dbPath        string // empty means an in-memory store, for local testing
	sweepInterval time.Duration
	logLevel      slog.Level
	logFormat     string
	policies      policies.Config
	printConfig   bool // dump the resolved policy set and exit
}

// fatal reports the error and exits, the job log.Fatalf did while there was one
// process logger. It takes the logger it should use because a configuration error
// is reported before the configured logger exists.
func fatal(l *slog.Logger, msg string, args ...any) {
	l.Error(msg, args...)
	os.Exit(1)
}

func main() {
	// a logger that exists before the configuration does: a rejected BKIND_LOG_LEVEL
	// has to be reported by something, and it cannot be the logger that setting
	// describes
	bootstrap := bkind.DefaultLogger()

	cfg := parseConfig(bootstrap)

	logger, err := bkind.NewLogger(os.Stderr, cfg.logLevel, cfg.logFormat)
	if err != nil {
		fatal(bootstrap, "invalid log configuration", "err", err)
	}

	if cfg.printConfig {
		// the effective policy set, after the embedded document, the file, the
		// environment and the flags. It is the canonical document: feeding it back
		// through BKIND_CONFIG reproduces exactly this configuration, which is what
		// makes the file reviewable instead of aspirational. It goes to stdout
		// unprefixed, so the output stays a document and pipes into jq.
		document, err := cfg.policies.JSON()
		if err != nil {
			fatal(logger, "failed to render the configuration", "err", err)
		}
		fmt.Println(string(document))
		return
	}

	relay, closer, err := newRelay(cfg, logger)
	if err != nil {
		fatal(logger, "failed to start the relay", "err", err)
	}
	defer closer()

	server := &http.Server{
		Addr:              cfg.addr,
		Handler:           relay,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	retention := "no expiration policy"
	for _, rule := range cfg.policies.RulesByKind() {
		if slices.Contains(rule.RequiredTags, "expiration") {
			retention = fmt.Sprintf("mandatory NIP-40 expiration (max %s)", rule.MaxExpiration)
			break
		}
	}

	go func() {
		logger.Info("listening",
			"addr", cfg.addr,
			"url", cfg.serviceURL,
			"kinds", kindList(cfg.policies.KindNumbers()),
			"retention", retention,
		)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fatal(logger, "http server failed", "err", err)
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")

	// give in-flight requests a moment, then close the store: a websocket accept
	// that lands after the store is closed loses the event, one that lands after a
	// hard kill can lose it too
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown failed", "err", err)
	}
}

func parseConfig(bootstrap *slog.Logger) config {
	// the embedded document, then BKIND_CONFIG / BKIND_CONFIG_JSON, then
	// BKIND_KINDS, validated at every step
	policySet, err := policies.LoadConfig(os.LookupEnv)
	if err != nil {
		fatal(bootstrap, "invalid configuration", "err", err)
	}

	addr := envOr("BKIND_ADDR", ":3334")
	serviceURL := envOr("BKIND_URL", "")
	dbPath := envOr("BKIND_DB", "")
	sweepInterval := envOr("BKIND_SWEEP_INTERVAL", defaultSweepInterval.String())
	logLevel := envOr("BKIND_LOG_LEVEL", "info")
	logFormat := envOr("BKIND_LOG_FORMAT", bkind.LogFormatText)
	kinds := strings.Join(kindListInts(policySet.KindNumbers()), ",")
	nip11Name := policySet.Settings.NIP11.Name
	nip11Description := policySet.Settings.NIP11.Description
	printConfig := false

	flag.StringVar(&addr, "addr", addr, "address to listen on")
	flag.StringVar(&serviceURL, "url", serviceURL, "public URL of this relay (wss://...), used for NIP-42 and NIP-62")
	flag.StringVar(&dbPath, "db", dbPath, "path of the database directory (empty means in-memory, nothing is persisted)")
	flag.StringVar(&sweepInterval, "sweep-interval", sweepInterval, "how often expired events are deleted")
	flag.StringVar(&logLevel, "log-level", logLevel, "log level: debug, info, warn or error")
	flag.StringVar(&logFormat, "log-format", logFormat, "log format: text or json")
	flag.StringVar(&kinds, "kinds", kinds, "comma-separated kinds the relay serves; drops the rules of kinds it leaves out")
	flag.StringVar(&nip11Name, "name", nip11Name, "relay name in the NIP-11 document")
	flag.StringVar(&nip11Description, "description", nip11Description, "relay description in the NIP-11 document (empty derives one from -kinds)")
	flag.BoolVar(&printConfig, "print-config", false, "print the resolved policy set as JSON and exit")
	flag.Parse()

	serviceURL, err = normalizeServiceURL(serviceURL)
	if err != nil {
		fatal(bootstrap, "invalid -url", "err", err)
	}

	cfg := config{
		addr:        addr,
		serviceURL:  serviceURL,
		dbPath:      dbPath,
		policies:    policySet,
		printConfig: printConfig,
	}

	if cfg.sweepInterval, err = time.ParseDuration(sweepInterval); err != nil || cfg.sweepInterval <= 0 {
		fatal(bootstrap, "invalid -sweep-interval", "value", sweepInterval)
	}

	// the log settings are validated here, last: a setting that only exists to report
	// problems is reported by the bootstrap logger, not by the one it describes
	if cfg.logLevel, err = bkind.ParseLevel(logLevel); err != nil {
		fatal(bootstrap, "invalid log configuration", "err", fmt.Errorf("-log-level: %w", err))
	}
	if cfg.logFormat, err = bkind.ParseFormat(logFormat); err != nil {
		fatal(bootstrap, "invalid log configuration", "err", fmt.Errorf("-log-format: %w", err))
	}

	// flags win over the environment, so they are applied back onto the policy set
	parsedKinds, err := parseKinds(kinds)
	if err != nil {
		fatal(bootstrap, "invalid -kinds", "err", err)
	}
	cfg.policies.SetKinds(parsedKinds)
	cfg.policies.Settings.NIP11.Name = nip11Name
	cfg.policies.Settings.NIP11.Description = nip11Description

	// re-validate: a flag can break an invariant the environment respected
	if err := cfg.policies.Validate(); err != nil {
		fatal(bootstrap, "invalid configuration", "err", err)
	}

	return cfg
}

// newRelay wires the store and the policy set. It returns the relay plus a close
// function for the store.
func newRelay(cfg config, logger *slog.Logger) (*bkind.Relay, func(), error) {
	relay := bkind.NewRelay()
	// the configured logger replaces the default NewRelay installs, so the relay and
	// the process settings around it report at the same level in the same format
	relay.Logger = logger
	relay.ServiceURL = cfg.serviceURL
	// the frame limit is only a backstop, and it is advertised, so it comes from the
	// same field: the limits on a message are the per-kind policies
	// (policies.MaxContentLen and policies.MaxEventLen), which NAK instead of
	// closing the connection
	relay.MaxMessageSize = int64(cfg.policies.Settings.NIP11.MaxMessageLength)
	relay.SetExpirationInterval(cfg.sweepInterval)

	closer := func() {}
	store, err := openStore(cfg.dbPath, cfg.policies.Settings.NIP11.MaxLimit, logger)
	if err != nil {
		return nil, nil, err
	}
	closer = store.close

	relay.StoreEvent = append(relay.StoreEvent, store.saveEvent)
	relay.QueryEvents = append(relay.QueryEvents, dropExpired(store.queryEvents))
	relay.CountEvents = append(relay.CountEvents, store.countEvents)
	relay.DeleteEvent = append(relay.DeleteEvent, store.deleteEvent)

	// one call installs every gate that decides which kinds are served — writes,
	// filter overwrite, reads, COUNT, live delivery and NIP-11 — from the same
	// config, so they cannot disagree
	if err := cfg.policies.Wire(relay); err != nil {
		store.close()
		return nil, nil, err
	}

	return relay, closer, nil
}

// store is the subset of an eventstore backend this relay uses, so the main file
// does not care whether it is talking to badger or to memory.
type store struct {
	saveEvent   func(context.Context, *nostr.Event) error
	queryEvents func(context.Context, nostr.Filter) (chan *nostr.Event, error)
	countEvents func(context.Context, nostr.Filter) (int64, error)
	deleteEvent func(context.Context, *nostr.Event) error
	close       func()
}

func openStore(path string, maxLimit int, logger *slog.Logger) (store, error) {
	if path == "" {
		// a warning and not an info line: an unconfigured relay loses every event on
		// restart, which is fine for a test and wrong for anything else
		logger.Warn("no -db given: using an in-memory store, everything is lost on restart")
		ss := &slicestore.SliceStore{}
		if err := ss.Init(); err != nil {
			return store{}, err
		}
		return store{
			saveEvent:   ss.SaveEvent,
			queryEvents: ss.QueryEvents,
			countEvents: ss.CountEvents,
			deleteEvent: ss.DeleteEvent,
			close:       func() {},
		}, nil
	}

	db := &badger.BadgerBackend{
		Path: path,
		// the page size the NIP-11 document advertises: a query limit above this
		// would be truncated by the store after being promised by the document
		MaxLimit: maxLimit,
		// badger writes its own lines to stderr by default, outside the configured
		// level; routing them through the same handler is what makes
		// BKIND_LOG_LEVEL=warn (or debug, for its INFO chatter) mean something
		BadgerOptionsModifier: func(opts badgerdb.Options) badgerdb.Options {
			return opts.WithLogger(badgerLog{logger: logger})
		},
	}
	if err := db.Init(); err != nil {
		return store{}, fmt.Errorf("failed to open the database at %s: %w", path, err)
	}

	return store{
		saveEvent:   db.SaveEvent,
		queryEvents: db.QueryEvents,
		countEvents: db.CountEvents,
		deleteEvent: db.DeleteEvent,
		close:       func() { db.Close() },
	}, nil
}

// dropExpired hides events whose NIP-40 expiration has already passed but that the
// background sweep has not deleted yet, so the answer never depends on when the last
// sweep ran.
func dropExpired(
	query func(context.Context, nostr.Filter) (chan *nostr.Event, error),
) func(context.Context, nostr.Filter) (chan *nostr.Event, error) {
	return func(ctx context.Context, filter nostr.Filter) (chan *nostr.Event, error) {
		ch, err := query(ctx, filter)
		if err != nil || ch == nil {
			return ch, err
		}

		out := make(chan *nostr.Event)
		go func() {
			defer close(out)

			now := nostr.Now()
			for evt := range ch {
				if expiresAt := nip40.GetExpiration(evt.Tags); expiresAt != -1 && expiresAt <= now {
					continue
				}
				select {
				case out <- evt:
				case <-ctx.Done():
					return
				}
			}
		}()

		return out, nil
	}
}

// badgerLog is badger's four-method logger forwarded onto slog, so its records
// carry the relay's level and format. The messages are preformatted because that is
// the interface badger offers: it hands over a format string, not key-value pairs.
// Infof maps to info rather than to debug so that a relay which logged badger's
// startup lines before this change still logs them.
//
// The trailing newline is trimmed: badger's own logger prints line-wise, and a
// newline inside an slog message would be escaped and land in the middle of a
// journal entry.
type badgerLog struct{ logger *slog.Logger }

func (b badgerLog) Errorf(format string, args ...any) {
	b.logger.Error(badgerMessage(format, args...))
}

func (b badgerLog) Warningf(format string, args ...any) {
	b.logger.Warn(badgerMessage(format, args...))
}

func (b badgerLog) Infof(format string, args ...any) {
	b.logger.Info(badgerMessage(format, args...))
}

func (b badgerLog) Debugf(format string, args ...any) {
	b.logger.Debug(badgerMessage(format, args...))
}

func badgerMessage(format string, args ...any) string {
	return strings.TrimRight(fmt.Sprintf(format, args...), "\r\n")
}

// normalizeServiceURL checks the public URL this relay advertises and strips the
// trailing slash, so NIP-62 "relay" tags and NIP-42 "relay" tags compare equal.
func normalizeServiceURL(raw string) (string, error) {
	if raw == "" {
		return "", nil // fine for local testing; NIP-42 falls back to the request host
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%q: %w", raw, err)
	}
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return "", fmt.Errorf("%q: scheme must be ws or wss", raw)
	}
	if u.Host == "" {
		return "", fmt.Errorf("%q: missing host", raw)
	}

	return strings.TrimSuffix(raw, "/"), nil
}

// kindList renders a kind set for a log line.
func kindList(kinds []uint16) string {
	parts := make([]string, 0, len(kinds))
	for _, kind := range kinds {
		parts = append(parts, strconv.Itoa(int(kind)))
	}
	return strings.Join(parts, "/")
}

func kindListInts(kinds []uint16) []string {
	parts := make([]string, 0, len(kinds))
	for _, kind := range kinds {
		parts = append(parts, strconv.Itoa(int(kind)))
	}
	return parts
}

func parseKinds(raw string) ([]uint16, error) {
	kinds := make([]uint16, 0, 4)
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		kind, err := strconv.ParseUint(item, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("%q is not a kind number", item)
		}
		kinds = append(kinds, uint16(kind))
	}
	if len(kinds) == 0 {
		return nil, fmt.Errorf("no kinds given")
	}
	return kinds, nil
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}
