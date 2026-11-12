package bkind

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fasthttp/websocket"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip11"
	"github.com/nbd-wtf/go-nostr/nip45/hyperloglog"
)

func NewRelay() *Relay {
	rl := &Relay{
		Logger: DefaultLogger(),

		Info: &nip11.RelayInformationDocument{
			Software:      "https://github.com/ZenTenApp/bkind",
			Version:       "n/a",
			SupportedNIPs: []any{1, 11, 40, 42, 70, 86},
		},

		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin:     func(r *http.Request) bool { return true },
		},

		clients:   make(map[*WebSocket][]listenerSpec, 100),
		listeners: make([]listener, 0, 100),

		serveMux: &http.ServeMux{},

		WriteWait:      10 * time.Second,
		PongWait:       60 * time.Second,
		PingPeriod:     30 * time.Second,
		MaxMessageSize: 512000,
	}

	rl.expirationManager = newExpirationManager(rl)

	return rl
}

type Relay struct {
	// setting this variable overwrites the hackish workaround we do to try to figure out our own base URL
	ServiceURL string

	// hooks that will be called at various times
	RejectEvent               []func(ctx context.Context, event *nostr.Event) (reject bool, msg string)
	OverwriteDeletionOutcome  []func(ctx context.Context, target *nostr.Event, deletion *nostr.Event) (acceptDeletion bool, msg string)
	StoreEvent                []func(ctx context.Context, event *nostr.Event) error
	ReplaceEvent              []func(ctx context.Context, event *nostr.Event) error
	DeleteEvent               []func(ctx context.Context, event *nostr.Event) error
	OnEventSaved              []func(ctx context.Context, event *nostr.Event)
	OnEphemeralEvent          []func(ctx context.Context, event *nostr.Event)
	RejectFilter              []func(ctx context.Context, filter nostr.Filter) (reject bool, msg string)
	RejectCountFilter         []func(ctx context.Context, filter nostr.Filter) (reject bool, msg string)
	OverwriteFilter           []func(ctx context.Context, filter *nostr.Filter)
	QueryEvents               []func(ctx context.Context, filter nostr.Filter) (chan *nostr.Event, error)
	CountEvents               []func(ctx context.Context, filter nostr.Filter) (int64, error)
	CountEventsHLL            []func(ctx context.Context, filter nostr.Filter, offset int) (int64, *hyperloglog.HyperLogLog, error)
	RejectConnection          []func(r *http.Request) bool
	OnConnect                 []func(ctx context.Context)
	OnDisconnect              []func(ctx context.Context)
	OverwriteRelayInformation []func(ctx context.Context, r *http.Request, info nip11.RelayInformationDocument) nip11.RelayInformationDocument
	OverwriteResponseEvent    []func(ctx context.Context, event *nostr.Event)
	PreventBroadcast          []func(ws *WebSocket, event *nostr.Event) bool

	// these are used when this relays acts as a router
	routes                []Route
	getSubRelayFromEvent  func(*nostr.Event) *Relay // used for handling EVENTs
	getSubRelayFromFilter func(nostr.Filter) *Relay // used for handling REQs

	// setting up handlers here will enable these methods
	ManagementAPI RelayManagementAPI

	// editing info will affect the NIP-11 responses
	Info *nip11.RelayInformationDocument

	// Default logger, as set by NewRelay, is a text slog logger writing to stderr at
	// level info, with every message prefixed "[bkind] ". Replace it to change the
	// level, the format or the destination; see NewLogger. A nil value falls back to
	// slog.Default(), so a hand-built Relay logs rather than panicking.
	Logger *slog.Logger

	// for establishing websockets
	upgrader websocket.Upgrader

	// keep a connection reference to all connected clients for Server.Shutdown
	// also used for keeping track of who is listening to what
	clients      map[*WebSocket][]listenerSpec
	listeners    []listener
	clientsMutex sync.Mutex

	// set this to true to support negentropy
	Negentropy bool

	// in case you call Server.Start
	Addr       string
	serveMux   *http.ServeMux
	httpServer *http.Server

	// websocket options
	WriteWait      time.Duration // Time allowed to write a message to the peer.
	PongWait       time.Duration // Time allowed to read the next pong message from the peer.
	PingPeriod     time.Duration // Send pings to peer with this period. Must be less than pongWait.
	MaxMessageSize int64         // Maximum message size allowed from peer.

	// NIP-40 expiration manager
	expirationManager      *expirationManager
	expirationManagerStart sync.Once
}

// ensureExpirationManager starts the NIP-40 sweeper once, the first time the relay
// is actually used. Doing it here instead of in NewRelay means the initial scan
// always sees a fully configured relay: stores and hooks are wired after the
// constructor returns.
func (rl *Relay) ensureExpirationManager() {
	rl.expirationManagerStart.Do(func() {
		go rl.expirationManager.start(context.Background())
	})
}

// SetExpirationInterval controls how often expired events are swept from the
// store. It is safe to call at any time, but a very short interval combined with a
// slow store will keep the sweep running continuously. The default is one hour.
func (rl *Relay) SetExpirationInterval(d time.Duration) {
	if d > 0 {
		rl.expirationManager.interval.Store(int64(d))
	}
}

func (rl *Relay) getBaseURL(r *http.Request) string {
	if rl.ServiceURL != "" {
		return rl.ServiceURL
	}

	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		if host == "localhost" {
			proto = "http"
		} else if strings.Contains(host, ":") {
			// has a port number
			proto = "http"
		} else if _, err := strconv.Atoi(strings.ReplaceAll(host, ".", "")); err == nil {
			// it's a naked IP
			proto = "http"
		} else {
			proto = "https"
		}
	}
	return proto + "://" + host
}
