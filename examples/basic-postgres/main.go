package main

import (
	"fmt"
	"net/http"

	"github.com/ZenTenApp/bkind"
	"github.com/fiatjaf/eventstore/postgresql"
)

func main() {
	relay := bkind.NewRelay()

	db := postgresql.PostgresBackend{DatabaseURL: "postgresql://localhost:5432/tmp-khatru-relay"}
	if err := db.Init(); err != nil {
		panic(err)
	}

	relay.StoreEvent = append(relay.StoreEvent, db.SaveEvent)
	relay.QueryEvents = append(relay.QueryEvents, db.QueryEvents)
	relay.CountEvents = append(relay.CountEvents, db.CountEvents)
	relay.DeleteEvent = append(relay.DeleteEvent, db.DeleteEvent)
	relay.ReplaceEvent = append(relay.ReplaceEvent, db.ReplaceEvent)

	fmt.Println("running on :3334")
	http.ListenAndServe(":3334", relay)
}
