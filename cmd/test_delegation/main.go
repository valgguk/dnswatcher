package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	_ "github.com/lib/pq"
	"github.com/miekg/dns"
	"github.com/niclabs/Observatorio/dbController"
	"github.com/niclabs/Observatorio/internal/analyzer"
	"github.com/niclabs/Observatorio/internal/collector"
)

func main() {
	domain := flag.String("domain", "nic.cl", "domain to inspect")
	dsn := flag.String("dsn", os.Getenv("DNSWATCHER_TEST_DSN"), "optional PostgreSQL DSN")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	parentNS, err := collector.NewTLDCollector(&dns.Client{Timeout: 5 * time.Second}).GetDelegatedNS(ctx, *domain)
	if err != nil {
		log.Fatalf("delegation lookup failed: %v", err)
	}
	fmt.Printf("Delegated NS for %s: %s\n", *domain, strings.Join(parentNS, ", "))

	primaryNS := strings.Fields(os.Getenv("DNSWATCHER_PRIMARY_NS"))
	diagnosis := analyzer.CompareNS(primaryNS, parentNS)
	fmt.Printf("Status=%s MissingInPrimary=%v MissingInParent=%v\n",
		diagnosis.Status, diagnosis.MissingInPrimary, diagnosis.MissingInParent)

	if *dsn == "" {
		return
	}
	db, err := sql.Open("postgres", *dsn)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		log.Fatalf("connect database: %v", err)
	}

	var domainID int
	err = db.QueryRowContext(ctx,
		"SELECT id FROM domain WHERE lower(trim(trailing '.' from name)) = lower(trim(trailing '.' from $1))",
		*domain,
	).Scan(&domainID)
	if err != nil {
		log.Fatalf("find domain %q: %v", *domain, err)
	}
	dbController.SaveDelegationDiagnosis(domainID, diagnosis, db)
	fmt.Printf("Saved diagnosis for domain_id=%d\n", domainID)
}
