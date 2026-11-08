package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"

	_ "github.com/lib/pq"
)

func main() {
	dsn := flag.String("dsn", os.Getenv("DNSWATCHER_TEST_DSN"), "PostgreSQL DSN")
	flag.Parse()
	if *dsn == "" {
		log.Fatal("provide -dsn or DNSWATCHER_TEST_DSN")
	}

	ctx := context.Background()
	db, err := sql.Open("postgres", *dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		log.Fatal(err)
	}

	var tableExists bool
	if err := db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'domain_diagnostics'
		)`).Scan(&tableExists); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("domain_diagnostics exists: %t\n", tableExists)
	if !tableExists {
		return
	}

	rows, err := db.QueryContext(ctx, `
		SELECT id, run_id, domain_id, delegation_status,
			delegation_missing_in_primary, delegation_missing_in_parent
		FROM public.domain_diagnostics
		ORDER BY id DESC
		LIMIT 10`)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	for rows.Next() {
		var id, runID, domainID int
		var status string
		var missingPrimary, missingParent []byte
		if err := rows.Scan(&id, &runID, &domainID, &status, &missingPrimary, &missingParent); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("id=%d run_id=%d domain_id=%d status=%s missing_in_primary=%s missing_in_parent=%s\n",
			id, runID, domainID, status, missingPrimary, missingParent)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}
}
