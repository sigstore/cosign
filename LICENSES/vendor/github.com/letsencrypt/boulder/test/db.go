package test

import (
	"database/sql"
	"fmt"
	"io"
	"testing"
)

var (
	_ CleanUpDB = &sql.DB{}
)

// CleanUpDB is an interface with only what is needed to delete all
// rows in all tables in a database plus close the database
// connection. It is satisfied by *sql.DB.
type CleanUpDB interface {
	Begin() (*sql.Tx, error)
	Exec(query string, args ...interface{}) (sql.Result, error)
	Query(query string, args ...interface{}) (*sql.Rows, error)

	io.Closer
}

// ResetSATestDatabase deletes all rows in all tables in the SA DB.
// If fails the tests if that errors and returns a clean up function
// that will delete all rows again and close the database.
// "Tables available" means all tables that can be seen in the MariaDB
// configuration by the database user except for ones that are
// configuration only like goose_db_version (for migrations) or
// the ones describing the internal configuration of the server. To be
// used only in test code.
func ResetSATestDatabase(t testing.TB) func() {
	return resetTestDatabase(t, "sa")
}

func resetTestDatabase(t testing.TB, dbType string) func() {
	db, err := sql.Open("mysql", fmt.Sprintf("test_setup@tcp(boulder-mysql:3306)/boulder_%s_test", dbType))
	if err != nil {
		t.Fatalf("Couldn't create db: %s", err)
	}
	err = deleteEverythingInAllTables(db)
	if err != nil {
		t.Fatalf("Failed to delete everything: %s", err)
	}
	return func() {
		err := deleteEverythingInAllTables(db)
		if err != nil {
			t.Fatalf("Failed to truncate tables after the test: %s", err)
		}
		_ = db.Close()
	}
}

// clearEverythingInAllTables deletes all rows in the tables
// available to the CleanUpDB passed in and resets the autoincrement
// counters. See allTableNamesInDB for what is meant by "all tables
// available". To be used only in test code.
func deleteEverythingInAllTables(db CleanUpDB) error {
	ts, err := allTableNamesInDB(db)
	if err != nil {
		return err
	}
	for _, tn := range ts {
		// We do this in a transaction to make sure that the foreign
		// key checks remain disabled even if the db object chooses
		// another connection to make the deletion on. Note that
		// `alter table` statements will silently cause transactions
		// to commit, so we do them outside of the transaction.
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("unable to start transaction to delete all rows from table %#v: %s", tn, err)
		}
		_, err = tx.Exec("set FOREIGN_KEY_CHECKS = 0")
		if err != nil {
			return fmt.Errorf("unable to disable FOREIGN_KEY_CHECKS to delete all rows from table %#v: %s", tn, err)
		}
		// 1 = 1 here prevents the MariaDB i_am_a_dummy setting from
		// rejecting the DELETE for not having a WHERE clause.

		_, err = tx.Exec("delete from `" + tn + "` where 1 = 1")
		if err != nil {
			return fmt.Errorf("unable to delete all rows from table %#v: %s", tn, err)
		}
		_, err = tx.Exec("set FOREIGN_KEY_CHECKS = 1")
		if err != nil {
			return fmt.Errorf("unable to re-enable FOREIGN_KEY_CHECKS to delete all rows from table %#v: %s", tn, err)
		}
		err = tx.Commit()
		if err != nil {
			return fmt.Errorf("unable to commit transaction to delete all rows from table %#v: %s", tn, err)
		}

		_, err = db.Exec("alter table `" + tn + "` AUTO_INCREMENT = 1")
		if err != nil {
			return fmt.Errorf("unable to reset autoincrement on table %#v: %s", tn, err)
		}
	}
	return err
}

// allTableNamesInDB returns the names of the tables available to the
// CleanUpDB passed in. "Tables available" means all tables that can
// be seen in the MariaDB configuration by the database user except
// for ones that are configuration only like goose_db_version (for
// migrations) or the ones describing the internal configuration of
// the server. To be used only in test code.
func allTableNamesInDB(db CleanUpDB) ([]string, error) {
	r, err := db.Query("select table_name from information_schema.tables t where t.table_schema = DATABASE() and t.table_name != 'goose_db_version';")
	if err != nil {
		return nil, err
	}
	var ts []string
	for r.Next() {
		tableName := ""
		err = r.Scan(&tableName)
		if err != nil {
			return nil, err
		}
		ts = append(ts, tableName)
	}
	return ts, r.Err()
}
