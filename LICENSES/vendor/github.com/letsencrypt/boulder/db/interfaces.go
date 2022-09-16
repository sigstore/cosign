package db

import (
	"context"
	"database/sql"
	"reflect"

	"github.com/go-gorp/gorp/v3"
)

// These interfaces exist to aid in mocking database operations for unit tests.
//
// By convention, any function that takes a OneSelector, Selector,
// Inserter, Execer, or SelectExecer as as an argument expects
// that a context has already been applied to the relevant DbMap or
// Transaction object.

// A OneSelector is anything that provides a `SelectOne` function.
type OneSelector interface {
	SelectOne(interface{}, string, ...interface{}) error
}

// A Selector is anything that provides a `Select` function.
type Selector interface {
	Select(interface{}, string, ...interface{}) ([]interface{}, error)
}

// A Inserter is anything that provides an `Insert` function
type Inserter interface {
	Insert(list ...interface{}) error
}

// A Execer is anything that provides an `Exec` function
type Execer interface {
	Exec(string, ...interface{}) (sql.Result, error)
}

// SelectExecer offers a subset of gorp.SqlExecutor's methods: Select and
// Exec.
type SelectExecer interface {
	Selector
	Execer
}

// DatabaseMap offers the full combination of OneSelector, Inserter,
// SelectExecer, and a Begin function for creating a Transaction.
type DatabaseMap interface {
	OneSelector
	Inserter
	SelectExecer
	Begin() (Transaction, error)
}

// Executor offers the full combination of OneSelector, Inserter, SelectExecer
// and adds a handful of other high level Gorp methods we use in Boulder.
type Executor interface {
	OneSelector
	Inserter
	SelectExecer
	Delete(...interface{}) (int64, error)
	Get(interface{}, ...interface{}) (interface{}, error)
	Update(...interface{}) (int64, error)
	Query(string, ...interface{}) (*sql.Rows, error)
}

// Transaction extends an Executor and adds Rollback, Commit, and WithContext.
type Transaction interface {
	Executor
	Rollback() error
	Commit() error
	WithContext(ctx context.Context) gorp.SqlExecutor
}

// MappedExecutor is anything that can map types to tables, and which can
// produce a SqlExecutor bound to a context.
type MappedExecutor interface {
	TableFor(reflect.Type, bool) (*gorp.TableMap, error)
	WithContext(ctx context.Context) gorp.SqlExecutor
}

// MappedSelector is anything that can execute various kinds of SQL statements
// against a table automatically determined from the parameterized type.
type MappedSelector[T any] interface {
	Query(ctx context.Context, clauses string, args ...interface{}) (Rows[T], error)
	QueryFrom(ctx context.Context, tablename string, clauses string, args ...interface{}) (Rows[T], error)
}

// Rows is anything which lets you iterate over the result rows of a SELECT
// query. It is similar to sql.Rows, but generic.
type Rows[T any] interface {
	Next() bool
	Get() (*T, error)
	Err() error
	Close() error
}
