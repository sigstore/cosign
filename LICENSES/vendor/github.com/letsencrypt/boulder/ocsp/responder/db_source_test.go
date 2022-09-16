package responder

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	"github.com/go-gorp/gorp/v3"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/db"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/test"
	"golang.org/x/crypto/ocsp"
)

// To mock out WithContext, we need to be able to return objects that satisfy
// gorp.SqlExecutor. That's a pretty big interface, so we specify one no-op mock
// that we can embed everywhere we need to satisfy it.
// Note: mockSqlExecutor does *not* implement WithContext. The expectation is
// that structs that embed mockSqlExecutor will define their own WithContext
// that returns a reference to themselves. That makes it easy for those structs
// to override the specific methods they need to implement (e.g. SelectOne).
type mockSqlExecutor struct{}

func (mse mockSqlExecutor) Get(i interface{}, keys ...interface{}) (interface{}, error) {
	return nil, errors.New("unimplemented")
}
func (mse mockSqlExecutor) Insert(list ...interface{}) error {
	return errors.New("unimplemented")
}
func (mse mockSqlExecutor) Update(list ...interface{}) (int64, error) {
	return 0, errors.New("unimplemented")
}
func (mse mockSqlExecutor) Delete(list ...interface{}) (int64, error) {
	return 0, errors.New("unimplemented")
}
func (mse mockSqlExecutor) Exec(query string, args ...interface{}) (sql.Result, error) {
	return nil, errors.New("unimplemented")
}
func (mse mockSqlExecutor) Select(i interface{}, query string, args ...interface{}) ([]interface{}, error) {
	return nil, errors.New("unimplemented")
}
func (mse mockSqlExecutor) SelectInt(query string, args ...interface{}) (int64, error) {
	return 0, errors.New("unimplemented")
}
func (mse mockSqlExecutor) SelectNullInt(query string, args ...interface{}) (sql.NullInt64, error) {
	return sql.NullInt64{}, errors.New("unimplemented")
}
func (mse mockSqlExecutor) SelectFloat(query string, args ...interface{}) (float64, error) {
	return 0, errors.New("unimplemented")
}
func (mse mockSqlExecutor) SelectNullFloat(query string, args ...interface{}) (sql.NullFloat64, error) {
	return sql.NullFloat64{}, errors.New("unimplemented")
}
func (mse mockSqlExecutor) SelectStr(query string, args ...interface{}) (string, error) {
	return "", errors.New("unimplemented")
}
func (mse mockSqlExecutor) SelectNullStr(query string, args ...interface{}) (sql.NullString, error) {
	return sql.NullString{}, errors.New("unimplemented")
}
func (mse mockSqlExecutor) SelectOne(holder interface{}, query string, args ...interface{}) error {
	return errors.New("unimplemented")
}
func (mse mockSqlExecutor) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return nil, errors.New("unimplemented")
}
func (mse mockSqlExecutor) QueryRow(query string, args ...interface{}) *sql.Row {
	return nil
}

// echoSelector always returns the given certificateStatus.
type echoSelector struct {
	mockSqlExecutor
	status core.CertificateStatus
}

func (s echoSelector) WithContext(context.Context) gorp.SqlExecutor {
	return s
}

func (s echoSelector) SelectOne(output interface{}, _ string, _ ...interface{}) error {
	outputPtr, ok := output.(*core.CertificateStatus)
	if !ok {
		return fmt.Errorf("incorrect output type %T", output)
	}
	*outputPtr = s.status
	return nil
}

// errorSelector always returns the given error.
type errorSelector struct {
	mockSqlExecutor
	err error
}

func (s errorSelector) SelectOne(_ interface{}, _ string, _ ...interface{}) error {
	return s.err
}

func (s errorSelector) WithContext(context.Context) gorp.SqlExecutor {
	return s
}

func TestDbSource(t *testing.T) {
	reqBytes, err := ioutil.ReadFile("./testdata/ocsp.req")
	test.AssertNotError(t, err, "failed to read OCSP request")
	req, err := ocsp.ParseRequest(reqBytes)
	test.AssertNotError(t, err, "failed to parse OCSP request")

	respBytes, err := ioutil.ReadFile("./testdata/ocsp.resp")
	test.AssertNotError(t, err, "failed to read OCSP response")

	// Test for failure when the database lookup fails.
	dbErr := errors.New("something went wrong")
	src, err := NewDbSource(errorSelector{err: dbErr}, metrics.NoopRegisterer, blog.NewMock())
	test.AssertNotError(t, err, "failed to create dbSource")
	_, err = src.Response(context.Background(), req)
	test.AssertEquals(t, err, dbErr)

	// Test for graceful recovery when the database returns no results.
	dbErr = db.ErrDatabaseOp{
		Op:    "test",
		Table: "certificateStatus",
		Err:   sql.ErrNoRows,
	}
	src, err = NewDbSource(errorSelector{err: dbErr}, metrics.NoopRegisterer, blog.NewMock())
	test.AssertNotError(t, err, "failed to create dbSource")
	_, err = src.Response(context.Background(), req)
	test.AssertErrorIs(t, err, ErrNotFound)

	// Test for converting expired results into no results.
	status := core.CertificateStatus{
		IsExpired: true,
	}
	src, err = NewDbSource(echoSelector{status: status}, metrics.NoopRegisterer, blog.NewMock())
	test.AssertNotError(t, err, "failed to create dbSource")
	_, err = src.Response(context.Background(), req)
	test.AssertErrorIs(t, err, ErrNotFound)

	// Test for converting never-updated results into no results.
	status = core.CertificateStatus{
		IsExpired:       false,
		OCSPLastUpdated: time.Time{},
	}
	src, err = NewDbSource(echoSelector{status: status}, metrics.NoopRegisterer, blog.NewMock())
	test.AssertNotError(t, err, "failed to create dbSource")
	_, err = src.Response(context.Background(), req)
	test.AssertErrorIs(t, err, ErrNotFound)

	// Test for reporting parse errors.
	status = core.CertificateStatus{
		IsExpired:       false,
		OCSPLastUpdated: time.Now(),
		OCSPResponse:    respBytes[1:],
	}
	src, err = NewDbSource(echoSelector{status: status}, metrics.NoopRegisterer, blog.NewMock())
	test.AssertNotError(t, err, "failed to create dbSource")
	_, err = src.Response(context.Background(), req)
	test.AssertError(t, err, "expected failure")

	// Test the happy path.
	status = core.CertificateStatus{
		IsExpired:       false,
		OCSPLastUpdated: time.Now(),
		OCSPResponse:    respBytes,
	}
	src, err = NewDbSource(echoSelector{status: status}, metrics.NoopRegisterer, blog.NewMock())
	test.AssertNotError(t, err, "failed to create dbSource")
	_, err = src.Response(context.Background(), req)
	test.AssertNotError(t, err, "unexpected failure")
}
