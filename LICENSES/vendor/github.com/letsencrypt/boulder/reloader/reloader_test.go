package reloader

import (
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"testing"
	"time"
)

func noop([]byte) error {
	return nil
}

func testErrCb(t *testing.T) func(error) {
	return func(e error) {
		t.Error(e)
	}
}

func testFatalCb(t *testing.T) func(error) {
	return func(e error) {
		t.Fatal(e)
	}
}

func TestNoStat(t *testing.T) {
	filename := os.TempDir() + "/doesntexist.123456789"
	_, err := New(filename, noop, testErrCb(t))
	if err == nil {
		t.Fatalf("Expected New to return error when the file doesn't exist.")
	}
}

func TestNoRead(t *testing.T) {
	f, _ := ioutil.TempFile("", "test-no-read.txt")
	defer os.Remove(f.Name())
	oldReadFile := readFile
	readFile = func(string) ([]byte, error) {
		return nil, fmt.Errorf("read failed")
	}
	_, err := New(f.Name(), noop, testErrCb(t))
	if err == nil {
		t.Fatalf("Expected New to return error when permission denied.")
		readFile = oldReadFile
	}
	readFile = oldReadFile
}

func TestFirstError(t *testing.T) {
	f, _ := ioutil.TempFile("", "test-first-error.txt")
	defer os.Remove(f.Name())
	_, err := New(f.Name(), func([]byte) error {
		return fmt.Errorf("i die")
	}, testErrCb(t))
	if err == nil {
		t.Fatalf("Expected New to return error when the callback returned error the first time.")
	}
}

func TestFirstSuccess(t *testing.T) {
	f, _ := ioutil.TempFile("", "test-first-success.txt")
	defer os.Remove(f.Name())
	r, err := New(f.Name(), func([]byte) error {
		return nil
	}, testErrCb(t))
	if err != nil {
		t.Errorf("Expected New to succeed, got %s", err)
	}
	r.Stop()
}

// Override makeTicker for testing.
// Returns a channel on which to send artificial ticks, and a function to
// restore the default makeTicker.
func makeFakeMakeTicker() (chan<- time.Time, func()) {
	origMakeTicker := makeTicker
	fakeTickChan := make(chan time.Time)
	makeTicker = func() (func(), <-chan time.Time) {
		return func() {}, fakeTickChan
	}
	return fakeTickChan, func() {
		makeTicker = origMakeTicker
	}
}

func TestReload(t *testing.T) {
	// Mock out makeTicker
	fakeTick, restoreMakeTicker := makeFakeMakeTicker()
	defer restoreMakeTicker()

	f, _ := ioutil.TempFile("", "test-reload.txt")
	filename := f.Name()
	defer os.Remove(filename)

	_, _ = f.Write([]byte("first body"))
	_ = f.Close()

	var bodies []string
	reloads := make(chan []byte, 1)
	r, err := New(filename, func(b []byte) error {
		bodies = append(bodies, string(b))
		reloads <- b
		return nil
	}, testFatalCb(t))
	if err != nil {
		t.Fatalf("Expected New to succeed, got %s", err)
	}
	defer r.Stop()
	expected := []string{"first body"}
	if !reflect.DeepEqual(bodies, expected) {
		t.Errorf("Expected bodies = %#v, got %#v", expected, bodies)
	}
	fakeTick <- time.Now()
	<-reloads
	if !reflect.DeepEqual(bodies, expected) {
		t.Errorf("Expected bodies = %#v, got %#v", expected, bodies)
	}

	// Write to the file, expect a reload. Sleep a few milliseconds first so the
	// timestamps actually differ.
	time.Sleep(1 * time.Second)
	err = ioutil.WriteFile(filename, []byte("second body"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	fakeTick <- time.Now()
	<-reloads
	expected = []string{"first body", "second body"}
	if !reflect.DeepEqual(bodies, expected) {
		t.Errorf("Expected bodies = %#v, got %#v", expected, bodies)
	}

	// Send twice on this blocking channel to make sure we go through at least on
	// iteration of the reloader's loop.
	fakeTick <- time.Now()
	fakeTick <- time.Now()
	if !reflect.DeepEqual(bodies, expected) {
		t.Errorf("Expected bodies = %#v, got %#v", expected, bodies)
	}
}

func TestReloadFailure(t *testing.T) {
	// Mock out makeTicker
	fakeTick, restoreMakeTicker := makeFakeMakeTicker()

	f, _ := ioutil.TempFile("", "test-reload-failure.txt")
	filename := f.Name()
	defer func() {
		restoreMakeTicker()
		_ = os.Remove(filename)
	}()

	_, _ = f.Write([]byte("first body"))
	_ = f.Close()

	type res struct {
		b   []byte
		err error
	}

	reloads := make(chan res, 1)
	_, err := New(filename, func(b []byte) error {
		reloads <- res{b, nil}
		return nil
	}, func(e error) {
		reloads <- res{nil, e}
	})
	if err != nil {
		t.Fatalf("Expected New to succeed.")
	}
	<-reloads
	os.Remove(filename)
	fakeTick <- time.Now()
	select {
	case r := <-reloads:
		if r.err == nil {
			t.Errorf("Expected error trying to read missing file.")
		}
	case <-time.After(5 * time.Second):
		t.Errorf("timed out waiting for reload")
	}

	time.Sleep(1 * time.Second)
	// Create a file with no permissions
	oldReadFile := readFile
	readFile = func(string) ([]byte, error) {
		return nil, fmt.Errorf("permission denied")
	}

	fakeTick <- time.Now()
	select {
	case r := <-reloads:
		if r.err == nil {
			t.Errorf("Expected error trying to read file with no permissions.")
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for reload")
	}
	readFile = oldReadFile

	err = ioutil.WriteFile(filename, []byte("third body"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	fakeTick <- time.Now()
	select {
	case r := <-reloads:
		if r.err != nil {
			t.Errorf("Unexpected error: %s", err)
		}
		if string(r.b) != "third body" {
			t.Errorf("Expected 'third body' reading file after restoring it.")
		}
		return
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for successful reload")
	}
}
