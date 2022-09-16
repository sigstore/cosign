// Package reloader provides a method to load a file whenever it changes.
package reloader

import (
	"io/ioutil"
	"os"
	"time"
)

// Wrap time.Tick so we can override it in tests.
var makeTicker = func() (func(), <-chan time.Time) {
	t := time.NewTicker(1 * time.Second)
	return t.Stop, t.C
}

// Reloader represents an ongoing reloader task.
type Reloader struct {
	stopChan chan<- struct{}
}

// Stop stops an active reloader, release its resources.
func (r *Reloader) Stop() {
	r.stopChan <- struct{}{}
}

// A pointer we can override for testing.
var readFile = ioutil.ReadFile

// New loads the filename provided, and calls the callback.  It then spawns a
// goroutine to check for updates to that file, calling the callback again with
// any new contents. The first load, and the first call to callback, are run
// synchronously, so it is easy for the caller to check for errors and fail
// fast. New will return an error if it occurs on the first load. Otherwise all
// errors are sent to the callback.
func New(filename string, dataCallback func([]byte) error, errorCallback func(error)) (*Reloader, error) {
	if errorCallback == nil {
		errorCallback = func(e error) {}
	}
	fileInfo, err := os.Stat(filename)
	if err != nil {
		return nil, err
	}
	b, err := readFile(filename)
	if err != nil {
		return nil, err
	}
	stopChan := make(chan struct{})
	tickerStop, tickChan := makeTicker()
	loop := func() {
		for {
			select {
			case <-stopChan:
				tickerStop()
				return
			case <-tickChan:
				currentFileInfo, err := os.Stat(filename)
				if err != nil {
					errorCallback(err)
					continue
				}
				if !currentFileInfo.ModTime().After(fileInfo.ModTime()) {
					continue
				}
				b, err := readFile(filename)
				if err != nil {
					errorCallback(err)
					continue
				}
				fileInfo = currentFileInfo
				err = dataCallback(b)
				if err != nil {
					errorCallback(err)
				}
			}
		}
	}
	err = dataCallback(b)
	if err != nil {
		tickerStop()
		return nil, err
	}
	go loop()
	return &Reloader{stopChan}, nil
}
