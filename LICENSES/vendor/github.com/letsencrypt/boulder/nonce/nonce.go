// Package nonce implements a service for generating and redeeming nonces.
// To generate a nonce, it encrypts a monotonically increasing counter (latest)
// using an authenticated cipher. To redeem a nonce, it checks that the nonce
// decrypts to a valid integer between the earliest and latest counter values,
// and that it's not on the cross-off list. To avoid a constantly growing cross-off
// list, the nonce service periodically retires the oldest counter values by
// finding the lowest counter value in the cross-off list, deleting it, and setting
// "earliest" to its value. To make this efficient, the cross-off list is represented
// two ways: Once as a map, for quick lookup of a given value, and once as a heap,
// to quickly find the lowest value.
// The MaxUsed value determines how long a generated nonce can be used before it
// is forgotten. To calculate that period, divide the MaxUsed value by average
// redemption rate (valid POSTs per second).
package nonce

import (
	"container/heap"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	noncepb "github.com/letsencrypt/boulder/nonce/proto"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	defaultMaxUsed = 65536
	nonceLen       = 32
)

var errInvalidNonceLength = errors.New("invalid nonce length")

// NonceService generates, cancels, and tracks Nonces.
type NonceService struct {
	mu               sync.Mutex
	latest           int64
	earliest         int64
	used             map[int64]bool
	usedHeap         *int64Heap
	gcm              cipher.AEAD
	maxUsed          int
	prefix           string
	nonceCreates     prometheus.Counter
	nonceRedeems     *prometheus.CounterVec
	nonceHeapLatency prometheus.Histogram
}

type int64Heap []int64

func (h int64Heap) Len() int           { return len(h) }
func (h int64Heap) Less(i, j int) bool { return h[i] < h[j] }
func (h int64Heap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *int64Heap) Push(x interface{}) {
	*h = append(*h, x.(int64))
}

func (h *int64Heap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

// NewNonceService constructs a NonceService with defaults
func NewNonceService(stats prometheus.Registerer, maxUsed int, prefix string) (*NonceService, error) {
	// If a prefix is provided it must be four characters and valid
	// base64. The prefix is required to be base64url as RFC8555
	// section 6.5.1 requires that nonces use that encoding.
	// As base64 operates on three byte binary segments we require
	// the prefix to be three bytes (four characters) so that the
	// bytes preceding the prefix wouldn't impact the encoding.
	if prefix != "" {
		if len(prefix) != 4 {
			return nil, errors.New("nonce prefix must be 4 characters")
		}
		if _, err := base64.RawURLEncoding.DecodeString(prefix); err != nil {
			return nil, errors.New("nonce prefix must be valid base64url")
		}
	}

	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		panic("Failure in NewCipher: " + err.Error())
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		panic("Failure in NewGCM: " + err.Error())
	}

	if maxUsed <= 0 {
		maxUsed = defaultMaxUsed
	}

	nonceCreates := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "nonce_creates",
		Help: "A counter of nonces generated",
	})
	stats.MustRegister(nonceCreates)
	nonceRedeems := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "nonce_redeems",
		Help: "A counter of nonce validations labelled by result",
	}, []string{"result", "error"})
	stats.MustRegister(nonceRedeems)
	nonceHeapLatency := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "nonce_heap_latency",
		Help: "A histogram of latencies of heap pop operations",
	})
	stats.MustRegister(nonceHeapLatency)

	return &NonceService{
		earliest:         0,
		latest:           0,
		used:             make(map[int64]bool, maxUsed),
		usedHeap:         &int64Heap{},
		gcm:              gcm,
		maxUsed:          maxUsed,
		prefix:           prefix,
		nonceCreates:     nonceCreates,
		nonceRedeems:     nonceRedeems,
		nonceHeapLatency: nonceHeapLatency,
	}, nil
}

func (ns *NonceService) encrypt(counter int64) (string, error) {
	// Generate a nonce with upper 4 bytes zero
	nonce := make([]byte, 12)
	for i := 0; i < 4; i++ {
		nonce[i] = 0
	}
	if _, err := rand.Read(nonce[4:]); err != nil {
		return "", err
	}

	// Encode counter to plaintext
	pt := make([]byte, 8)
	ctr := big.NewInt(counter)
	pad := 8 - len(ctr.Bytes())
	copy(pt[pad:], ctr.Bytes())

	// Encrypt
	ret := make([]byte, nonceLen)
	ct := ns.gcm.Seal(nil, nonce, pt, nil)
	copy(ret, nonce[4:])
	copy(ret[8:], ct)

	return ns.prefix + base64.RawURLEncoding.EncodeToString(ret), nil
}

func (ns *NonceService) decrypt(nonce string) (int64, error) {
	body := nonce
	if ns.prefix != "" {
		var prefix string
		var err error
		prefix, body, err = splitNonce(nonce)
		if err != nil {
			return 0, err
		}
		if ns.prefix != prefix {
			return 0, fmt.Errorf("nonce contains invalid prefix: expected %q, got %q", ns.prefix, prefix)
		}
	}
	decoded, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return 0, err
	}
	if len(decoded) != nonceLen {
		return 0, errInvalidNonceLength
	}

	n := make([]byte, 12)
	for i := 0; i < 4; i++ {
		n[i] = 0
	}
	copy(n[4:], decoded[:8])

	pt, err := ns.gcm.Open(nil, n, decoded[8:], nil)
	if err != nil {
		return 0, err
	}

	ctr := big.NewInt(0)
	ctr.SetBytes(pt)
	return ctr.Int64(), nil
}

// Nonce provides a new Nonce.
func (ns *NonceService) Nonce() (string, error) {
	ns.mu.Lock()
	ns.latest++
	latest := ns.latest
	ns.mu.Unlock()
	defer ns.nonceCreates.Inc()
	return ns.encrypt(latest)
}

// Valid determines whether the provided Nonce string is valid, returning
// true if so.
func (ns *NonceService) Valid(nonce string) bool {
	c, err := ns.decrypt(nonce)
	if err != nil {
		ns.nonceRedeems.WithLabelValues("invalid", "decrypt").Inc()
		return false
	}

	ns.mu.Lock()
	defer ns.mu.Unlock()
	if c > ns.latest {
		ns.nonceRedeems.WithLabelValues("invalid", "too high").Inc()
		return false
	}

	if c <= ns.earliest {
		ns.nonceRedeems.WithLabelValues("invalid", "too low").Inc()
		return false
	}

	if ns.used[c] {
		ns.nonceRedeems.WithLabelValues("invalid", "already used").Inc()
		return false
	}

	ns.used[c] = true
	heap.Push(ns.usedHeap, c)
	if len(ns.used) > ns.maxUsed {
		s := time.Now()
		ns.earliest = heap.Pop(ns.usedHeap).(int64)
		ns.nonceHeapLatency.Observe(time.Since(s).Seconds())
		delete(ns.used, ns.earliest)
	}

	ns.nonceRedeems.WithLabelValues("valid", "").Inc()
	return true
}

func splitNonce(nonce string) (string, string, error) {
	if len(nonce) < 4 {
		return "", "", errInvalidNonceLength
	}
	return nonce[:4], nonce[4:], nil
}

// RemoteRedeem checks the nonce prefix and routes the Redeem RPC
// to the associated remote nonce service
func RemoteRedeem(ctx context.Context, noncePrefixMap map[string]noncepb.NonceServiceClient, nonce string) (bool, error) {
	prefix, _, err := splitNonce(nonce)
	if err != nil {
		return false, nil
	}
	nonceService, present := noncePrefixMap[prefix]
	if !present {
		return false, nil
	}
	resp, err := nonceService.Redeem(ctx, &noncepb.NonceMessage{Nonce: nonce})
	if err != nil {
		return false, err
	}
	return resp.Valid, nil
}
