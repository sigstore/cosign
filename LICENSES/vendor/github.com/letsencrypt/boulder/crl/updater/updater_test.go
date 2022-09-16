package updater

import (
	"testing"
	"time"

	"github.com/letsencrypt/boulder/test"
)

func TestGetWindowForShard(t *testing.T) {
	// Our test updater divides a 107-day window into 107 shards, resulting in a
	// shard width of 24 hours.
	tcu := crlUpdater{
		numShards:         107,
		lookbackPeriod:    7 * 24 * time.Hour,
		lookforwardPeriod: 100 * 24 * time.Hour,
	}
	zeroTime := time.Time{}

	// At just a moment past the 0 time, the zeroth shard should start at time 0,
	// and end exactly one day later.
	start, end := tcu.getShardBoundaries(zeroTime.Add(time.Minute), 0)
	test.Assert(t, start.IsZero(), "start time should be zero")
	test.AssertEquals(t, end, zeroTime.Add(24*time.Hour))

	// At the same moment, the 93rd shard should start 93 days later.
	start, end = tcu.getShardBoundaries(zeroTime.Add(time.Minute), 93)
	test.AssertEquals(t, start, zeroTime.Add(93*24*time.Hour))
	test.AssertEquals(t, end, zeroTime.Add(94*24*time.Hour))

	// If we jump 100 days into the future, now the 0th shard should start 107
	// days after the zero time.
	start, end = tcu.getShardBoundaries(zeroTime.Add(100*24*time.Hour+time.Minute), 0)
	test.AssertEquals(t, start, zeroTime.Add(107*24*time.Hour))
	test.AssertEquals(t, end, zeroTime.Add(108*24*time.Hour))

	// During day 100, the 93rd shard should still start at the same time (just
	// over 7 days ago), because we haven't fully left it behind yet. The 92nd
	// shard, however, should have jumped into the future.
	start, end = tcu.getShardBoundaries(zeroTime.Add(100*24*time.Hour+time.Minute), 93)
	test.AssertEquals(t, start, zeroTime.Add(93*24*time.Hour))
	test.AssertEquals(t, end, zeroTime.Add(94*24*time.Hour))
	start, end = tcu.getShardBoundaries(zeroTime.Add(100*24*time.Hour+time.Minute), 92)
	test.AssertEquals(t, start, zeroTime.Add(199*24*time.Hour))
	test.AssertEquals(t, end, zeroTime.Add(200*24*time.Hour))
}
