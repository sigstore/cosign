package live

import (
	"context"

	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/ocsp/responder"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	"golang.org/x/crypto/ocsp"
	"golang.org/x/sync/semaphore"
	"google.golang.org/grpc"
)

type ocspGenerator interface {
	GenerateOCSP(ctx context.Context, in *rapb.GenerateOCSPRequest, opts ...grpc.CallOption) (*capb.OCSPResponse, error)
}

type Source struct {
	ra  ocspGenerator
	sem *semaphore.Weighted
}

func New(ra ocspGenerator, maxInflight int64) *Source {
	return &Source{
		ra:  ra,
		sem: semaphore.NewWeighted(maxInflight),
	}
}

func (s *Source) Response(ctx context.Context, req *ocsp.Request) (*responder.Response, error) {
	err := s.sem.Acquire(ctx, 1)
	if err != nil {
		return nil, err
	}
	defer s.sem.Release(1)

	resp, err := s.ra.GenerateOCSP(ctx, &rapb.GenerateOCSPRequest{
		Serial: core.SerialToString(req.SerialNumber),
	})
	if err != nil {
		return nil, err
	}
	parsed, err := ocsp.ParseResponse(resp.Response, nil)
	if err != nil {
		return nil, err
	}
	return &responder.Response{
		Raw:      resp.Response,
		Response: parsed,
	}, nil
}
