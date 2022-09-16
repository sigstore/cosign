package grpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	berrors "github.com/letsencrypt/boulder/errors"
)

// wrapError wraps the internal error types we use for transport across the gRPC
// layer and appends an appropriate errortype to the gRPC trailer via the provided
// context. errors.BoulderError error types are encoded using the grpc/metadata
// in the context.Context for the RPC which is considered to be the 'proper'
// method of encoding custom error types (grpc/grpc#4543 and grpc/grpc-go#478)
func wrapError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	var berr *berrors.BoulderError
	if errors.As(err, &berr) {
		pairs := []string{
			"errortype", strconv.Itoa(int(berr.Type)),
		}

		// If there are suberrors then extend the metadata pairs to include the JSON
		// marshaling of the suberrors. Errors in marshaling are not ignored and
		// instead result in a return of an explicit InternalServerError and not
		// a wrapped error missing suberrors.
		if len(berr.SubErrors) > 0 {
			jsonSubErrs, err := json.Marshal(berr.SubErrors)
			if err != nil {
				return berrors.InternalServerError(
					"error marshaling json SubErrors, orig error %q",
					err)
			}
			pairs = append(pairs, "suberrors")
			pairs = append(pairs, string(jsonSubErrs))
		}

		// Ignoring the error return here is safe because if setting the metadata
		// fails, we'll still return an error, but it will be interpreted on the
		// other side as an InternalServerError instead of a more specific one.
		_ = grpc.SetTrailer(ctx, metadata.Pairs(pairs...))
		return status.Errorf(codes.Unknown, err.Error())
	}
	return status.Errorf(codes.Unknown, err.Error())
}

// unwrapError unwraps errors returned from gRPC client calls which were wrapped
// with wrapError to their proper internal error type. If the provided metadata
// object has an "errortype" field, that will be used to set the type of the
// error.
func unwrapError(err error, md metadata.MD) error {
	if err == nil {
		return nil
	}

	unwrappedErr := status.Convert(err).Message()

	errTypeStrs, ok := md["errortype"]
	if !ok {
		return err
	}
	if len(errTypeStrs) != 1 {
		return berrors.InternalServerError(
			"multiple errorType metadata, wrapped error %q",
			unwrappedErr,
		)
	}

	errType, decErr := strconv.Atoi(errTypeStrs[0])
	if decErr != nil {
		return berrors.InternalServerError(
			"failed to decode error type, decoding error %q, wrapped error %q",
			decErr,
			unwrappedErr,
		)
	}
	outErr := berrors.New(berrors.ErrorType(errType), unwrappedErr)

	subErrsJSON, ok := md["suberrors"]
	if !ok {
		return outErr
	}
	if len(subErrsJSON) != 1 {
		return berrors.InternalServerError(
			"multiple suberrors metadata, wrapped error %q",
			unwrappedErr,
		)
	}

	var suberrs []berrors.SubBoulderError
	err2 := json.Unmarshal([]byte(subErrsJSON[0]), &suberrs)
	if err2 != nil {
		return berrors.InternalServerError(
			"error unmarshaling suberrs JSON %q, wrapped error %q",
			subErrsJSON[0],
			unwrappedErr,
		)
	}

	var berr *berrors.BoulderError
	if errors.As(outErr, &berr) {
		outErr = berr.WithSubErrors(suberrs)
	} else {
		return fmt.Errorf(
			"expected type of outErr to be %T got %T: %q",
			berr, outErr,
			outErr.Error(),
		)
	}
	return outErr
}
