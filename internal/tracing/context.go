package tracing

import "context"

// ActiveCtx holds the context with the active span so that HTTP requests
// created without context (e.g. inside sigstore-go) can inherit trace context.
var ActiveCtx context.Context
