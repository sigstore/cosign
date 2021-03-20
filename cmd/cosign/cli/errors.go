package cli

// KeyParseError is an error returned when an incorrect set of key flags
// are parsed by the CLI
type KeyParseError struct{}

func (e *KeyParseError) Error() string {
	return "either local key path (-key) or KMS path (-kms) must be provided, not both"
}
