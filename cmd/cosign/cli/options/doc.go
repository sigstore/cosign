// Package options contains the options used by the cosign cli.
//
// Aspirational flag patterns. Not all flags are used for all commands, but no
// other command may reuse the flag meaning listed here.
//
// Boolean types:
// `-a`, `--all`: All.
// `-d`, `--debug`: Show debug output. Example: each input and output is printed, each step is detailed.
// `-q`, `--quiet`: Show less output.
// `-F`, `--force`: Force an operation.
// `-v`, `--verbose`: Verbose output. Example: each step is detailed.
// `-K`, `--security-key`: Whether to use a hardware security key.
// `-R`, `--recursive`: Apply the operation recursively.

// Single-entry inputs
// `-o`, `--output`: The output file (payload).
// `-f`, `--output-format`: The format of the output.
// `-O`, `--output-file`: The file to redirect stdout to (task steps).
// `-k`, `--key`: Path to the private key file, KMS URI or Kubernetes Secret.
// '-s', `--signature`: Path to signature, or content or remote URL.
// `-c`, `--cert`: Path to the public certificate.
// `-S`, `--security-key-slot`: The slot of the hardware security key in use.
//
// Multi-entry inputs
// `-a`, `--annotations`: List of annotations.
//
//
package options
