package cosign

import (
	"os"
	"testing"
)

func Test_FileExists(t *testing.T) {
	tmpFile, err := os.CreateTemp(os.TempDir(), "cosign_test.txt")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		path    string
		exists  bool
		wantErr bool
	}{
		{"file exists", tmpFile.Name(), true, false},
		{"file does not exist", "testt.txt", false, false},
		{"other error e.g cannot access file", "\000x", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FileExists(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("FileExists() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.exists {
				t.Errorf("FileExists() = %v, want %v", got, tt.exists)
			}
		})
	}
}
