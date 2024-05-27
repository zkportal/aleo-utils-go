package aleo_utils

import (
	_ "embed"
	"errors"
	"log"
	"reflect"
	"testing"
)

func TestAleoWrapper_NewAleoWrapper(t *testing.T) {
	wrapper, closeFn, err := NewWrapper()
	if err != nil {
		t.Fatalf("NewWrapper error = %v\n", err)
	}

	_, err = wrapper.NewSession()
	if err != nil {
		t.Fatalf("NewSession error = %v\n", err)
	}

	closeFn()

	_, err = wrapper.NewSession()
	if err == nil {
		t.Fatal("NewSession should return an error if the wrapper is closed")
	}
}

func TestAleoWrapper_NewPrivateKey(t *testing.T) {
	wrapper, closeFn, err := NewWrapper()
	if err != nil {
		t.Fatalf("NewWrapper error = %v\n", err)
	}
	defer closeFn()

	s, err := wrapper.NewSession()
	if err != nil {
		t.Fatal(err)
	}

	gotKey, gotAddress, err := s.NewPrivateKey()
	if err != nil {
		t.Fatalf("AleoWrapper.NewPrivateKey() error = %v\n", err)
		return
	}
	if gotKey == "" {
		t.Errorf("AleoWrapper.NewPrivateKey() gotKey = %v, want not empty\n", gotKey)
	}
	if gotAddress == "" {
		t.Errorf("AleoWrapper.NewPrivateKey() gotAddress = %v, want not empty\n", gotAddress)
	}

	s.Close()

	_, _, err = s.NewPrivateKey()
	if !errors.Is(err, ErrNoModule) {
		t.Fatal("session should return error on any function call after it was closed")
	}
}

func TestAleoWrapper_FormatMessage(t *testing.T) {
	wrapper, closeFn, err := NewWrapper()
	if err != nil {
		t.Fatalf("NewWrapper error = %v\n", err)
	}
	defer closeFn()

	s, err := wrapper.NewSession()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		message []byte
		chunks  int
		wantErr bool
	}{
		{
			name:    "empty message", // should be an array of 1 element - an array of 32 zeroes
			message: nil,
			chunks:  1,
			wantErr: false,
		},
		{
			name:    "message, just enough for 1 u128", // should be an array of 1 element - an array of 32 elements (in case of this test it's all zeroes again)
			message: make([]byte, 16),
			chunks:  1,
			wantErr: false,
		},
		{
			name:    "message", // should be an array of 1 element - an array of 32 elements (in case of this test it's all zeroes again)
			message: make([]byte, MESSAGE_FORMAT_BLOCK_SIZE),
			chunks:  1,
			wantErr: false,
		},
		{
			name:    "message is too long for target length",
			message: make([]byte, MESSAGE_FORMAT_BLOCK_SIZE*2),
			chunks:  1,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := s.FormatMessage(tt.message, tt.chunks)
			if (err != nil) != tt.wantErr {
				t.Errorf("AleoWrapper.FormatMessage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}

	s.Close()

	_, err = s.FormatMessage(nil, 1)
	if !errors.Is(err, ErrNoModule) {
		t.Fatal("session should return error on any function call after it was closed")
	}
}

func TestAleoWrapper_Sign(t *testing.T) {
	type args struct {
		key     string
		message []byte
	}

	wrapper, closeFn, err := NewWrapper()
	if err != nil {
		t.Fatalf("NewWrapper error = %v\n", err)
	}
	defer closeFn()

	s, err := wrapper.NewSession()
	if err != nil {
		t.Fatal(err)
	}

	key, _, err := s.NewPrivateKey()
	if err != nil {
		t.Fatalf("NewWrapper.NewPrivateKey() error = %v\n", err)
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "empty key",
			args: args{
				key:     "",
				message: []byte(""),
			},
			wantErr: true,
		},
		{
			name: "invalid key",
			args: args{
				key:     "12345678901234567890123456789012345678901234567890123456789",
				message: []byte(""),
			},
			wantErr: true,
		},
		{
			name: "empty message",
			args: args{
				key:     key,
				message: []byte(""),
			},
			wantErr: false,
		},
		{
			name: "message",
			args: args{
				key:     key,
				message: []byte("test"),
			},
			wantErr: false,
		},
		{
			name: "long message",
			args: args{
				key:     key,
				message: make([]byte, MESSAGE_FORMAT_BLOCK_SIZE*32),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := s.FormatMessage(tt.args.message, 32)
			if err != nil {
				t.Fatal(err)
			}
			gotSignature, err := s.Sign(tt.args.key, msg)
			if (err != nil) != tt.wantErr {
				t.Errorf("AleoWrapper.Sign() error = %v, wantErr %v\n", err, tt.wantErr)
				return
			}
			if err == nil && gotSignature == "" {
				t.Error("AleoWrapper.Sign() signature is empty, want not empty")
			}
		})
	}

	s.Close()

	_, err = s.Sign(key, nil)
	if !errors.Is(err, ErrNoModule) {
		t.Fatal("session should return error on any function call after it was closed")
	}
}

func TestAleoWrapper_RecoverMessage(t *testing.T) {
	wrapper, closeFn, err := NewWrapper()
	if err != nil {
		t.Fatalf("NewWrapper error = %v\n", err)
	}
	defer closeFn()

	s, err := wrapper.NewSession()
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		message []byte
	}
	tests := []struct {
		name        string
		args        args
		formatFirst bool
		wantErr     bool
	}{
		{
			name: "invalid - nil",
			args: args{
				message: nil,
			},
			formatFirst: false,
			wantErr:     true,
		},
		{
			name: "invalid - not a formatted message",
			args: args{
				message: make([]byte, 10),
			},
			formatFirst: false,
			wantErr:     true,
		},
		{
			name: "invalid - not a struct",
			args: args{
				message: []byte("123u128"),
			},
			formatFirst: false,
			wantErr:     true,
		},
		{
			name: "invalid - not a correct struct",
			args: args{
				message: []byte("{ a: 1u128 }"),
			},
			formatFirst: false,
			wantErr:     true,
		},
		{
			name: "valid",
			args: args{
				message: make([]byte, 16),
			},
			formatFirst: true,
			wantErr:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var formattedMessage, gotMessage []byte
			var err error
			if tt.formatFirst {
				formattedMessage, err = s.FormatMessage(tt.args.message, 32)
				if err != nil {
					t.Fatal(err)
					return
				}
				log.Println(string(formattedMessage))
			} else {
				formattedMessage = tt.args.message
				err = nil
			}

			gotMessage, err = s.RecoverMessage(formattedMessage)
			if (err != nil) != tt.wantErr {
				t.Errorf("AleoWrapper.RecoverMessage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			padding := make([]byte, 16*32*32-len(tt.args.message))
			wantMessage := append(tt.args.message, padding...)

			if !reflect.DeepEqual(gotMessage, wantMessage) {
				t.Errorf("AleoWrapper.RecoverMessage() = %v, want %v", gotMessage, wantMessage)
			}
		})
	}

	s.Close()

	_, err = s.RecoverMessage(nil)
	if !errors.Is(err, ErrNoModule) {
		t.Fatal("session should return error on any function call after it was closed")
	}
}
