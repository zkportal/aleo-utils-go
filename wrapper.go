// Package aleo_utils implements Aleo-compatible Schnorr signing.
package aleo_utils

import (
	"context"
	"crypto/rand"
	_ "embed"
	"errors"
	"fmt"
	"log"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

//go:embed aleo_utils.wasm
var wasmBytes []byte

var ErrNoRuntime = errors.New("no runtime, create new wrapper")

const (
	PRIVATE_KEY_SIZE          = 59
	ADDRESS_SIZE              = 63
	SIGNATURE_SIZE            = 216
	MESSAGE_FORMAT_BLOCK_SIZE = 16 * 32
	MAX_FORMAT_MESSAGE_CHUNKS = 32
)

// Wrapper is an interface for Aleo Wrapper session manager. Create an instance of a Wrapper using
// NewWrapper, then create a new Session to use the signing functionality.
type Wrapper interface {
	NewSession() (Session, error)
	Close()
}

func logString(ctx context.Context, module api.Module, ptr, byteCount uint32) {
	buf, ok := module.Memory().Read(ptr, byteCount)
	if ok {
		log.Println("Aleo Wrapper log:", string(buf))
	}
}

type aleoWrapper struct {
	Wrapper

	runtime       wazero.Runtime
	cmod          wazero.CompiledModule
	moduleConfig  wazero.ModuleConfig
	runtimeActive bool // a simple guard against using wrapper after it's runtime was destroyed
}

// NewWrapper creates Leo contract compatible Schnorr wrapper manager.
// The second argument is a cleanup function, which destroys wrapper runtime.
// aleoWrapper cannot be used after the cleanup function is called, and must be recreated using this function.
func NewWrapper() (wrapper Wrapper, closeFn func(), err error) {
	defer func() {
		if r := recover(); r != nil {
			// find out exactly what the error was and set err
			switch x := r.(type) {
			case string:
				err = errors.New(x)
			case error:
				err = x
			default:
				err = errors.New("unknown panic")
			}
			wrapper = nil
			closeFn = func() {}
		}
	}()

	ctx := context.Background()

	runtimeConfig := wazero.NewRuntimeConfigCompiler()
	runtime := wazero.NewRuntimeWithConfig(ctx, runtimeConfig)

	// export some wasi system functions
	wasi_snapshot_preview1.MustInstantiate(ctx, runtime)

	// export logging function to the guest
	hostBuilder := runtime.NewHostModuleBuilder("env")
	hostBuilder.NewFunctionBuilder().WithFunc(logString).Export("host_log_string").Instantiate(ctx)

	moduleConfig := wazero.NewModuleConfig().WithRandSource(rand.Reader)

	cmod, err := runtime.CompileModule(ctx, wasmBytes)
	if err != nil {
		return nil, nil, err
	}
	log.Println("compiled wrapper WASM module")

	wrapper = &aleoWrapper{
		runtime:       runtime,
		cmod:          cmod,
		moduleConfig:  moduleConfig,
		runtimeActive: true,
	}

	return wrapper, wrapper.Close, nil
}

// NewSession creates a new wrapper session, which can used to access signing logic. Sessions
// are not goroutine-safe.
func (s *aleoWrapper) NewSession() (Session, error) {
	if !s.runtimeActive || s.runtime == nil {
		s.runtime = nil
		return nil, ErrNoRuntime
	}

	mod, err := s.runtime.InstantiateModule(context.Background(), s.cmod, s.moduleConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate wrapper session: %w", err)
	}

	session := &aleoWrapperSession{
		mod:              mod,
		ctx:              context.Background(),
		newPrivateKey:    mod.ExportedFunction("new_private_key"),
		getAddress:       mod.ExportedFunction("get_address"),
		sign:             mod.ExportedFunction("sign"),
		allocate:         mod.ExportedFunction("alloc"),
		deallocate:       mod.ExportedFunction("dealloc"),
		hashMessage:      mod.ExportedFunction("hash_message"),
		hashMessageBytes: mod.ExportedFunction("hash_message_bytes"),
		formatMessage:    mod.ExportedFunction("format_message"),
		recoverMessage:   mod.ExportedFunction("formatted_message_to_bytes"),
	}

	return session, nil
}

// Closes WASM runtime
func (s *aleoWrapper) Close() {
	if s.runtime != nil {
		s.runtime.Close(context.Background())
	}
	s.runtimeActive = false
}
