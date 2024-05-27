# Aleo utility wrapper for Golang

This is a helper library for Golang, it provides selected functions (see below) from the Aleo [library](https://github.com/AleoHQ/snarkVM) with correct encoding.

This library is using WebAssembly under the hood, which is compiled to `wasm32-wasi`. It is using the library based on https://github.com/AleoHQ/snarkVM `console` crate. The WebAssembly program is embed into the binary using `go:embed`.

## Building WASM module before using

1. Install Cargo and Rust 1.76.0
2. Build WASM library by running `./build.sh`
3. (optional) optimize wasm by running this command (requires `wasm-snip`, `wasm-opt`): `./optimize_wasm.sh`

## Usage

Available functions:

| Function | Arguments | Return type | Description |
| --- | --- | --- | --- |
| `NewPrivateKey` | | `(key string, address string, err error)` | Generates a new Aleo private key, returns it with it's public address |
| `FormatMessage` | <ul><li>`message []byte` - buffer to format for Leo</li><li>`targetChunks int` - number of desired chunks in the resulting struct, where every chunk is a struct of 32 `u128`s. Allowed: 1-32.</li></ul> | `(formattedMessage []byte, err error)` | Formats a byte buffer as a nested struct with the specified number of 512-byte chunks. The result is returned as bytes of the string representation of the struct. |
| `RecoverMessage` | `formattedMessage []byte` | `(message []byte, err error)` | Recovers original byte buffer from a formatted message created with `FormatMessage` |
| `HashMessageToString` | `message []byte` | `(hash string, err error)` | Hashes a message using Poseidon8 Leo function, and returns a string representation of a resulting `u128`, meaning it can be used as a literal in a Leo program, e.g. "12345u128" |
| `HashMessage` | `message []byte` | `(hash []byte, err error)` | Hashes a message using Poseidon8 Leo function, and returns a byte representation of a resulting `u128`, meaning it has to be converted to Leo `u128` type before it can be used as a literal. Use this function if you want to sign a message that is too big and verify it in a contract. If you don't plan to verify it in contract, `HashMessageToString` will work as well |
| `Sign` | <ul><li>`key string` - private key for signing, e.g. from `NewPrivateKey`</li><li>`message []byte` - a message to sign, must be string or byte representation of Leo `u128` value</li></ul> | `(signature string, err error)` | Signs data using private key, returns the signature as a string representation of Leo `signature` value |

Create a wrapper using `NewWrapper`. It will return a wrapper manager, runtime close function, and optionally an error. Then use
wrapper manager to create a new session.

```go
import (
  aleo "github.com/zkportal/aleo-utils-go"
  "context"
)

func main() {
  wrapper, closeFn, err := aleo.NewWrapper(context.Background())
  if err != nil {
    panic(err)
  }

  session, err := wrapper.NewSession()
  if err != nil {
    panic(err)
  }

  // session provides access to the functionality
  session.NewPrivateKey()

  // calling closeFn will destroy WASM runtime,
  // all wrapper functions will panic if called after the runtime was closed
  defer closeFn()
}
```

After the wrapper session is instantiated, you can use the wrapper functions.

For more examples check out: https://github.com/zkportal/aleo-utils-go/blob/main/example_test.go

## Using in SGX

Since this package uses WASM, an SGX enclave needs to have the executable heap enabled in the config. Heap size may also need to be increased.
