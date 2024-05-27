package aleo_utils

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/tetratelabs/wazero/api"
)

var (
	ErrNoModule = errors.New("session module is closed")
)

// Provides access to wrapper functionality. A session is not goroutine safe so
// you need to create a new one for every goroutine
type Session interface {
	NewPrivateKey() (key string, address string, err error)
	FormatMessage(message []byte, targetChunks int) (formattedMessage []byte, err error)
	RecoverMessage(formattedMessage []byte) (message []byte, err error)
	HashMessageToString(message []byte) (hash string, err error)
	HashMessage(message []byte) (hash []byte, err error)
	Sign(key string, message []byte) (signature string, err error)

	Close()
}

// internal implementation of the Session interface
type aleoWrapperSession struct {
	Session

	// unique wasm module for this session
	mod api.Module
	ctx context.Context

	newPrivateKey    api.Function
	getAddress       api.Function
	sign             api.Function
	allocate         api.Function
	deallocate       api.Function
	hashMessage      api.Function
	hashMessageBytes api.Function
	formatMessage    api.Function
	recoverMessage   api.Function
}

func (session *aleoWrapperSession) Close() {
	if session.mod != nil {
		session.mod.Close(context.Background())
	}
}

// NewPrivateKey generates a new Aleo private key, returns it's string representation and the address derived from that private key.
func (s *aleoWrapperSession) NewPrivateKey() (key string, address string, err error) {
	if s.mod == nil || s.mod.IsClosed() {
		return "", "", ErrNoModule
	}

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
			key = ""
			address = ""
		}
	}()

	// generate new private key
	var privKeyPtr []uint64
	privKeyPtr, err = s.newPrivateKey.Call(s.ctx)
	if err != nil {
		log.Println("new_private_key error:", err)
		return
	}
	if privKeyPtr[0] == 0 {
		return "", "", errors.New("failed to create new private key")
	}

	// read wasm memory at pointer for the private key string
	privKey, ok := s.mod.Memory().Read(uint32(privKeyPtr[0]), PRIVATE_KEY_SIZE)
	if !ok {
		return "", "", errors.New("failed to create new private key")
	}
	defer s.deallocate.Call(s.ctx, privKeyPtr[0], PRIVATE_KEY_SIZE)

	// since memory read returns a slice of wasm memory buffer, it needs to be copied
	// to avoid our returned slice being wiped when wasm memory is wiped.
	// explicit copy is not needed since we create a string, which copies the slice instead of referencing it
	key = string(privKey)

	// get public address from the private key, reuse the returned value from private key generation
	addressPtr, err := s.getAddress.Call(s.ctx, privKeyPtr[0], PRIVATE_KEY_SIZE)
	if err != nil {
		log.Println("get_address error:", err)
		return "", "", errors.New("failed to get address from the generated private key")
	}
	if addressPtr[0] == 0 {
		return "", "", errors.New("internal error when getting address from the generated private key")
	}

	// read address from wasm memory
	addr, ok := s.mod.Memory().Read(uint32(addressPtr[0]), ADDRESS_SIZE)
	if !ok {
		return "", "", errors.New("failed to convert generated private key to address")
	}
	defer s.deallocate.Call(s.ctx, addressPtr[0], ADDRESS_SIZE)

	// since memory read returns a slice of wasm memory buffer, it needs to be copied
	// to avoid our returned slice being wiped when wasm memory is wiped.
	// explicit copy is not needed since we create a string, which copies the slice instead of referencing it
	address = string(addr)

	return
}

// FormatMessage formats a byte array as a Leo struct of up to 32 structs of 32 u128 numbers. The returned value
// is a string representation of that struct, as bytes.
func (s *aleoWrapperSession) FormatMessage(message []byte, targetChunks int) (formattedMessage []byte, err error) {
	if s.mod == nil || s.mod.IsClosed() {
		return nil, ErrNoModule
	}

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
			formattedMessage = nil
		}
	}()

	if targetChunks < 1 || targetChunks > MAX_FORMAT_MESSAGE_CHUNKS {
		return nil, errors.New("target number of chunks must be between 1 and 32")
	}

	if len(message) > targetChunks*MESSAGE_FORMAT_BLOCK_SIZE {
		return nil, fmt.Errorf("target formatted message length must be at most %d (%d chunks)", targetChunks*MESSAGE_FORMAT_BLOCK_SIZE, targetChunks)
	}

	msgLen := uint64(len(message))

	// allocate memory for the message to pass to the formatting function
	messagePtr, err := s.allocate.Call(s.ctx, msgLen)
	if err != nil {
		log.Println("message allocate error:", err)
		return nil, errors.New("failed to allocate memory for message")
	}

	// don't forget to dealloc memory
	defer s.deallocate.Call(s.ctx, messagePtr[0], msgLen)

	// write message to wasm memory
	ok := s.mod.Memory().Write(uint32(messagePtr[0]), message)
	if !ok {
		return nil, errors.New("failed to write message to memory for formatting")
	}

	// call format message with the pointer to the message
	formatResult, err := s.formatMessage.Call(s.ctx, messagePtr[0], msgLen, uint64(targetChunks))
	if err != nil {
		log.Println("string format error:", err)
		return nil, errors.New("failed to format message")
	}
	if formatResult[0] == 0 {
		return nil, errors.New("invalid message")
	}

	// take the first (big endian) 32 bits as string size
	strLen := uint32(formatResult[0] >> 32)

	// casting uint64 to uint32 discards the first (big endian) 32 bits so we're left with the last 32 bits of the result pointer
	strPtr := uint32(formatResult[0])

	// now we know how many bytes to read to get the string representation of a field
	buf, ok := s.mod.Memory().Read(strPtr, strLen)
	if !ok {
		return nil, errors.New("failed to convert message to a field")
	}
	defer s.deallocate.Call(s.ctx, uint64(strPtr), uint64(strLen))

	// since memory read returns a slice of wasm memory buffer, it needs to be copied
	// to avoid our returned slice being wiped when wasm memory is wiped
	formattedMessage = make([]byte, len(buf))
	copy(formattedMessage, buf)

	adjusted := strings.ReplaceAll(string(formattedMessage), "\n", "")

	return []byte(adjusted), nil
}

// Recovers the original byte message from a formatted message string that was created using FormatMessage
func (s *aleoWrapperSession) RecoverMessage(formattedMessage []byte) (message []byte, err error) {
	if s.mod == nil || s.mod.IsClosed() {
		return nil, ErrNoModule
	}

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
			message = nil
		}
	}()

	formattedMsgLen := uint64(len(formattedMessage))

	// allocate memory for the message to pass to the recovery function
	formattedMessagePtr, err := s.allocate.Call(s.ctx, formattedMsgLen)
	if err != nil {
		log.Println("message allocate error:", err)
		return nil, errors.New("failed to allocate memory for message")
	}

	// don't forget to dealloc memory
	defer s.deallocate.Call(s.ctx, formattedMessagePtr[0], formattedMsgLen)

	// write message to wasm memory
	ok := s.mod.Memory().Write(uint32(formattedMessagePtr[0]), formattedMessage)
	if !ok {
		return nil, errors.New("failed to write message to memory for recovering")
	}

	// call recover message with the pointer to the message
	recoverResult, err := s.recoverMessage.Call(s.ctx, formattedMessagePtr[0], formattedMsgLen)
	if err != nil {
		log.Println("string recover error:", err)
		return nil, errors.New("failed to recover message")
	}
	if recoverResult[0] == 0 {
		return nil, errors.New("invalid message")
	}

	// take the first (big endian) 32 bits as string size
	bufLen := uint32(recoverResult[0] >> 32)

	// casting uint64 to uint32 discards the first (big endian) 32 bits so we're left with the last 32 bits of the result pointer
	bugPtr := uint32(recoverResult[0])

	// now we know how many bytes to read to get the string representation of a field
	buf, ok := s.mod.Memory().Read(bugPtr, bufLen)
	if !ok {
		return nil, errors.New("failed to convert message to a field")
	}
	defer s.deallocate.Call(s.ctx, uint64(bugPtr), uint64(bufLen))

	// since memory read returns a slice of wasm memory buffer, it needs to be copied
	// to avoid our returned slice being wiped when wasm memory is wiped
	message = make([]byte, len(buf))
	copy(message, buf)

	return
}

// HashMessageToString hashes a message using Poseidon8 Leo function, and returns a string
// representation of a resulting U128.
//
// Use this function if you need a hash as a literal, for example for using it in a contract.
func (s *aleoWrapperSession) HashMessageToString(message []byte) (hash string, err error) {
	if s.mod == nil || s.mod.IsClosed() {
		return "", ErrNoModule
	}

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
			hash = ""
		}
	}()

	msgLen := uint64(len(message))

	// allocate memory for the message to pass to the signing function
	messagePtr, err := s.allocate.Call(s.ctx, msgLen)
	if err != nil {
		log.Println("message allocate error:", err)
		return "", errors.New("failed to allocate memory for message")
	}

	// don't forget to dealloc memory
	defer s.deallocate.Call(s.ctx, messagePtr[0], msgLen)

	// write message to wasm memory
	ok := s.mod.Memory().Write(uint32(messagePtr[0]), message)
	if !ok {
		return "", errors.New("failed to write message to memory for hashing")
	}

	// call the hash function and pass the pointer to the message
	hashResult, err := s.hashMessage.Call(s.ctx, messagePtr[0], msgLen)
	if err != nil {
		log.Println("hash message error:", err)
		return "", errors.New("failed to hash message to a string representation")
	}
	if hashResult[0] == 0 {
		return "", errors.New("invalid message")
	}

	// take the first (big endian) 32 bits as string size
	hashLen := uint32(hashResult[0] >> 32)

	// casting uint64 to uint32 discards the first (big endian) 32 bits so we're left with the last 32 bits of the result pointer
	hashPtr := uint32(hashResult[0])

	// now we know how many bytes to read to get the string representation of a field
	hashBytes, ok := s.mod.Memory().Read(hashPtr, hashLen)
	if !ok {
		return "", errors.New("failed to convert message to a field")
	}
	defer s.deallocate.Call(s.ctx, uint64(hashPtr), uint64(hashLen))

	// since memory read returns a slice of wasm memory buffer, it needs to be copied
	// to avoid our returned slice being wiped when wasm memory is wiped.
	// explicit copy is not needed since we create a string, which copies the slice instead of referencing it
	hash = string(hashBytes)

	return
}

// HashMessage hashes a message using Poseidon8 Leo function, and returns a little-endian
// byte representation of a resulting U128.
func (s *aleoWrapperSession) HashMessage(message []byte) (hash []byte, err error) {
	if s.mod == nil || s.mod.IsClosed() {
		return nil, ErrNoModule
	}

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
			hash = nil
		}
	}()

	msgLen := uint64(len(message))

	// allocate memory for the message to pass to the signing function
	messagePtr, err := s.allocate.Call(s.ctx, msgLen)
	if err != nil {
		log.Println("message allocate error:", err)
		return nil, errors.New("failed to allocate memory for message")
	}

	// don't forget to dealloc memory
	defer s.deallocate.Call(s.ctx, messagePtr[0], msgLen)

	// write message to wasm memory
	ok := s.mod.Memory().Write(uint32(messagePtr[0]), message)
	if !ok {
		return nil, errors.New("failed to write message to memory for hashing")
	}

	// pass message to the hash function
	hashResult, err := s.hashMessageBytes.Call(s.ctx, messagePtr[0], msgLen)
	if err != nil {
		log.Println("hash message bytes error:", err)
		return nil, errors.New("failed to hash message")
	}
	if hashResult[0] == 0 {
		return nil, errors.New("invalid message")
	}

	// take the first (big endian) 32 bits as string size
	hashLen := uint32(hashResult[0] >> 32)

	// casting uint64 to uint32 discards the first (big endian) 32 bits so we're left with the last 32 bits of the result pointer
	hashPtr := uint32(hashResult[0])

	// now we know how many bytes to read to get the byte result
	buf, ok := s.mod.Memory().Read(hashPtr, hashLen)
	if !ok {
		return nil, errors.New("failed to convert message to a field")
	}
	defer s.deallocate.Call(s.ctx, uint64(hashPtr), uint64(hashLen))

	// since memory read returns a slice of wasm memory buffer, it needs to be copied
	// to avoid our returned slice being wiped when wasm memory is wiped
	hash = make([]byte, len(buf))
	copy(hash, buf)

	return
}

// Creates a Aleo-compatible Schnorr signature, returns signature's string representation and Aleo-compatible
// message's string representation.
//
// The message must be a string or little-endian byte representation of a Leo U128.
func (s *aleoWrapperSession) Sign(key string, message []byte) (signature string, err error) {
	if s.mod == nil || s.mod.IsClosed() {
		return "", ErrNoModule
	}

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
			signature = ""
		}
	}()

	if len(key) != PRIVATE_KEY_SIZE {
		return "", errors.New("invalid private key size")
	}

	// allocate memory for the message to pass to the signing function
	messagePtr, err := s.allocate.Call(s.ctx, uint64(len(message)))
	if err != nil {
		log.Println("message allocate error:", err)
		return "", errors.New("failed to allocate memory for message")
	}
	defer s.deallocate.Call(s.ctx, messagePtr[0], uint64(len(message)))

	// write formatted message to memory
	ok := s.mod.Memory().Write(uint32(messagePtr[0]), message)
	if !ok {
		return "", errors.New("failed to write formatted message to memory for signing")
	}

	// allocate memory for private key to pass to the signing function
	privateKeyPtr, err := s.allocate.Call(s.ctx, PRIVATE_KEY_SIZE)
	if err != nil {
		log.Println("private key allocate error:", err)
		return "", errors.New("failed to allocate memory for private key")
	}

	// don't forget to dealloc memory
	defer s.deallocate.Call(s.ctx, privateKeyPtr[0], PRIVATE_KEY_SIZE)

	// write private key to wasm memory
	ok = s.mod.Memory().Write(uint32(privateKeyPtr[0]), []byte(key))
	if !ok {
		return "", errors.New("failed to write private key to memory for signing")
	}

	// call sign function with the pointers to private key and message
	signaturePtr, err := s.sign.Call(s.ctx, privateKeyPtr[0], PRIVATE_KEY_SIZE, uint64(messagePtr[0]), uint64(len(message)))
	if err != nil {
		log.Println("sign error:", err)
		return "", errors.New("failed to sign message")
	}
	if signaturePtr[0] == 0 {
		return "", errors.New("internal error when signing message")
	}

	// read signature string from memory
	sig, ok := s.mod.Memory().Read(uint32(signaturePtr[0]), SIGNATURE_SIZE)
	if !ok {
		return "", errors.New("failed to sign message")
	}
	defer s.deallocate.Call(s.ctx, signaturePtr[0], SIGNATURE_SIZE)

	// since memory read returns a slice of wasm memory buffer, it needs to be copied
	// to avoid our returned slice being wiped when wasm memory is wiped.
	// explicit copy is not needed since we create a string, which copies the slice instead of referencing it
	signature = string(sig)

	return
}
