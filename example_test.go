package aleo_utils_test

import (
	"log"

	aleo "github.com/zkportal/aleo-utils-go"
)

func Example() {
	// create Aleo wrapper
	wrapper, closeFn, err := aleo.NewWrapper()
	if err != nil {
		log.Fatalln(err)
	}
	defer closeFn()

	// create a new session
	s, err := wrapper.NewSession()
	if err != nil {
		log.Fatalln(err)
	}

	// generate a new Aleo private key
	privKey, address, err := s.NewPrivateKey()
	if err != nil {
		log.Fatalln(err)
	}

	// create a formatted message. the message fits in 1 512-byte block, so that's how many we request.
	// the formatted message is an equivalent of Leo type Data with 1 DataChunk
	// struct DataChunk {
	//   f0: u128,
	//   ...
	//   f31: u128
	// }
	// struct Data {
	// 	c0: DataChunk
	// }
	formattedMessage, err := s.FormatMessage([]byte("btc/usd = 1.0"), 1)
	if err != nil {
		log.Fatalln(err)
	}

	// formatted message can be signed as is or hashed first
	hashedMessage, err := s.HashMessage(formattedMessage)
	if err != nil {
		log.Fatalln(err)
	}

	// sign a message
	signature, err := s.Sign(privKey, hashedMessage)
	if err != nil {
		log.Fatalln(err)
	}

	log.Println("Formatted message:", formattedMessage)
	log.Println("Signature:", signature)
	log.Println("Address:", address)
	log.Println("Poseidon8 hash:", hashedMessage)
	log.Println("Private key:", privKey)

	// Output:
}
