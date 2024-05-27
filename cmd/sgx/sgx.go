package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/edgelesssys/ego/attestation/tcbstatus"
	"github.com/edgelesssys/ego/enclave"

	aleo "github.com/zkportal/aleo-utils-go"
)

func main() {
	extractedData := make([]byte, 16*1024)
	n, err := rand.Read(extractedData)
	if err != nil {
		log.Fatalln(err)
	}
	if n != 16*1024 {
		log.Fatalln("not enough randomness")
	}

	wrapper, close, err := aleo.NewWrapper()
	if err != nil {
		log.Fatalln(err)
	}
	defer close()

	s, err := wrapper.NewSession()
	if err != nil {
		log.Fatalln(err)
	}

	message, err := s.FormatMessage([]byte(extractedData), 32)
	if err != nil {
		log.Fatalln(err)
	}

	hash, err := s.HashMessage(message)
	if err != nil {
		log.Fatalln(err)
	}
	hashAsField, err := s.HashMessageToString(message)
	if err != nil {
		log.Fatalln(err)
	}

	report, err := enclave.GetRemoteReport(hash)
	if err != nil {
		log.Fatalln(err)
	}

	reportObj, err := enclave.VerifyRemoteReport(report)
	if err != nil {
		log.Println("TCB:", reportObj.TCBStatus)
		log.Println("TCB status:", tcbstatus.Explain(reportObj.TCBStatus))
		log.Fatalln(err)
	}

	formattedReport, err := s.FormatMessage(report, 20)
	if err != nil {
		log.Fatalln(err)
	}

	hashedReport, err := s.HashMessageToString(formattedReport)
	if err != nil {
		log.Fatalln(err)
	}

	signature, err := s.Sign("APrivateKey1zkpEem71u7U75h5VodKNgyR37aGJBj4ZTgagCHm3qsuz5PU", []byte(hashedReport))
	if err != nil {
		log.Fatalln(err)
	}

	var b strings.Builder

	b.WriteString(fmt.Sprintf("Private key = \"%s\"\n", "APrivateKey1zkpEem71u7U75h5VodKNgyR37aGJBj4ZTgagCHm3qsuz5PU"))
	b.WriteString(fmt.Sprintf("Address = \"%s\"\n", "aleo1vz6e7yyv9anm7xpnl02nzwz5qdgvaypx428gpx5vdjnhgle64cpsld55le"))
	b.WriteString(fmt.Sprintf("Extracted data = \"%s\"\n", hex.EncodeToString(extractedData)))
	b.WriteString(fmt.Sprintf("Formatted extracted data = \"%s\"\n", string(message)))
	b.WriteString(fmt.Sprintf("Hashed extracted data = \"%s\"\n", hex.EncodeToString(hash)))
	b.WriteString(fmt.Sprintf("Hashed extracted data as field = \"%s\"\n", hashAsField))
	b.WriteString(fmt.Sprintf("Report = \"%s\"\n", hex.EncodeToString(report)))
	b.WriteString(fmt.Sprintf("Report SignerID = \"%s\"\n", hex.EncodeToString(reportObj.SignerID)))
	b.WriteString(fmt.Sprintf("Report UniqueID = \"%s\"\n", hex.EncodeToString(reportObj.UniqueID)))
	b.WriteString(fmt.Sprintf("Report ProductID = \"%s\"\n", hex.EncodeToString(reportObj.ProductID)))
	b.WriteString(fmt.Sprintf("Report TCBStatus = \"%d\"\n", uint(reportObj.TCBStatus)))
	b.WriteString(fmt.Sprintf("Formatted report = \"%s\"\n", string(formattedReport)))
	b.WriteString(fmt.Sprintf("Hashed report = \"%s\"\n", hashedReport))
	b.WriteString(fmt.Sprintf("Signature = \"%s\"\n", signature))

	os.WriteFile("output.txt", []byte(b.String()), 0666)
}
