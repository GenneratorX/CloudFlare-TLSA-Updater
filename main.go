package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/cloudflare/cloudflare-go"
)

var (
	errorLog = log.New(os.Stderr, "[ERROR] ", 0)
	infoLog  = log.New(os.Stdout, "[INFO] ", 0)
)

func main() {
	cloudflareAPIKey := flag.String(
		"api_key",
		os.Getenv("CLOUDFLARE_API_KEY"),
		"Cloudflare API Token",
	)
	certificatePath := flag.String(
		"cert_path",
		os.Getenv("CERT_PATH"),
		"Path to SSL certificate",
	)

	flag.Parse()

	if *cloudflareAPIKey == "" {
		errorLog.Fatalln("cloudflare API key not provided and CLOUDFLARE_API_KEY environment variable is empty")
	}
	if *certificatePath == "" {
		errorLog.Fatalln("ssl certificate file not provided and CERT_PATH environment variable is empty")
	}

	infoLog.Println("parsing certificate file")
	cert, err := parseCert(certificatePath)
	printError(err)

	infoLog.Println("creating CloudFlare API client")
	api, err := cloudflare.NewWithAPIToken(*cloudflareAPIKey)
	printError(err)

	infoLog.Println("getting CloudFlare zone for domain:", cert.Subject.CommonName)
	zoneId, err := api.ZoneIDByName(cert.Subject.CommonName)
	printError(err)

	infoLog.Println("fetching current TLSA DNS records")
	dnsRecords, _, err := api.ListDNSRecords(
		context.Background(),
		cloudflare.ZoneIdentifier(zoneId),
		cloudflare.ListDNSRecordsParams{Type: "TLSA"},
	)
	printError(err)

	errs := removeDNSRecords(api, zoneId, dnsRecords)
	errsCount := 0
	for i := 0; i < len(errs); i++ {
		if errs[i] != nil {
			errorLog.Println(errs[i])
			errsCount++
		}
	}
	if errsCount == 0 {
		infoLog.Println("removed", len(errs), "TLSA DNS records")
	} else {
		errorLog.Fatalln("removed", len(errs)-errsCount, "/", len(errs), "TLSA DNS records")
	}

	infoLog.Println("creating TLSA DNS records for:", strings.Join(cert.DNSNames, ", "))
	errs = createDNSRecords(api, zoneId, cert)
	errsCount = 0
	for i := 0; i < len(errs); i++ {
		if errs[i] != nil {
			errorLog.Println(errs[i])
			errsCount++
		}
	}
	if errsCount == 0 {
		infoLog.Println("created", len(errs), "TLSA DNS records")
	} else {
		errorLog.Fatalln("created", len(errs)-errsCount, "/", len(errs), "TLSA DNS records")
	}
}

func parseCert(certPath *string) (*x509.Certificate, error) {
	certificate, err := os.ReadFile(*certPath)
	if err != nil {
		var errorMessage string
		switch {
		case errors.Is(err, os.ErrNotExist):
			errorMessage = "could not find file at specified location"
		case errors.Is(err, os.ErrPermission):
			errorMessage = "not enough permissions to open file"
		default:
			errorMessage = "could not open certificate file"
		}
		return nil, errors.New(errorMessage)
	}

	cert, _ := pem.Decode(certificate)
	if cert == nil {
		return nil, errors.New("invalid SSL certificate")
	}

	return x509.ParseCertificate(cert.Bytes)
}

func getRemovableDNSRecords(api *cloudflare.API, zoneId string, cert *x509.Certificate) ([]string, error) {
	dnsRecords, _, err := api.ListDNSRecords(
		context.Background(),
		cloudflare.ZoneIdentifier(zoneId),
		cloudflare.ListDNSRecordsParams{Type: "TLSA"},
	)
	if err != nil {
		return nil, err
	}

	removableRecords := make([]string, 0, len(cert.DNSNames))
	for i := 0; i < len(cert.DNSNames); i++ {
		for j := 0; j < len(dnsRecords); j++ {
			if dnsRecords[j].Name == "_443._tcp."+cert.DNSNames[i] {
				removableRecords = append(removableRecords, dnsRecords[j].ID)
				break
			}
		}
	}

	return removableRecords, nil
}

func removeDNSRecords(api *cloudflare.API, zoneId string, dnsRecords []cloudflare.DNSRecord) []error {
	ctx := context.Background()
	removeErrors := make([]error, len(dnsRecords))

	var wg sync.WaitGroup
	wg.Add(len(dnsRecords))
	for i := 0; i < len(dnsRecords); i++ {
		go func(i int) {
			defer wg.Done()
			err := api.DeleteDNSRecord(ctx, cloudflare.ZoneIdentifier(zoneId), dnsRecords[i].ID)
			if err != nil {
				removeErrors[i] = errors.New("TLSA " + dnsRecords[i].Name + " - " + err.Error())
			}
		}(i)
	}
	wg.Wait()

	return removeErrors
}

func createDNSRecords(api *cloudflare.API, zoneId string, cert *x509.Certificate) []error {
	ctx := context.Background()
	tlsaRecord := generateTLSA(cert)
	createErrors := make([]error, len(cert.DNSNames))

	var wg sync.WaitGroup
	wg.Add(len(cert.DNSNames))
	for i := 0; i < len(cert.DNSNames); i++ {
		go func(i int) {
			defer wg.Done()
			_, err := api.CreateDNSRecord(
				ctx,
				cloudflare.ZoneIdentifier(zoneId),
				cloudflare.CreateDNSRecordParams{
					Type: "TLSA",
					Name: "_443._tcp." + cert.DNSNames[i],
					Data: tlsaRecord,
				})
			if err != nil {
				createErrors[i] = errors.New("TLSA " + cert.DNSNames[i] + " - " + err.Error())
			}
		}(i)
	}
	wg.Wait()

	return createErrors
}

func generateTLSA(cert *x509.Certificate) map[string]string {
	certHashBytes := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	certHash := hex.EncodeToString(certHashBytes[:])

	return map[string]string{
		"usage":         "3",
		"selector":      "1",
		"matching_type": "1",
		"certificate":   certHash,
	}
}

func printError(err error) {
	if err != nil {
		errorLog.Fatalln(err)
	}
}
