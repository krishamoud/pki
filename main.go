package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/justinas/alice"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	_ "reflect"
	"strings"
	"time"
)

var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

type UserRequestBody struct {
	UserId string `json:"userId"`
}

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func NewLoggingResponseWriter(w http.ResponseWriter) *loggingResponseWriter {
	return &loggingResponseWriter{w, http.StatusOK}
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func handleCertificate(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte("Not Implemented"))
		return
	case "POST":
		generateCertificates(w, r)
	case "PUT":
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte("Not Implemented"))
		return
	case "DELETE":
		deleteCertificate(w, r)
	default:
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Bad Request"))
		return
	}
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte("Not Implemented"))
		return
	case "POST":
		verifyCertificate(w, r)
	case "PUT":
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte("Not Implemented"))
		return
	case "DELETE":
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte("Not Implemented"))
		return
	default:
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Bad Request"))
		return
	}
}

func generateCertificates(w http.ResponseWriter, r *http.Request) {
	userId := r.Header.Get("x-user-id")
	if len(userId) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("No userId found"))
		return
	}
	// Step 1: Create the key using 2048 bits or 4096
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	checkError(err)

	// Encode the key to pem format
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)
	// Write the newly created pemfile to the file ssl/{userid}-key.pem
	var keyBuffer bytes.Buffer
	keyBuffer.WriteString("ssl/")
	keyBuffer.WriteString(userId)
	keyBuffer.WriteString("-key.pem")
	ioutil.WriteFile(keyBuffer.String(), pemdata, 0644)

	// Step 2: Create the CSR
	// Set the email for the CSR
	emailAddress := "enterprise@ihealthlabs.com"

	// Set the subject for the CSR
	subj := pkix.Name{
		CommonName:         "enterprise@ihealthlabs.com",
		Country:            []string{"US"},
		Province:           []string{"CA"},
		Locality:           []string{"Sunnyvale"},
		Organization:       []string{"iHealth Labs"},
		OrganizationalUnit: []string{"Engineering"},
	}
	// create the subeject sequence
	rawSubj := subj.ToRDNSequence()
	rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
		{Type: oidEmailAddress, Value: emailAddress},
	})

	asn1Subj, _ := asn1.Marshal(rawSubj)
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		EmailAddresses:     []string{emailAddress},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	// create the certificate signing request and write it to key.csr
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, key)
	csrData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	var csrBuffer bytes.Buffer
	csrBuffer.WriteString("ssl/")
	csrBuffer.WriteString(userId)
	csrBuffer.WriteString("-csr.csr")
	ioutil.WriteFile(csrBuffer.String(), csrData, 0644)

	// create a randiom io.Reader
	random := rand.Reader

	// Step 3: Open the CA cert and private key
	// Open both the CA key and CA certificate files
	CACrt, err := loadCertificate("ssl/ca-crt.pem")
	checkError(err)
	CAKey, err := loadPrivateKey("ssl/ca-key.pem")
	checkError(err)

	// Step 4: create the key template for the certificate
	now := time.Now()
	then := now.Add(60 * 60 * 24 * 365 * 1000 * 1000 * 1000) // one year
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	checkError(err)
	keyTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   userId,
			Organization: []string{userId},
		},
		NotBefore: now,
		NotAfter:  then,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,

		BasicConstraintsValid: true,
		IsCA:     false,
		DNSNames: []string{"localhost"},
	}

	// Step 5: create the certificate
	derBytes, err := x509.CreateCertificate(random, &keyTemplate, CACrt, &key.PublicKey, CAKey)
	checkError(err)

	// Encode the key to pem format
	clientKey := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: derBytes,
		},
	)
	// Write the newly created pemfile to the file ssl/{userid}-crt.pem
	var crtBuffer bytes.Buffer
	crtBuffer.WriteString("ssl/")
	crtBuffer.WriteString(userId)
	crtBuffer.WriteString("-crt.pem")
	ioutil.WriteFile(crtBuffer.String(), clientKey, 0644)
	fmt.Fprintf(w, "%s", clientKey)
}

func deleteCertificate(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var t UserRequestBody
	err := decoder.Decode(&t)
	checkError(err)
	defer r.Body.Close()
	filename := "ssl/" + t.UserId + "-crt.pem"
	cert, err := loadCertificate(filename)
	checkError(err)
	CACrt, err := loadCertificate("ssl/ca-crt.pem")
	checkError(err)
	CAKey, err := loadPrivateKey("ssl/ca-key.pem")
	checkError(err)
	crl, err := loadCRL("ssl/ca-crl.pem")
	checkError(err)
	// create a randiom io.Reader
	random := rand.Reader
	// Step 4: create the key template for the certificate
	now := time.Now()
	then := now.Add(60 * 60 * 24 * 365 * 1000 * 1000 * 1000) // one year
	certs := append(crl.TBSCertList.RevokedCertificates, pkix.RevokedCertificate{SerialNumber: cert.SerialNumber, RevocationTime: now})
	crlBytes, err := CACrt.CreateCRL(random, CAKey, certs, now, then)
	checkError(err)
	crlData := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes})

	var crlBuffer bytes.Buffer
	crlBuffer.WriteString("ssl/ca-crl.pem")
	ioutil.WriteFile(crlBuffer.String(), crlData, 0644)
	w.WriteHeader(http.StatusOK)
	return
}

func verifyCertificate(w http.ResponseWriter, r *http.Request) {
	userCrt := r.Header.Get("x-user-certificate")
	if len(userCrt) == 0 {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("You are not authorized"))
		return
	}
	lines := strings.Split(userCrt, "\t")
	crt := strings.Join(lines, "\n")
	rootPEM, err := ioutil.ReadFile("ssl/ca-crt.pem")
	checkError(err)
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		panic("failed to parse root certificate")
	}
	block, _ := pem.Decode([]byte(crt))
	cert, err := x509.ParseCertificate(block.Bytes)
	checkError(err)
	opts := x509.VerifyOptions{
		DNSName: "localhost",
		Roots:   roots,
	}
	_, err = cert.Verify(opts)
	checkError(err)
	crl, err := loadCRL("ssl/ca-crl.pem")
	checkError(err)

	for _, revokedCert := range crl.TBSCertList.RevokedCertificates {
		revoked := cert.SerialNumber.Cmp(revokedCert.SerialNumber) == 0
		if revoked {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("You are not authorized"))
			return
		}
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(cert.Subject.CommonName))
	return
}

func loadCRL(fileName string) (*pkix.CertificateList, error) {
	crl, err := ioutil.ReadFile(fileName)
	checkError(err)
	return x509.ParseCRL(crl)
}

func loadCertificate(fileName string) (*x509.Certificate, error) {
	b, err := ioutil.ReadFile(fileName) // just pass the file name
	checkError(err)
	block, _ := pem.Decode(b)
	cert, err := x509.ParseCertificate(block.Bytes)
	checkError(err)
	return cert, nil
}

func loadPrivateKey(fileName string) (*rsa.PrivateKey, error) {
	b, err := ioutil.ReadFile(fileName) // just pass the file name
	checkError(err)
	block, _ := pem.Decode(b)
	bytes, err := x509.DecryptPEMBlock(block, []byte("password"))
	checkError(err)
	cert, err := x509.ParsePKCS1PrivateKey(bytes)
	checkError(err)
	return cert, nil
}

func checkError(err error) {
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		panic(err.Error())
	}
}

func loggingHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		lrw := NewLoggingResponseWriter(w)
		t1 := time.Now()
		next.ServeHTTP(lrw, r)
		t2 := time.Now()
		statusCode := lrw.statusCode
		log.Printf("[%s] %q %d - %v\n", r.Method, r.URL.String(), statusCode, t2.Sub(t1))
	}
	return http.HandlerFunc(fn)
}

func recoverHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("Panic: %+v", err)
				http.Error(w, http.StatusText(500), 500)
			}
		}()
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func main() {
	commonHandlers := alice.New(loggingHandler, recoverHandler)
	http.Handle("/v1/verify", commonHandlers.ThenFunc(handleVerify))     // verify the certificate
	http.Handle("/v1/certs", commonHandlers.ThenFunc(handleCertificate)) // set router
	http.ListenAndServe(":9090", nil)                                    // set listen port
}
