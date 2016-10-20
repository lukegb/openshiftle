package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/golang/glog"

	"github.com/lukegb/openshiftle/acme"
	"github.com/lukegb/openshiftle/openshift"
)

var (
	token     = flag.String("token", "", "Token to use for authentication against the OpenShift API. token-path consulted if empty.")
	tokenPath = flag.String("token-path", "/var/run/secrets/kubernetes.io/serviceaccount/token", "Path to file containing OpenShift API token. Default to service account.")

	apiURL    = flag.String("api-url", "https://kubernetes.default.svc.cluster.local", "URL to root of OpenShift REST API.")
	apiCAPath = flag.String("api-ca-path", "/run/kubernetes.io/serviceaccount/service-ca.crt", "Path to CA to trust for OpenShift REST API. If empty, the default CA store is used.")
	namespace = flag.String("namespace", os.Getenv("OPENSHIFTLE_NAMESPACE"), "Namespace to acquire certificates for. Must be provided.")

	acmeURL = flag.String("acme-url", envOrDefault("OPENSHIFTLE_ACME_URL", "https://acme-staging.api.letsencrypt.org/directory"), "URL to ACME CA to issue certificates from.")
	keyPath = flag.String("acme-key-path", os.Getenv("OPENSHIFTLE_ACME_KEY_PATH"), "Path to key used for authenticating against ACME. Will be generated automatically if empty.")

	port        = flag.Int("port", 9000, "HTTP port to perform HTTP challenge responses on.")
	serviceName = flag.String("service-name", os.Getenv("OPENSHIFTLE_SERVICE_NAME"), "Service to route HTTP challenge responses to. Ensure that this is routed to the port above.")

	rerunInterval = flag.Duration("rerun-interval", 10*time.Minute, "Interval at which to check if certificates need issuance.")
)

func envOrDefault(env, def string) string {
	v := os.Getenv(env)
	if v == "" {
		return def
	}
	return v
}

const (
	generatedKeySize = 2048 // bits of RSA key
)

func getToken() (string, error) {
	if *token != "" {
		glog.Info("Using provided token")
		return *token, nil
	}

	glog.Infof("Reading token from file %q", *tokenPath)
	b, err := ioutil.ReadFile(*tokenPath)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func getKey() (crypto.Signer, error) {
	if *keyPath == "" {
		glog.Infof("Generating new %d-bit RSA key", generatedKeySize)
		return rsa.GenerateKey(rand.Reader, generatedKeySize)
	}

	glog.Infof("Reading key from file %q", *keyPath)
	b, err := ioutil.ReadFile(*keyPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("unable to decode PEM data")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		// PKCS#1
		return x509.ParsePKCS1PrivateKey(block.Bytes)

	case "PRIVATE KEY":
		// PKCS#8
		resp, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return resp.(crypto.Signer), nil
	case "EC PRIVATE KEY":
		// SEC 1
		return x509.ParseECPrivateKey(block.Bytes)
	}
	return nil, fmt.Errorf("unknown key type %q", block.Type)

}

func httpClientWithCAFromPath(caPath string) (*http.Client, error) {
	caBytes, err := ioutil.ReadFile(caPath)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("failed to AppendCertsFromPEM from file %s", caPath)
	}

	c := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}
	return c, nil
}

func main() {
	flag.Parse()

	glog.Info("Starting up...")
	if *namespace == "" {
		glog.Exit("No -namespace specified.")
	}
	if *serviceName == "" {
		glog.Exit("No -service-name specified.")
	}

	glog.Infof("Using namespace %q", *namespace)
	glog.Infof("Using HTTP challenge response port %d", *port)

	token, err := getToken()
	if err != nil {
		glog.Exitf("Failed to read token: %v", err)
	}

	key, err := getKey()
	if err != nil {
		glog.Exitf("Failed to get key: %v", err)
	}

	osHTTPClient := http.DefaultClient
	if apiCAPath != nil {
		glog.Infof("Using CA at %s for OpenShift API", *apiCAPath)
		var err error
		osHTTPClient, err = httpClientWithCAFromPath(*apiCAPath)
		if err != nil {
			glog.Exitf("Failed to initialize OpenShift HTTP client: %v", err)
		}
	} else {
		glog.Infof("Using system CA roots for OpenShift API")
	}

	retr, err := acme.New(context.Background(), *port, *acmeURL, key)
	if err != nil {
		glog.Exitf("Failed to instantiate ACME retriever: %v", err)
	}

	os := &openshift.Client{
		HTTPClient: osHTTPClient,
		APIPath:    *apiURL,
		Namespace:  *namespace,
		Token:      token,
	}

	for {
		glog.Info(os.Run(context.Background(), *serviceName, retr.GetCertificate))
		glog.Infof("Sleeping for %s", rerunInterval.String())
		time.Sleep(*rerunInterval)
	}
}
