package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io/ioutil"
	mathrand "math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/golang/glog"

	"golang.org/x/crypto/acme"
	"golang.org/x/sync/errgroup"
)

const (
	httpChallenge         = "http-01" // ACME challenge identifier for HTTP-01
	certificateRsaKeySize = 2048

	retryStartInterval = 1 * time.Second  // time between requests to self to allow router to settle
	retryMaxInterval   = 60 * time.Second // time to cap requests out
	retryJitter        = 5 * time.Second  // maximum +/- jitter to apply

	maxAttempts = 30 // attempts to try to retrieve challenge token from self before giving up
)

// Retriever retrieves TLS certificates from an ACME host using the HTTP-01 challenge on a given port.
type Retriever struct {
	Port   int
	Client *acme.Client

	responseMu  sync.RWMutex
	responseMap map[hostPath]string

	listenDo  sync.Once
	listenErr error
}

type hostPath struct {
	Host string
	Path string
}

func (a *Retriever) authorize(ctx context.Context, hostname string) error {
	glog.Infof("Authorizing %s", hostname)
	auth, err := a.Client.Authorize(ctx, hostname)
	if err != nil {
		return err
	}
	if auth.Status == acme.StatusValid {
		glog.Info("%s: already authorized", hostname)
		return nil
	}
	err = func() error {
		// Check that "http-01" is acceptable
		canDoChallenges := make(map[int]*acme.Challenge)
		for idx, chal := range auth.Challenges {
			if chal.Type != httpChallenge {
				glog.Infof("%s: skipping challenge %s at pos %d", hostname, chal.Type, idx)
				continue
			}
			canDoChallenges[idx] = chal
		}

		if len(auth.Combinations) == 0 && len(auth.Challenges) != len(canDoChallenges) {
			return fmt.Errorf("server required we perform all challenges, which includes challenge types we don't understand")
		}
		var validChallenges []*acme.Challenge
		if len(auth.Combinations) == 0 {
			if len(auth.Challenges) != len(canDoChallenges) {
				return fmt.Errorf("server required we perform all challenges, which includes challenge types we don't understand")
			}
			validChallenges = auth.Challenges
		}
	comboLoop:
		for _, combo := range auth.Combinations {
			glog.Infof("%s: checking combination %v", hostname, combo)
			thisChallenges := make([]*acme.Challenge, len(combo))
			for n, challengeIdx := range combo {
				if canDoChallenges[challengeIdx] == nil {
					glog.Infof("%s: challenge %d not possible", hostname, challengeIdx)
					continue comboLoop
				}
				thisChallenges[n] = canDoChallenges[challengeIdx]
			}
			validChallenges = thisChallenges
			break
		}
		if validChallenges == nil {
			return fmt.Errorf("unable to find valid combination of challenges")
		}

		glog.Infof("%s: setting up challenges", hostname)
		a.responseMu.Lock()
		for _, chal := range validChallenges {
			resp, err := a.Client.HTTP01ChallengeResponse(chal.Token)
			if err != nil {
				return fmt.Errorf("unable to sign http-01 challenge response: %#v", err)
			}
			a.responseMap[hostPath{hostname, a.Client.HTTP01ChallengePath(chal.Token)}] = resp
		}
		a.responseMu.Unlock()

		for _, chal := range validChallenges {
			challengeURL := fmt.Sprintf("http://%s%s", hostname, a.Client.HTTP01ChallengePath(chal.Token))
			expectResponse, err := a.Client.HTTP01ChallengeResponse(chal.Token)
			if err != nil {
				return err
			}

			isReady := false
			retryTime := retryStartInterval
			attempts := 0
			for !isReady {
				glog.Infof("%s: attempting to retrieve %s to verify content (attempt %d)", hostname, challengeURL, attempts+1)
				resp, err := http.Get(fmt.Sprintf("http://%s%s", hostname, a.Client.HTTP01ChallengePath(chal.Token)))
				if err != nil {
					return err
				}
				defer resp.Body.Close()
				b, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					return err
				}
				if string(b) != expectResponse {
					glog.Infof("%s: unexpected response %q", hostname, string(b))
				}

				attempts = attempts + 1
				if attempts >= maxAttempts {
					glog.Infof("%s: exceed max attempts, giving up.", hostname)
					return fmt.Errorf("failed to retrieve challenge token from self within %d tries", maxAttempts)
				}

				thisRetryTime := retryTime + time.Duration(float64(retryJitter)*2*mathrand.Float64()) - retryJitter
				retryTime = retryTime * 2
				glog.Infof("%s: retrying in %s", thisRetryTime.String())
				time.Sleep(thisRetryTime)
			}

			if _, err := a.Client.Accept(ctx, chal); err != nil {
				return err
			}
		}

		_, err := a.Client.WaitAuthorization(ctx, auth.URI)
		return err
	}()
	if err != nil {
		glog.Infof("%s: detected error, revoking authorization %s", hostname, auth.URI)
		if err := a.Client.RevokeAuthorization(ctx, auth.URI); err != nil {
			glog.Errorf("%s: error while revoking authorization: %v", hostname, err)
		}
	}
	return err
}

func generateCSR(hostnames []string) ([]byte, crypto.Signer, error) {
	// generate new private key
	privkey, err := rsa.GenerateKey(rand.Reader, certificateRsaKeySize)
	if err != nil {
		return nil, nil, err
	}

	// generate csr
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: hostnames[0]},
		DNSNames: hostnames,
	}, privkey)
	if err != nil {
		return nil, nil, err
	}
	return csr, privkey, nil
}

func validCert(hostnames []string, der [][]byte, key crypto.Signer) (leaf *x509.Certificate, chain []*x509.Certificate, err error) {
	// parse public part(s)
	var n int
	for _, b := range der {
		n += len(b)
	}
	pub := make([]byte, n)
	n = 0
	for _, b := range der {
		n += copy(pub[n:], b)
	}
	x509Cert, err := x509.ParseCertificates(pub)
	if len(x509Cert) == 0 {
		return nil, nil, errors.New("no public key found")
	}
	// verify the leaf is not expired and matches the domain name
	leaf = x509Cert[0]
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return nil, nil, errors.New("certificate is not valid yet")
	}
	if now.After(leaf.NotAfter) {
		return nil, nil, errors.New("expired certificate")
	}
	for _, domain := range hostnames {
		if err := leaf.VerifyHostname(domain); err != nil {
			return nil, nil, err
		}
	}
	// ensure the leaf corresponds to the private key
	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		prv, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, errors.New("private key type does not match public key type")
		}
		if pub.N.Cmp(prv.N) != 0 {
			return nil, nil, errors.New("private key does not match public key")
		}
	case *ecdsa.PublicKey:
		prv, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, nil, errors.New("private key type does not match public key type")
		}
		if pub.X.Cmp(prv.X) != 0 || pub.Y.Cmp(prv.Y) != 0 {
			return nil, nil, errors.New("private key does not match public key")
		}
	default:
		return nil, nil, errors.New("unknown public key algorithm")
	}
	return leaf, x509Cert[1:], nil
}

// GetCertificate issues a certificate for the given set of hostnames, and will attempt to verify ownership of any hostnames which are not already verified.
func (a *Retriever) GetCertificate(ctx context.Context, hostnames []string) (*x509.Certificate, crypto.Signer, []*x509.Certificate, error) {
	// authorize all hostnames
	var g errgroup.Group
	for _, hostname := range hostnames {
		hostname := hostname
		g.Go(func() error {
			if err := a.authorize(ctx, hostname); err != nil {
				return fmt.Errorf("failed to authorize %s: %v", hostname, err)
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, nil, nil, err
	}

	csr, privkey, err := generateCSR(hostnames)
	if err != nil {
		return nil, nil, nil, err
	}

	der, _, err := a.Client.CreateCert(ctx, csr, 0, true)
	if err != nil {
		return nil, nil, nil, err
	}

	leaf, chain, err := validCert(hostnames, der, privkey)
	if err != nil {
		return nil, nil, nil, err
	}
	return leaf, privkey, chain, nil
}

// ListenAndServe listens on the provided port. It will only do anything the first time it is called on a given retriever.
func (a *Retriever) ListenAndServe() error {
	a.listenDo.Do(func() {
		a.listenErr = http.ListenAndServe(fmt.Sprintf(":%d", a.Port), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			glog.Infof("got request for %s - %s", r.Host, r.URL.Path)
			a.responseMu.RLock()
			resp, ok := a.responseMap[hostPath{r.Host, r.URL.Path}]
			a.responseMu.RUnlock()
			if !ok {
				glog.Infof("%s - %s -- 404", r.Host, r.URL.Path)
				http.NotFound(w, r)
				return
			}

			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "%s", resp)
			glog.Infof("%s - %s -- 200: %s", r.Host, r.URL.Path, resp)
		}))
	})
	return a.listenErr
}

// New creates a new instance of Retriever using the provided HTTP listening port, ACME server, and subscriber private key.
func New(ctx context.Context, port int, directory string, key crypto.Signer) (*Retriever, error) {
	client := &acme.Client{
		Key:          key,
		DirectoryURL: directory,
	}

	account := &acme.Account{}
	_, err := client.Register(ctx, account, func(tosURL string) bool { return true })
	if ae, ok := err.(*acme.Error); err != nil && (!ok || ae.StatusCode != http.StatusConflict) {
		return nil, err
	}

	r := &Retriever{
		Port:        port,
		Client:      client,
		responseMap: make(map[hostPath]string),
	}
	go r.ListenAndServe()
	return r, nil
}
