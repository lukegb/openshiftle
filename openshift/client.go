package openshift

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/golang/glog"
)

const (
	expiryTime = 30 * 24 * time.Hour // roughly one month

	annotationNeedsSSL  = "openshiftle.lukegb.com/enabled"
	annotationWKRMapsTo = "openshiftle.lukegb.com/maps-to"

	annotationValueForce = "force" // if annotationNeedsSSL contains this string, then this certificate is considered stale immediately
	annotationValueOn    = "true"
)

// Client uses the OpenShift API to manage the TLS certificates for routes in the provided namespace with the provided token.
type Client struct {
	HTTPClient *http.Client
	APIPath    string
	Namespace  string
	Token      string
}

func (c *Client) do(ctx context.Context, req *http.Request) (*http.Response, error) {
	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)

	r, derr := httputil.DumpRequestOut(req, true)
	if derr == nil {
		glog.Info(string(r))
	}

	resp, err := httpClient.Do(req.WithContext(ctx))

	r, derr = httputil.DumpResponse(resp, true)
	if derr == nil {
		glog.Info(string(r))
	}

	return resp, err
}

func (c *Client) getRoutes(ctx context.Context) (*Routes, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/oapi/v1/namespaces/%s/routes", c.APIPath, c.Namespace), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.do(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var routes Routes
	if err := json.NewDecoder(resp.Body).Decode(&routes); err != nil {
		return nil, err
	}
	return &routes, nil
}

func (c *Client) deleteRoute(ctx context.Context, route Route) error {
	req, err := http.NewRequest("DELETE", fmt.Sprintf("%s%s", c.APIPath, route.Metadata.SelfLink), nil)
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func (c *Client) patchRoute(ctx context.Context, route Route, patch interface{}) error {
	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(patch); err != nil {
		return err
	}
	req, err := http.NewRequest("PATCH", fmt.Sprintf("%s%s", c.APIPath, route.Metadata.SelfLink), &b)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/strategic-merge-patch+json")
	resp, err := c.do(ctx, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func (c *Client) createRoute(ctx context.Context, route Route) error {
	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(route); err != nil {
		return err
	}
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/oapi/v1/namespaces/%s/routes", c.APIPath, c.Namespace), &b)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.do(ctx, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// Run performs a single check-actuate loop on Client.
func (c *Client) Run(ctx context.Context, targetService string, issueCertificate func(ctx context.Context, hostnames []string) (*x509.Certificate, crypto.Signer, []*x509.Certificate, error)) error {
	routes, err := c.getRoutes(ctx)
	if err != nil {
		return err
	}

	interestingRoutes := filterRoutes(routes, func(r Route) string {
		if r.Metadata.Annotations[annotationNeedsSSL] == "" {
			glog.Infof("Route %q is not enabled for openshiftle, ignoring.", r.Metadata.Name)
			return ""
		}
		// if it's not edge terminated, we can't issue certificates for it
		if r.Spec.TLS != nil && r.Spec.TLS.Termination != "edge" {
			glog.Infof("Route %q is %q terminated, not edge terminated, ignoring!", r.Metadata.Name, r.Spec.TLS.Termination)
			return ""
		}
		return r.Metadata.Name
	})
	wellKnownRoutes := filterRoutes(routes, func(r Route) string {
		return r.Metadata.Annotations[annotationWKRMapsTo]
	})

	if err := c.deleteStaleRoutes(ctx, interestingRoutes, wellKnownRoutes); err != nil {
		glog.Errorf("deleteStaleRoutes: %v", err)
		return err
	}
	if err := c.correctWellKnownRoutes(ctx, wellKnownRoutes, targetService); err != nil {
		glog.Errorf("correctWellKnownRoutes: %v", err)
		return err
	}
	if err := c.createNewWellKnownRoutes(ctx, interestingRoutes, wellKnownRoutes, targetService); err != nil {
		glog.Errorf("createNewWellKnownRoutes: %v", err)
		return err
	}

	if reissue, err := mustReissue(interestingRoutes); err != nil {
		glog.Errorf("mustReissue: %v", err)
		return err
	} else if !reissue {
		glog.Info("No need to reissue certificates.")
		return nil
	}
	glog.Info("Must reissue certificates!")

	hostnames := computeHostnames(interestingRoutes)
	glog.Info("Requesting certificates for hostnames: %v", hostnames)

	cert, privkey, chain, err := issueCertificate(ctx, hostnames)
	if err != nil {
		glog.Errorf("issueCertificate: failed to issue certificates for %v: %v", hostnames, err)
		return err
	}

	glog.Info("Certificate issued!")
	if err := c.setCertificatesForRoutes(ctx, interestingRoutes, cert, privkey, chain); err != nil {
		glog.Errorf("setCertificatesForRoutes: failed to set certificates: %v", err)
		return err
	}

	return nil
}

func signerToBytes(privkey crypto.Signer) ([]byte, string, error) {
	switch privkey := privkey.(type) {
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(privkey)
		if err != nil {
			return nil, "", err
		}
		return b, "EC PRIVATE KEY", nil
	case *rsa.PrivateKey:
		return x509.MarshalPKCS1PrivateKey(privkey), "RSA PRIVATE KEY", nil
	}
	return nil, "", fmt.Errorf("unknown private key %#v", privkey)
}

func (c *Client) setCertificatesForRoutes(ctx context.Context, routes map[string]Route, cert *x509.Certificate, privkey crypto.Signer, chain []*x509.Certificate) error {
	// Convert certificate into friendly form
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	var chainPEMStrings []string
	for _, caCert := range chain {
		chainPEMStrings = append(chainPEMStrings, string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caCert.Raw,
		})))
	}

	// Convert key to PEM too
	keyASN1Bytes, keyPEMHeader, err := signerToBytes(privkey)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  keyPEMHeader,
		Bytes: keyASN1Bytes,
	})

	patch := RouteCertificatePatch{}
	patch.Spec.TLS.Termination = "edge"
	patch.Spec.TLS.Certificate = string(certPEM)
	patch.Spec.TLS.Key = string(keyPEM)
	patch.Spec.TLS.CACertificate = strings.Join(chainPEMStrings, "")
	patch.Metadata.Annotations.OpenShiftLEEnabled = annotationValueOn

	// TODO: CA certificate, but we'll assume it's correct for now...
	for name, route := range routes {
		glog.Infof("Patching certificate for %s", name)
		if err := c.patchRoute(ctx, route, patch); err != nil {
			glog.Errorf("Failed patching certificate for %s: %v", name, err)
			return fmt.Errorf("failed to patch %s: %v", name, err)
		}
	}
	return nil
}

func mustReissue(routes map[string]Route) (bool, error) {
	minimumNotAfter := time.Now().Add(expiryTime)
	glog.Infof("Not After deadline is: %s", minimumNotAfter.String())
	// now work out whether we need a certificate. there are two cases:
	// 1) a new domain has been added which now needs a certificate.
	// 2) we're within expiryTime
	// if either of these cases are true, we will issue a new certificate covering ALL domains
	for routeName, route := range routes {
		if route.Spec.TLS == nil {
			// if there's no cert, then obviously we need to issue a new one
			return true, nil
		}

		if route.Metadata.Annotations[annotationNeedsSSL] == annotationValueForce {
			glog.Infof("%s has %q annotation set to %q!", routeName, annotationNeedsSSL, annotationValueForce)
			return true, nil
		}

		certBytes := []byte(route.Spec.TLS.Certificate)
		certPEM, _ := pem.Decode(certBytes)
		if certPEM == nil {
			return false, fmt.Errorf("failed to decode certificate as PEM from %s", routeName)
		}

		cert, err := x509.ParseCertificate(certPEM.Bytes)
		if err != nil {
			return false, fmt.Errorf("failed to decode certificate: %s", err.Error())
		}

		glog.Infof("Certificate for %s expires at %s", routeName, cert.NotAfter.String())
		if cert.NotAfter.Before(minimumNotAfter) {
			glog.Infof("Certificate for %s is before the Not After deadline!", routeName)
			return true, nil
		}
	}
	return false, nil
}

func computeHostnames(routes map[string]Route) []string {
	var hostnames []string
	for _, route := range routes {
		hostnames = append(hostnames, route.Spec.Host)
	}
	return hostnames
}

func filterRoutes(routes *Routes, match func(r Route) string) map[string]Route {
	out := make(map[string]Route)
	for _, route := range routes.Items {
		if key := match(route); key != "" {
			out[key] = route
		}
	}
	return out
}

func (c *Client) deleteStaleRoutes(ctx context.Context, interestingRoutes, wellKnownRoutes map[string]Route) error {
	// delete any routes which make no sense
	var toDelete []string
	for mapsToName, route := range wellKnownRoutes {
		if _, ok := interestingRoutes[mapsToName]; ok {
			// This is fine
			continue
		}
		// Delete this route
		glog.Infof("Deleting stale well-known route %s", route.Metadata.Name)
		if err := c.deleteRoute(ctx, route); err != nil {
			return err
		}
		toDelete = append(toDelete, mapsToName)
	}
	for _, mapsToName := range toDelete {
		delete(wellKnownRoutes, mapsToName)
	}
	return nil
}

func (c *Client) correctWellKnownRoutes(ctx context.Context, wellKnownRoutes map[string]Route, targetService string) error {
	// update any well-known routes which don't point to us
	for _, route := range wellKnownRoutes {
		to := route.Spec.To
		if to.Kind != "Service" || to.Name != targetService || len(route.Spec.AlternateBackends) != 0 {
			glog.Infof("Patching well-known route %s to point at %s", route.Metadata.Name)
			rtp := RouteTargetPatch{}
			rtp.Spec.To.Kind = "Service"
			rtp.Spec.To.Name = targetService
			rtp.Spec.To.Weight = 100
			if err := c.patchRoute(ctx, route, rtp); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Client) createNewWellKnownRoutes(ctx context.Context, interestingRoutes, wellKnownRoutes map[string]Route, targetService string) error {
	// create new routes for required well-known routes
	for name, route := range interestingRoutes {
		if _, ok := wellKnownRoutes[name]; ok {
			// This is fine
			continue
		}
		// Create a new route
		wkr := Route{
			Kind:       "Route",
			APIVersion: "v1",
			Metadata: ObjectMeta{
				Name: fmt.Sprintf("%s-wkr", name),
				Annotations: map[string]string{
					"openshiftle.lukegb.com/maps-to": name,
				},
			},
			Spec: RouteSpec{
				Host: route.Spec.Host,
				Path: "/.well-known/acme-challenge/",
				To: RouteTargetReference{
					Kind:   "Service",
					Name:   targetService,
					Weight: 100,
				},
			},
		}
		if err := c.createRoute(ctx, wkr); err != nil {
			return err
		}
		wellKnownRoutes[name] = wkr
	}
	return nil
}
