package openshift

// RouteTargetPatch encodes to a JSON patch which updates the target for a Route.
type RouteTargetPatch struct {
	Spec struct {
		To struct {
			Kind   string
			Name   string
			Weight int
		} `json:"to"`
		AlternateBackends []interface{} `json:"alternateBackends"`
	} `json:"spec"`
}

// RouteCertificatePatch encodes to a JSON patch which updates the TLS certificate for a Route.
type RouteCertificatePatch struct {
	Spec struct {
		TLS struct {
			Termination   string `json:"termination"`
			Certificate   string `json:"certificate"`
			Key           string `json:"key"`
			CACertificate string `json:"caCertificate"`
		} `json:"tls"`
	} `json:"spec"`
	Metadata struct {
		Annotations struct {
			OpenShiftLEEnabled string `json:"openshiftle.lukegb.com/enabled"`
		} `json:"annotations"`
	} `json:"metadata"`
}

// ListMeta encodes the metadata for a grouping of items.
type ListMeta struct {
	ResourceVersion string `json:"resourceVersion"`
	SelfLink        string `json:"selfLink"`
}

// ObjectMeta encodes the metadata for a single item.
type ObjectMeta struct {
	ResourceVersion string            `json:"resourceVersion"`
	SelfLink        string            `json:"selfLink"`
	Name            string            `json:"name"`
	Annotations     map[string]string `json:"annotations"`
}

// RouteTargetReference is a reference to a single target (usually of Kind: "Service")
type RouteTargetReference struct {
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Weight int    `json:"weight"`
}

// RoutePort indicates which port on the service is to be used by the router.
type RoutePort struct {
	TargetPort string `json:"targetPort"`
}

// TLSConfig describes the TLS configuration for a given route.
type TLSConfig struct {
	Termination                   string `json:"termination"`
	Certificate                   string `json:"certificate"`
	Key                           string `json:"key"`
	CACertificate                 string `json:"caCertificate"`
	DestinationCACertificate      string `json:"destinationCACertificate"`
	InsecureEdgeTerminationPolicy string `json:"insecureEdgeTerminationPolicy"`
}

// RouteSpec encodes the desired state of a route.
type RouteSpec struct {
	Host              string                 `json:"host"`
	Path              string                 `json:"path"`
	To                RouteTargetReference   `json:"to"`
	AlternateBackends []RouteTargetReference `json:"alternateBackends"`
	Port              *RoutePort             `json:"port"`
	TLS               *TLSConfig             `json:"tls"`
}

// RouteIngressCondition does something.
type RouteIngressCondition struct {
	Type               string `json:"type"`
	Status             string `json:"status"`
	Reason             string `json:"reason"`
	Message            string `json:"message"`
	LastTransitionTime string `json:"lastTransitionTime"`
}

// RouteIngress nope, no idea.
type RouteIngress struct {
	Host string `json:"host"`
}

// RouteStatus contains the current state of the route.
type RouteStatus struct {
	Ingress []RouteIngress `json:"ingress"`
}

// Route holds information about the current state of the route in question, as well as information about its status in the cluster.
type Route struct {
	Kind       string       `json:"kind"`
	APIVersion string       `json:"apiVersion"`
	Metadata   ObjectMeta   `json:"metadata"`
	Spec       RouteSpec    `json:"spec"`
	Status     *RouteStatus `json:"status"`
}

// Routes is a list of Route.
type Routes struct {
	Kind       string   `json:"kind"`
	APIVersion string   `json:"apiVersion"`
	Metadata   ListMeta `json:"metadata"`
	Items      []Route  `json:"items"`
}
