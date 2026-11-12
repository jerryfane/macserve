package controllerconfig

import "testing"

func TestPrivateListenerPolicyRejectsPublicWildcardAndMappedAddresses(t *testing.T) {
	base := Config{Root: "/service/data", Socket: "/service/run/worker.sock", JobUID: 502, OwnerUID: 501, ProfilesFile: "/service/config/profiles.json", TLSCertificate: "/service/config/tls.crt", TLSKey: "/service/secrets/tls.key", HealthFile: "/service/config/health.json"}
	base.Receipt = ReceiptConfig{KeyID: "test", PrivateKeyFile: "/service/secrets/receipt.key", ServiceID: "test", HostID: "test", Repositories: map[string]int64{"example-org/example-app": 123}}
	for _, address := range []string{"0.0.0.0:9443", "[::]:9443", "127.0.0.1:9443", "localhost:9443", "8.8.8.8:9443", "[::ffff:100.64.0.1]:9443", "100.64.0.1:0", "192.168.1.1:9443", "[fe80::1]:9443", "[fe80::1%en0]:9443", "169.254.1.1:9443", "[fd7a:115c:a1e0::1%en0]:9443"} {
		c := base
		c.Listen = address
		if err := c.validate(); err == nil {
			t.Fatalf("accepted listener %q", address)
		}
	}
	for _, address := range []string{"100.64.0.1:9443", "[fd7a:115c:a1e0::1]:9443"} {
		c := base
		c.Listen = address
		if err := c.validate(); err != nil {
			t.Fatalf("private listener %q: %v", address, err)
		}
	}
	c := base
	c.Listen = "8.8.8.8:9443"
	c.AllowedNetworks = []string{"0.0.0.0/0"}
	if err := c.validate(); err == nil {
		t.Fatal("public CIDR expanded listener policy")
	}
}

// controller.json takes max_concurrent_jobs 1..6 (omitted means 1); 7 is
// refused.
func TestControllerConfigLanesUpToSix(t *testing.T) {
	base := Config{Root: "/service/data", Socket: "/service/run/worker.sock", JobUID: 502, OwnerUID: 501, ProfilesFile: "/service/config/profiles.json", TLSCertificate: "/service/config/tls.crt", TLSKey: "/service/secrets/tls.key", HealthFile: "/service/config/health.json", Listen: "100.64.0.1:9443"}
	base.Receipt = ReceiptConfig{KeyID: "test", PrivateKeyFile: "/service/secrets/receipt.key", ServiceID: "test", HostID: "test", Repositories: map[string]int64{"example-org/example-app": 123}}
	for _, lanes := range []int{4, 5, 6} {
		c := base
		c.MaxConcurrentJobs = lanes
		if err := c.validate(); err != nil || c.Lanes() != lanes {
			t.Fatalf("max_concurrent_jobs %d: lanes %d, %v", lanes, c.Lanes(), err)
		}
	}
	for _, lanes := range []int{-1, 7} {
		c := base
		c.MaxConcurrentJobs = lanes
		if err := c.validate(); err == nil {
			t.Fatalf("max_concurrent_jobs %d accepted", lanes)
		}
	}
}
