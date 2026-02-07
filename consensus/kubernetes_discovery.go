package consensus

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// KubernetesDiscovery discovers consensus nodes via Kubernetes DNS
type KubernetesDiscovery struct {
	headlessService string
	namespace       string
	podName         string
	podIP           string
}

// NewKubernetesDiscovery creates a new Kubernetes-based node discovery
func NewKubernetesDiscovery() *KubernetesDiscovery {
	return &KubernetesDiscovery{
		headlessService: os.Getenv("HEADLESS_SERVICE"),
		namespace:       os.Getenv("POD_NAMESPACE"),
		podName:         os.Getenv("POD_NAME"),
		podIP:           os.Getenv("POD_IP"),
	}
}

// GetNodeID returns unique node ID (pod name)
func (kd *KubernetesDiscovery) GetNodeID() string {
	return kd.podName
}

// GetNodeIP returns this node's IP
func (kd *KubernetesDiscovery) GetNodeIP() string {
	return kd.podIP
}

// DiscoverNodes discovers all consensus nodes via DNS lookup
func (kd *KubernetesDiscovery) DiscoverNodes() ([]Node, error) {
	// DNS name for headless service
	dnsName := fmt.Sprintf("%s.%s.svc.cluster.local", kd.headlessService, kd.namespace)

	// Lookup all IPs
	ips, err := net.LookupIP(dnsName)
	if err != nil {
		return nil, fmt.Errorf("failed to discover nodes: %w", err)
	}

	var nodes []Node
	for _, ip := range ips {
		// Skip IPv6
		if ip.To4() == nil {
			continue
		}

		ipStr := ip.String()
		isSelf := ipStr == kd.podIP

		nodes = append(nodes, Node{
			ID:       fmt.Sprintf("node-%s", strings.ReplaceAll(ipStr, ".", "-")),
			Address:  fmt.Sprintf("%s:8080", ipStr),
			IP:       ipStr,
			IsActive: true,
			IsSelf:   isSelf,
		})
	}

	return nodes, nil
}

// WatchNodes watches for node changes (pods added/removed)
func (kd *KubernetesDiscovery) WatchNodes(callback func([]Node)) {
	// Periodic discovery (every 10 seconds)
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			nodes, err := kd.DiscoverNodes()
			if err == nil {
				callback(nodes)
			}
		}
	}()
}
