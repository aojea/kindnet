// SPDX-License-Identifier: APACHE-2.0

package dnscache

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
)

var (
	dnsCacheSize = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "kindnet",
		Subsystem: "dns_cache",
		Name:      "entries_total",
		Help:      "The number of entries in the dns cache per family",
	}, []string{"family"})
)

var registerMetricsOnce sync.Once

// RegisterMetrics registers kube-proxy metrics.
func registerMetrics() {
	registerMetricsOnce.Do(func() {
		klog.Infof("Registering metrics")
		prometheus.MustRegister(dnsCacheSize)
	})
}
