package main

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
)

var (
	dnsCacheSize = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dns_cache_total",
		Help: "The number of entries in the dns cache per family",
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
