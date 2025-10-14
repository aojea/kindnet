
package nat64

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
)

var (
	connectionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "kindnet",
		Subsystem: "nat64",
		Name:      "connections_total",
		Help:      "The number of nat64 connections",
	}, []string{"protocol"})
)

var registerMetricsOnce sync.Once

func registerMetrics() {
	registerMetricsOnce.Do(func() {
		klog.Infof("Registering metrics")
		prometheus.MustRegister(connectionsTotal)
	})
}
