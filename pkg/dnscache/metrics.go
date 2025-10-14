/*
Copyright YEAR The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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

	dnsRecordsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "kindnet",
		Subsystem: "dns_cache",
		Name:      "records_processed_total",
		Help:      "The number of dns records processed by the dns cache per type",
	}, []string{"type"})

	dnsRecordsForwardedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "kindnet",
		Subsystem: "dns_cache",
		Name:      "records_forwarded_total",
		Help:      "The number of dns records forwarded to the upstream server by type",
	}, []string{"type"})

	dnsRecordsForwardeHist = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "kindnet",
		Subsystem: "dns_cache",
		Name:      "records_forwarded_latency_milliseconds",
		Help:      "The latency of dns records forwarded successfully to the upstream server by type",
	}, []string{"type"})

	packetProcessingHist = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "kindnet_dns_cache",
		Name:      "packet_process_time",
		Help:      "Time it has taken to process each packet (microseconds)",
		Buckets:   []float64{1, 10, 50, 200, 500, 750, 1000, 2000, 5000, 10000, 100000},
	}, []string{"family"})

	packetProcessingSum = prometheus.NewSummary(prometheus.SummaryOpts{
		Namespace: "kindnet_dns_cache",
		Name:      "packet_process_duration_microseconds",
		Help:      "A summary of the packet processing durations in microseconds.",
		Objectives: map[float64]float64{
			0.5:  0.05,  // 50th percentile with a max. absolute error of 0.05.
			0.9:  0.01,  // 90th percentile with a max. absolute error of 0.01.
			0.99: 0.001, // 99th percentile with a max. absolute error of 0.001.
		},
	})

	packetCounterVec = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "kindnet_dns_cache",
		Name:      "packet_count",
		Help:      "Number of packets",
	}, []string{"family", "verdict"})
)

var registerMetricsOnce sync.Once

func registerMetrics() {
	registerMetricsOnce.Do(func() {
		klog.Infof("Registering metrics")
		prometheus.MustRegister(packetProcessingHist)
		prometheus.MustRegister(packetProcessingSum)
		prometheus.MustRegister(packetCounterVec)
		prometheus.MustRegister(dnsCacheSize)
		prometheus.MustRegister(dnsRecordsTotal)
		prometheus.MustRegister(dnsRecordsForwardedTotal)
		prometheus.MustRegister(dnsRecordsForwardeHist)
	})
}
