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
package conntrack

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
)

var metricBytesHist = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Namespace: "kindnet",
		Subsystem: "conntrack",
		Name:      "connection_bytes_total",
		Help:      "Amount of bytes sent to/received on a connection",
		Buckets:   []float64{1, 5, 10, 50, 100, 500, 1000, 5000, 10000, 50000, 100000},
	},
	[]string{"protocol"},
)

var metricPacketsHist = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Namespace: "kindnet",
		Subsystem: "conntrack",
		Name:      "connection_packets_total",
		Help:      "Amount of packets sent to/received on a connection",
		Buckets:   []float64{1, 5, 10, 50, 100, 500, 1000, 5000, 10000, 50000, 100000},
	},
	[]string{"protocol"},
)

var metricDurationHist = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Namespace: "kindnet",
		Subsystem: "conntrack",
		Name:      "connection_duration_seconds",
		Help:      "Conntrack connection duration (includes timeout waiting time)",
		Buckets:   []float64{0, 1, 2.5, 5, 10, 30, 60, 120, 300, 600, 3600, 7200, 18000, 36000, 72000},
	},
	[]string{"protocol"},
)

var metricTCPSeenReplyLatency = prometheus.NewHistogram(
	prometheus.HistogramOpts{
		Namespace: "kindnet",
		Subsystem: "conntrack",
		Name:      "tcp_connection_seen_reply_latency_milliseconds",
		Help:      "Latency between conntrack flow being created and SEEN_REPLY event",
		Buckets:   []float64{0, 1, 2.5, 5, 10, 30, 60, 120, 300, 600, 1200, 3600, 7200, 10000},
	},
)

var metricConntrackEventsCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "kindnet",
		Subsystem: "conntrack",
		Name:      "events_counter",
		Help:      "Number of handled conntrack events.",
	},
	[]string{"type"},
)

var metricConntrackGlobalMax = prometheus.NewGauge(
	prometheus.GaugeOpts{
		Namespace: "kindnet",
		Subsystem: "conntrack",
		Name:      "entries_max",
		Help:      "Number of max conntrack entries.",
	},
)

var metricConntrackGlobalTotal = prometheus.NewGauge(
	prometheus.GaugeOpts{
		Namespace: "kindnet",
		Subsystem: "conntrack",
		Name:      "entries_total",
		Help:      "Number of conntrack entries.",
	},
)

var metricConntrackFoundTotal = prometheus.NewGauge(
	prometheus.GaugeOpts{
		Namespace: "kindnet",
		Subsystem: "conntrack",
		Name:      "stats_found_total",
	},
)

var metricConntrackInvalidTotal = prometheus.NewGauge(
	prometheus.GaugeOpts{
		Namespace: "kindnet",
		Subsystem: "conntrack",
		Name:      "stats_invalid_total",
	},
)

var metricConntrackIgnoreTotal = prometheus.NewGauge(
	prometheus.GaugeOpts{
		Namespace: "kindnet",
		Subsystem: "conntrack",
		Name:      "stats_ignore_total",
	},
)

var metricConntrackInsertTotal = prometheus.NewGauge(
	prometheus.GaugeOpts{
		Namespace: "kindnet",
		Subsystem: "conntrack",
		Name:      "stats_insert_total",
	},
)

var metricConntrackInsertFailedTotal = prometheus.NewGauge(
	prometheus.GaugeOpts{
		Namespace: "kindnet",
		Subsystem: "conntrack",
		Name:      "stats_insert_failed_total",
	},
)

var metricConntrackEarlyDropTotal = prometheus.NewGauge(
	prometheus.GaugeOpts{
		Namespace: "kindnet",
		Subsystem: "conntrack",
		Name:      "stats_early_drop_total",
	},
)

var metricConntrackErrorTotal = prometheus.NewGauge(
	prometheus.GaugeOpts{
		Namespace: "kindnet",
		Subsystem: "conntrack",
		Name:      "stats_error_total",
	},
)

var metricConntrackSearchRestartTotal = prometheus.NewGauge(
	prometheus.GaugeOpts{
		Namespace: "kindnet",
		Subsystem: "conntrack",
		Name:      "stats_search_restart_total",
	},
)

var registerMetricsOnce sync.Once

func registerMetrics() {
	registerMetricsOnce.Do(func() {
		klog.Infof("Registering metrics")
		prometheus.MustRegister(metricBytesHist)
		prometheus.MustRegister(metricPacketsHist)
		prometheus.MustRegister(metricDurationHist)
		prometheus.MustRegister(metricTCPSeenReplyLatency)
		prometheus.MustRegister(metricConntrackEventsCounter)

		prometheus.MustRegister(metricConntrackGlobalTotal)
		prometheus.MustRegister(metricConntrackGlobalMax)

		prometheus.MustRegister(metricConntrackFoundTotal)
		prometheus.MustRegister(metricConntrackInvalidTotal)
		prometheus.MustRegister(metricConntrackIgnoreTotal)
		prometheus.MustRegister(metricConntrackInsertTotal)
		prometheus.MustRegister(metricConntrackInsertFailedTotal)
		prometheus.MustRegister(metricConntrackEarlyDropTotal)
		prometheus.MustRegister(metricConntrackErrorTotal)
		prometheus.MustRegister(metricConntrackSearchRestartTotal)
	})

}
