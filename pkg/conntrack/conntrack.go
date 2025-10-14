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
	"context"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"
	"github.com/vishvananda/netlink/nl"
	"k8s.io/klog/v2"
	"k8s.io/utils/lru"
)

const (
	netfilterConntrackAcctSetting = "/proc/sys/net/netfilter/nf_conntrack_acct"
	netfilterTimestampSetting     = "/proc/sys/net/netfilter/nf_conntrack_timestamp"
	numWorkers                    = 4
	metricPeriod                  = 10 * time.Second
)

func enableConntrackFeatures() {
	err := os.WriteFile(netfilterConntrackAcctSetting, []byte("1"), 0644)
	if err != nil {
		klog.Infof("failed to enable %s : %v", netfilterConntrackAcctSetting, err)
	}

	err = os.WriteFile(netfilterTimestampSetting, []byte("1"), 0644)
	if err != nil {
		klog.Infof("failed to enable %s : %v", netfilterTimestampSetting, err)
	}
}

func StartConntrackMetricsAgent(ctx context.Context) error {
	enableConntrackFeatures()
	registerMetrics()

	// Open a Conntrack connection.
	statsConn, err := conntrack.Dial(nil)
	if err != nil {
		return err
	}
	defer statsConn.Close()

	// Start a goroutine to process all conntrack stats.
	go func() {
		for {
			aggrStats := conntrackStats{}
			stats, err := statsConn.Stats()
			if err == nil {
				for _, stat := range stats {
					aggrStats.Found += float64(stat.Found)
					aggrStats.Invalid += float64(stat.Invalid)
					aggrStats.Ignore += float64(stat.Ignore)
					aggrStats.Insert += float64(stat.Insert)
					aggrStats.InsertFailed += float64(stat.InsertFailed)
					aggrStats.EarlyDrop += float64(stat.EarlyDrop)
					aggrStats.Error += float64(stat.Error)
					aggrStats.SearchRestart += float64(stat.SearchRestart)
				}
				klog.V(4).Infof("Conntrack aggregated stats: %#v", aggrStats)
				metricConntrackFoundTotal.Set(aggrStats.Found)
				metricConntrackInvalidTotal.Set(aggrStats.Invalid)
				metricConntrackIgnoreTotal.Set(aggrStats.Ignore)
				metricConntrackInsertTotal.Set(aggrStats.Insert)
				metricConntrackInsertFailedTotal.Set(aggrStats.InsertFailed)
				metricConntrackEarlyDropTotal.Set(aggrStats.EarlyDrop)
				metricConntrackErrorTotal.Set(aggrStats.Error)
				metricConntrackSearchRestartTotal.Set(aggrStats.SearchRestart)
			} else {
				klog.V(2).Infof("could not get conntrack stats error: %v", err)
			}

			global, err := statsConn.StatsGlobal()
			if err == nil {
				klog.V(2).Infof("Conntrack global stats max: %d entries: %d", global.MaxEntries, global.Entries)
				metricConntrackGlobalTotal.Set(float64(global.Entries))
				metricConntrackGlobalMax.Set(float64(global.MaxEntries))
			} else {
				klog.V(2).Infof("could not get conntrack global stats error: %v", err)
			}

			select {
			case <-ctx.Done():
				return
			case <-time.After(metricPeriod):
			}
		}
	}()

	// Open a Conntrack connection.
	eventsConn, err := conntrack.Dial(nil)
	if err != nil {
		return err
	}
	defer eventsConn.Close()
	// reference https://lore.kernel.org/netdev/49C789F4.4050906@trash.net/T/#mfa68b0c462d1342869f4a2a152285910220f72bc
	err = eventsConn.SetOption(netlink.BroadcastError, true)
	if err != nil {
		klog.Infof("could not set NETLINK_BROADCAST_SEND_ERROR option: %v", err)
	}
	err = eventsConn.SetOption(netlink.NoENOBUFS, true)
	if err != nil {
		klog.Infof("could not set NETLINK_NO_ENOBUFS option: %v", err)
	}
	// Make a buffered channel to receive event updates on.
	evCh := make(chan conntrack.Event, 1024)

	// Listen for all Conntrack and Conntrack-Expect events with 4 decoder goroutines.
	// All errors caught in the decoders are passed on channel errCh.
	errCh, err := eventsConn.Listen(evCh, numWorkers, netfilter.GroupsCT)
	if err != nil {
		return err
	}
	go func() {
		activeWorkers := numWorkers
		for j := range errCh {
			activeWorkers--
			klog.Infof("conntrack events workers: %d - worker error: %v", j, activeWorkers)
			if activeWorkers == 0 {
				return
			}
		}
	}()
	// events are not guaranteed to be delivered so avoid to
	// leak entries and cap the size of the tracker.
	// key is the flow-id uint32 and value the time it has been received time.Time{}
	tracker := lru.New(1024)
	// we need as many workers to drain the channel to process the events
	worker := func(ctx context.Context, evCh <-chan conntrack.Event) {
		for {
			select {
			case <-ctx.Done():
				return
			case evt := <-evCh:
				klog.V(7).Infof("event received: %s", evt.String())
				klog.V(7).Infof("flow received: %#v", evt.Flow)

				metricConntrackEventsCounter.WithLabelValues(evt.Type.String()).Inc()
				switch evt.Type {
				case conntrack.EventNew:
					if evt.Flow.TupleOrig.Proto.Protocol == syscall.IPPROTO_TCP {
						tracker.Add(evt.Flow.ID, time.Now())
					}
				case conntrack.EventUpdate:
					if evt.Flow.ProtoInfo.TCP != nil &&
						evt.Flow.ProtoInfo.TCP.State == nl.TCP_CONNTRACK_SYN_RECV {
						firstSeen, ok := tracker.Get(evt.Flow.ID)
						if ok {
							duration := float64(time.Since(firstSeen.(time.Time)).Milliseconds())
							metricTCPSeenReplyLatency.Observe(duration)
						}
					}
				case conntrack.EventDestroy:
					var duration time.Duration
					if evt.Flow.TupleOrig.Proto.Protocol == syscall.IPPROTO_TCP {
						tracker.Remove(evt.Flow.ID)
					}
					proto := l4ProtoMap(evt.Flow.TupleOrig.Proto.Protocol)
					if !evt.Flow.Timestamp.Start.IsZero() && !evt.Flow.Timestamp.Stop.IsZero() {
						duration = evt.Flow.Timestamp.Stop.Sub(evt.Flow.Timestamp.Start)
						metricDurationHist.WithLabelValues(proto).Observe(duration.Seconds())
					}
					if evt.Flow.CountersOrig.Bytes > 0 || evt.Flow.CountersReply.Bytes > 0 {
						bytes := float64(evt.Flow.CountersOrig.Bytes + evt.Flow.CountersReply.Bytes)
						metricBytesHist.WithLabelValues(proto).Observe(bytes)
					}
					if evt.Flow.CountersOrig.Packets > 0 || evt.Flow.CountersReply.Packets > 0 {
						pkts := float64(evt.Flow.CountersOrig.Packets + evt.Flow.CountersReply.Packets)
						metricPacketsHist.WithLabelValues(proto).Observe(pkts)
					}

					// log connecvtions summary
					klog.V(4).Infof("connection: %s\torig: src=%s:%d dst=%s:%d packets=%d bytes=%d -- reply: src=%s:%d dst=%s:%d packets=%d bytes=%d duration=%v",
						proto,
						evt.Flow.TupleOrig.IP.SourceAddress.String(), evt.Flow.TupleOrig.Proto.SourcePort,
						evt.Flow.TupleOrig.IP.DestinationAddress.String(), evt.Flow.TupleOrig.Proto.DestinationPort,
						evt.Flow.CountersOrig.Packets, evt.Flow.CountersOrig.Bytes,
						evt.Flow.TupleReply.IP.SourceAddress.String(), evt.Flow.TupleReply.Proto.SourcePort,
						evt.Flow.TupleReply.IP.DestinationAddress.String(), evt.Flow.TupleReply.Proto.DestinationPort,
						evt.Flow.CountersReply.Packets, evt.Flow.CountersReply.Bytes,
						duration,
					)
				}
			}
		}
	}

	for i := 0; i < numWorkers; i++ {
		go func() {
			worker(ctx, evCh)
		}()
	}

	<-ctx.Done()

	return nil
}

func eventTypeString(t uint8) string {
	switch t {
	case 1:
		return "new"
	case 2:
		return "update"
	case 3:
		return "destroy"
	default:
		return "unknown"
	}
}

func l4ProtoMap(t uint8) string {
	switch t {
	case syscall.IPPROTO_TCP:
		return "tcp"
	case syscall.IPPROTO_UDP:
		return "udp"
	case syscall.IPPROTO_SCTP:
		return "sctp"
	default:
		return strconv.Itoa(int(t))
	}
}

type conntrackStats struct {
	Found         float64
	Invalid       float64
	Ignore        float64
	Insert        float64
	InsertFailed  float64
	Drop          float64
	EarlyDrop     float64
	Error         float64
	SearchRestart float64
}
