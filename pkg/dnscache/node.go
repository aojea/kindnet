
package dnscache

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	kubeletconfigv1beta1 "k8s.io/kubelet/config/v1beta1"
	utilio "k8s.io/utils/io"
)

const (
	maxResolvConfLength = 10 * 1 << 20 // 10MB
)

// returns a status 200 response from the /configz endpoint or nil if fails
func getKubeletConfigz(ctx context.Context, nodeName string) (*kubeletconfigv1beta1.KubeletConfiguration, error) {
	// create a Kubernetes client
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	config.Timeout = 3 * time.Second

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	req := client.CoreV1().RESTClient().Get().
		Resource("nodes").Name(nodeName).SubResource("proxy").Suffix("configz")

	// This hack because /configz reports the following structure:
	// {"kubeletconfig": {the JSON representation of kubeletconfigv1beta1.KubeletConfiguration}}
	type configzWrapper struct {
		ComponentConfig kubeletconfigv1beta1.KubeletConfiguration `json:"kubeletconfig"`
	}

	configz := configzWrapper{}
	var respBody []byte

	err = wait.PollUntilContextTimeout(ctx, 5*time.Second, 300*time.Second, true, func(ctx context.Context) (bool, error) {
		result, err := req.DoRaw(ctx)
		if err != nil {
			klog.Infof("Could not get kubelet config for node %v: %v", nodeName, err)
			return false, nil
		}

		err = json.Unmarshal(result, &configz)
		if err != nil {
			klog.Infof("kubelet configz fail to unmarshal config %s: %v", string(respBody), err)
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return nil, err
	}

	return &configz.ComponentConfig, nil
}

// https://github.com/kubernetes/kubernetes/blob/2108e54f5249c6b3b0c9f824314cb5f33c01e3f4/pkg/kubelet/network/dns/dns.go#L176
// parseResolvConf reads a resolv.conf file from the given reader, and parses
// it into nameservers, searches and options, possibly returning an error.
func parseResolvConf(resolvPath string) (nameservers []string, searches []string, options []string, err error) {
	f, err := os.Open(resolvPath)
	if err != nil {
		klog.ErrorS(err, "Could not open resolv conf file.", "path", resolvPath)
		return nil, nil, nil, err
	}
	defer f.Close()

	file, err := utilio.ReadAtMost(f, maxResolvConfLength)
	if err != nil {
		return nil, nil, nil, err
	}

	// Lines of the form "nameserver 1.2.3.4" accumulate.
	nameservers = []string{}

	// Lines of the form "search example.com" overrule - last one wins.
	searches = []string{}

	// Lines of the form "option ndots:5 attempts:2" overrule - last one wins.
	// Each option is recorded as an element in the array.
	options = []string{}

	var allErrors []error
	lines := strings.Split(string(file), "\n")
	for l := range lines {
		trimmed := strings.TrimSpace(lines[l])
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "nameserver" {
			if len(fields) >= 2 {
				nameservers = append(nameservers, fields[1])
			} else {
				allErrors = append(allErrors, fmt.Errorf("nameserver list is empty "))
			}
		}
		if fields[0] == "search" {
			// Normalise search fields so the same domain with and without trailing dot will only count once, to avoid hitting search validation limits.
			searches = []string{}
			for _, s := range fields[1:] {
				if s != "." {
					searches = append(searches, strings.TrimSuffix(s, "."))
				}
			}
		}
		if fields[0] == "options" {
			options = appendOptions(options, fields[1:]...)
		}
	}

	return nameservers, searches, options, utilerrors.NewAggregate(allErrors)
}

// appendOptions appends options to the given list, but does not add duplicates.
// append option will overwrite the previous one either in new line or in the same line.
func appendOptions(options []string, newOption ...string) []string {
	var optionMap = make(map[string]string)
	for _, option := range options {
		optName := strings.Split(option, ":")[0]
		optionMap[optName] = option
	}
	for _, option := range newOption {
		optName := strings.Split(option, ":")[0]
		optionMap[optName] = option
	}

	options = []string{}
	for _, v := range optionMap {
		options = append(options, v)
	}
	return options
}
