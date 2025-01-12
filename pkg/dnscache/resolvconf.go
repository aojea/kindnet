// SPDX-License-Identifier: APACHE-2.0

package dnscache

import (
	"fmt"
	"os"
	"strings"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/klog/v2"
	utilio "k8s.io/utils/io"
)

const maxResolvConfLength = 10 * 1 << 20 // 10MB
// https://github.com/kubernetes/kubernetes/blob/2108e54f5249c6b3b0c9f824314cb5f33c01e3f4/pkg/kubelet/network/dns/dns.go#L176
// parseResolvConf reads a resolv.conf file from the given reader, and parses
// it into nameservers, searches and options, possibly returning an error.
func parseResolvConf() (nameservers []string, searches []string, options []string, err error) {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		klog.ErrorS(err, "Could not open resolv conf file.")
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
