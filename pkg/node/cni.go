
package node

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"

	"k8s.io/klog/v2"
)

/* cni config management */
const (
	// cniConfigPath is where kindnetd will write the computed CNI config
	cniConfigPath = "/etc/cni/net.d"
	cniConfigFile = "10-kindnet.conflist"
	// cniConfig is static as it will get the values from the daemon
	cniConfig = `{
  "cniVersion": "0.4.0",
  "name": "kindnet",
  "plugins": [
    {
      "type": "cni-kindnet",
      "ranges": [
	    {{- range $i, $cidr := .PodCIDRs}}
	    {{- if gt $i 0 }},{{end}}
        "{{ $cidr }}"
      {{- end}}
      ],
      "capabilities": {"portMappings": true}
    }
  ]
}
`
)

func WriteCNIConfig(ranges []string) (err error) {
	// obtain the new config
	t, err := template.New("cni-json").Parse(cniConfig)
	if err != nil {
		return fmt.Errorf("failed to parse cni template: %v", err)
	}
	data := struct {
		PodCIDRs []string
	}{
		PodCIDRs: ranges,
	}

	var buf bytes.Buffer
	err = t.Execute(&buf, &data)
	if err != nil {
		return fmt.Errorf("failed to parse cni template: %w", err)
	}

	// If the file exists only write it if the content is different
	cniFile := filepath.Join(cniConfigPath, cniConfigFile)

	f1, err := os.Open(cniFile)
	if err == nil {
		defer f1.Close()
		// Calculate the MD5 checksum of the existing file
		h1 := md5.New()
		if _, err := io.Copy(h1, f1); err != nil {
			return fmt.Errorf("error calculating checksum for file %s: %w", cniFile, err)
		}
		// Calculate the MD5 checksum of the new content
		h2 := md5.New()
		if _, err := io.Copy(h2, bytes.NewReader(buf.Bytes())); err != nil {
			return fmt.Errorf("error calculating checksum for generated file: %w", err)
		}

		// Compare the checksums to write only if the file is different
		if bytes.Equal(h1.Sum(nil), h2.Sum(nil)) {
			return nil
		}
		_ = os.Remove(cniFile)
	}

	err = os.WriteFile(cniFile, buf.Bytes(), 0644)
	if err != nil {
		_ = os.Remove(cniFile)
		return err
	}
	klog.Infof("CNI config file succesfully written")
	return nil
}
