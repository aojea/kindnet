package apis

import _ "embed"

// KindnetYamlCRD TODO see if we can get the gocode directly
//
//go:embed kindnet.io_configurations.yaml
var KindnetYamlCRD []byte
