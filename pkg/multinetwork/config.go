// SPDX-License-Identifier: APACHE-2.0

package multinetwork

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/gorillamux"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"
)

// NetworkConfigSchema is the OpenAPI schema as a string.
const NetworkConfigSchema = `
openapi: 3.0.0
info:
  title: Network Configuration
  version: 0.0.1
paths:
  /:
    post:
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/NetworkConfig'
      responses:
        "200":
          description: OK
components:
  schemas:
    NetworkConfig:
      type: object
      properties:
        name:
          type: string
          description: Name of the additional network interface (valid Linux interface name).
          pattern: "^[a-zA-Z0-9_-]{1,15}$"
        ips:
          type: array
          items:
            type: string
            pattern: "^([0-9]{1,3}\\.){3}[0-9]{1,3}(\\/([0-9]|[1-2][0-9]|3[0-2]))?$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(\\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))?$"
          description: Array of IP addresses and subnet masks in CIDR notation.
        routes:
          type: array
          items:
            type: object
            properties:
              destination:
                type: string
                pattern: "^([0-9]{1,3}\\.){3}[0-9]{1,3}(\\/([0-9]|[1-2][0-9]|3[0-2]))?$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(\\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))?$"
              gateway:
                type: string
            required:
              - destination
              - gateway
            description: Array of static routes.
        dns:
          type: array
          items:
            type: string
          description: IPv4 or IPv6 address of DNS server.
`

// TODO Generate code and keep in sync golang types on schema
type NetworkConfig struct {
	Name   string   `json:"name"`
	IPs    []string `json:"ips"`
	Routes []Route  `json:"routes"`
	DNS    []string `json:"dns"`
}

type Route struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
}

// ValidateConfig validates the data in a runtime.RawExtension against the OpenAPI schema.
func ValidateConfig(raw *runtime.RawExtension) (*NetworkConfig, error) {
	if raw == nil || raw.Raw == nil {
		return nil, nil
	}
	// Check if raw.Raw is empty
	if len(raw.Raw) == 0 {
		return nil, nil
	}
	var data map[string]interface{}
	if err := yaml.Unmarshal(raw.Raw, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML data: %w", err)
	}

	ctx := context.Background()
	loader := &openapi3.Loader{Context: ctx, IsExternalRefsAllowed: true}

	doc, err := loader.LoadFromData([]byte(NetworkConfigSchema))
	if err != nil {
		return nil, fmt.Errorf("failed to load OpenAPI schema: %w", err)
	}

	err = doc.Validate(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to validate OpenAPI schema: %w", err)
	}

	router, err := gorillamux.NewRouter(doc)
	if err != nil {
		return nil, fmt.Errorf("failed to create router: %v", err)
	}

	// Convert data to JSON for the request body
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal data to JSON: %w", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, "/", bytes.NewReader(jsonData)) // Using root path
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json") // Set Content-Type header

	// Find route
	route, pathParams, err := router.FindRoute(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to find http route: %v", err)
	}
	// Validate request
	requestValidationInput := &openapi3filter.RequestValidationInput{
		Request:    httpReq,
		PathParams: pathParams,
		Route:      route,
	}

	if err := openapi3filter.ValidateRequest(ctx, requestValidationInput); err != nil {
		return nil, fmt.Errorf("OpenAPI schema validation error: %w", err)
	}

	// Unmarshal validated data into NetworkConfig struct
	var config NetworkConfig
	if err := json.Unmarshal(jsonData, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal validated data into NetworkConfig: %w", err)
	}

	return &config, nil

}
