package v1alpha1

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:subresource:status

// Configuration describes an Dapr configuration setting.
type Configuration struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +optional
	Spec ConfigurationSpec `json:"spec,omitempty"`
	// +optional
	Status ConfigurationStatus `json:"status,omitempty"`
}

// ConfigurationSpec is the spec for a configuration.
type ConfigurationSpec struct {
	// +optional
	NetworkPolicy Feature `json:"networkPolicy,omitempty"`
	// +optional
	AdminNetworkPolicy Feature `json:"adminNetworkPolicy,omitempty"`
	// +optional
	BaselineAdminNetworkPolicy Feature `json:"baselineAdminNetworkPolicy,omitempty"`
	// +optional
	Masquerade MasqueradeConfig `json:"masquerade,omitempty"`
}

type MasqueradeConfig struct {
	Feature               `json:",inline"`
	NonMasqueradeNetworks []string `json:"nonMasqueradeNetworks,omitempty"`
	OutputInterfaces      []string `json:"outputInterfaces,omitempty"`
}

type Feature struct {
	Enable       bool            `json:"enable"`
	NodeSelector v1.NodeSelector `json:"nodeSelector,omitempty"`
}

// ConfigurationStatus is the status for a configuration.
type ConfigurationStatus struct {
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,2,rep,name=conditions"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ConfigurationList
type ConfigurationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []Configuration `json:"items"`
}
