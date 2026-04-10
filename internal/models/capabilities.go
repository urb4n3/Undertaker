package models

// APICapability maps a Win32/NT API to a capability category.
type APICapability struct {
	API        string `json:"api"`
	DLL        string `json:"dll"`
	Capability string `json:"capability"`
	TechniqueID string `json:"technique_id,omitempty"`
}
