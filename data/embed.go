package data

import _ "embed"

//go:embed ioc_patterns.json
var IOCPatterns []byte

//go:embed string_filters.json
var StringFilters []byte

//go:embed api_capabilities.json
var APICapabilities []byte

//go:embed script_capabilities.json
var ScriptCapabilities []byte

//go:embed log_keywords.json
var LogKeywords []byte
