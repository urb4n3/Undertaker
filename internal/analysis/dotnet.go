package analysis

import (
	"fmt"

	peparser "github.com/saferwall/pe"
	"github.com/urb4n3/undertaker/internal/models"
)

// ExtractDotNetMetadata extracts .NET CLR metadata from a parsed PE file.
// Returns nil if the file is not a .NET assembly.
func ExtractDotNetMetadata(pefile *peparser.File) *models.DotNetMetadata {
	if pefile == nil || !pefile.HasCLR {
		return nil
	}

	meta := &models.DotNetMetadata{}

	// Runtime version from the metadata header.
	meta.RuntimeVersion = pefile.CLR.MetadataHeader.Version

	stringsStream := pefile.CLR.MetadataStreams["#Strings"]

	// Extract classes and namespaces from the TypeDef table.
	if table, ok := pefile.CLR.MetadataTables[peparser.TypeDef]; ok && table != nil {
		if rows, ok := table.Content.([]peparser.TypeDefTableRow); ok {
			meta.Classes, meta.Namespaces = extractClassesAndNamespaces(pefile, rows, stringsStream)
		}
	}

	// Extract method names and associate with classes.
	if table, ok := pefile.CLR.MetadataTables[peparser.MethodDef]; ok && table != nil {
		if rows, ok := table.Content.([]peparser.MethodDefTableRow); ok {
			associateMethods(pefile, meta, rows, stringsStream)
		}
	}

	// Extract assembly references.
	if table, ok := pefile.CLR.MetadataTables[peparser.AssemblyRef]; ok && table != nil {
		if rows, ok := table.Content.([]peparser.AssemblyRefTableRow); ok {
			for _, row := range rows {
				name := resolveString(pefile, row.Name, stringsStream)
				if name != "" {
					ver := fmt.Sprintf("%d.%d.%d.%d",
						row.MajorVersion, row.MinorVersion,
						row.BuildNumber, row.RevisionNumber)
					meta.AssemblyRefs = append(meta.AssemblyRefs, name+" v"+ver)
				}
			}
		}
	}

	// Extract managed resources.
	if table, ok := pefile.CLR.MetadataTables[peparser.ManifestResource]; ok && table != nil {
		if rows, ok := table.Content.([]peparser.ManifestResourceTableRow); ok {
			for _, row := range rows {
				name := resolveString(pefile, row.Name, stringsStream)
				if name != "" {
					meta.Resources = append(meta.Resources, models.DotNetResource{
						Name: name,
						Size: row.Offset, // Offset field — size not directly available.
					})
				}
			}
		}
	}

	return meta
}

func extractClassesAndNamespaces(pefile *peparser.File, rows []peparser.TypeDefTableRow, stringsStream []byte) ([]models.DotNetClass, []string) {
	var classes []models.DotNetClass
	nsSet := make(map[string]bool)

	for _, row := range rows {
		ns := resolveString(pefile, row.TypeNamespace, stringsStream)
		name := resolveString(pefile, row.TypeName, stringsStream)

		// Skip the <Module> pseudo-class.
		if name == "<Module>" || name == "" {
			continue
		}

		classes = append(classes, models.DotNetClass{
			Namespace: ns,
			Name:      name,
		})

		if ns != "" && !nsSet[ns] {
			nsSet[ns] = true
		}
	}

	var namespaces []string
	for ns := range nsSet {
		namespaces = append(namespaces, ns)
	}

	return classes, namespaces
}

// associateMethods links methods to their owning class using MethodList indices.
func associateMethods(pefile *peparser.File, meta *models.DotNetMetadata, methodRows []peparser.MethodDefTableRow, stringsStream []byte) {
	if len(meta.Classes) == 0 || len(methodRows) == 0 {
		return
	}

	// Collect all method names.
	methodNames := make([]string, len(methodRows))
	for i, row := range methodRows {
		methodNames[i] = resolveString(pefile, row.Name, stringsStream)
	}

	// Get the TypeDef table to read MethodList boundaries.
	table, ok := pefile.CLR.MetadataTables[peparser.TypeDef]
	if !ok || table == nil {
		return
	}
	typeRows, ok := table.Content.([]peparser.TypeDefTableRow)
	if !ok {
		return
	}

	// classIdx tracks which non-<Module> class we're on.
	classIdx := 0
	for i := 0; i < len(typeRows); i++ {
		name := resolveString(pefile, typeRows[i].TypeName, stringsStream)
		if name == "<Module>" || name == "" {
			continue
		}
		if classIdx >= len(meta.Classes) {
			break
		}

		// Determine method range for this type.
		methodStart := int(typeRows[i].MethodList) - 1 // 1-based index.
		methodEnd := len(methodRows)
		if i+1 < len(typeRows) {
			methodEnd = int(typeRows[i+1].MethodList) - 1
		}

		if methodStart < 0 {
			methodStart = 0
		}
		if methodEnd > len(methodNames) {
			methodEnd = len(methodNames)
		}

		for j := methodStart; j < methodEnd; j++ {
			if methodNames[j] != "" {
				meta.Classes[classIdx].Methods = append(meta.Classes[classIdx].Methods, methodNames[j])
			}
		}
		classIdx++
	}
}

// resolveString reads a null-terminated string from the #Strings heap at the given offset.
func resolveString(pefile *peparser.File, offset uint32, stringsStream []byte) string {
	if stringsStream == nil || offset == 0 {
		return ""
	}
	data := pefile.GetStringFromData(offset, stringsStream)
	return string(data)
}
