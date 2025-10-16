package analysis

// buildAssetInventory construye el inventario de assets.
func (a *Analyzer) buildAssetInventory() *AssetInventory {
	inventory := &AssetInventory{
		Domains:     []Domain{},
		RestAPIs:    []string{},
		GraphQLAPIs: []string{},
	}

	// Contar dominios
	domains := a.FilterArtifacts("domain")
	inventory.TotalDomains = len(domains)

	activeDomains := 0
	for _, domain := range domains {
		if domain.Active {
			activeDomains++
		}

		// Agregar a lista (limitar a primeros 100)
		if len(inventory.Domains) < 100 {
			inventory.Domains = append(inventory.Domains, Domain{
				Name:     domain.Value,
				Active:   domain.Active,
				Verified: domain.Active, // Si está activo, está verificado
				Source:   domain.Tool,
			})
		}
	}
	inventory.ActiveDomains = activeDomains

	// Calcular subdominios (restar dominio principal solo si hay dominios)
	if inventory.TotalDomains > 0 {
		inventory.TotalSubdomains = inventory.TotalDomains - 1
	}
	if activeDomains > 0 {
		inventory.ActiveSubdomains = activeDomains - 1
	}

	// Contar recursos web
	inventory.HTMLPages = len(a.FilterBySubtype("resource", "html"))
	inventory.JavaScripts = len(a.FilterBySubtype("resource", "javascript"))
	inventory.Stylesheets = len(a.FilterBySubtype("resource", "css"))
	inventory.Images = len(a.FilterBySubtype("resource", "image"))
	inventory.Documents = len(a.FilterBySubtype("resource", "document"))

	// Otros recursos
	fonts := len(a.FilterBySubtype("resource", "font"))
	videos := len(a.FilterBySubtype("resource", "video"))
	archives := len(a.FilterBySubtype("resource", "archive"))
	inventory.OtherResources = fonts + videos + archives

	// APIs
	restAPIs := a.FilterBySubtype("endpoint", "rest")
	for _, api := range restAPIs {
		if len(inventory.RestAPIs) < 50 { // Limitar
			inventory.RestAPIs = append(inventory.RestAPIs, api.Value)
		}
	}

	graphqlAPIs := a.FilterBySubtype("endpoint", "graphql")
	for _, api := range graphqlAPIs {
		if len(inventory.GraphQLAPIs) < 50 {
			inventory.GraphQLAPIs = append(inventory.GraphQLAPIs, api.Value)
		}
	}

	// Certificados
	inventory.Certificates = len(a.FilterArtifacts("certificate"))

	return inventory
}
