package helpers

type CVE struct {
	CVE_Items []struct {
		CVE struct {
			CVE_data_meta struct {
				ID string `json:"ID"`
			}
			ProblemType struct {
				Problemtype_data []struct {
					Description []struct {
						Value string `json:""value"`
					}
				}
			}
			Description struct {
				Description_data []struct {
					Value string `json:"value"`
				}
			}
			References struct {
				Reference_data []struct {
					URL string `json:"url"`
				}
			}
		}
		Configurations struct {
			Nodes []struct {
				Children *[]struct {
					Cpe_match []struct {
						Vulnerable bool `json:"vulnerable"`
						// CPE                   string  `json:"cpe23Uri"`
						VersionEndExcluding   *string `json:"versionEndExcluding"`
						VersionEndIncluding   *string `json:"versionEndIncluding"`
						VersionStartExcluding *string `json:"versionStartExcluding"`
						VersionStartIncluding *string `json:"versionStartIncluding"`
					}
				}
				Cpe_match *[]struct {
					Vulnerable bool `json:"vulnerable"`
					// CPE                   string  `json:"cpe23Uri"`
					VersionEndExcluding   *string `json:"versionEndExcluding"`
					VersionEndIncluding   *string `json:"versionEndIncluding"`
					VersionStartExcluding *string `json:"versionStartExcluding"`
					VersionStartIncluding *string `json:"versionStartIncluding"`
				}
			}
		}
	}
}

type Versions struct {
	Start string
	End   string
}

type CVEs struct {
	ID          string
	Description string
	// CPEs        []string
	References []string
	Excludings []string
	Exclude    []Versions
	Includings []string
	Include    []Versions
}
