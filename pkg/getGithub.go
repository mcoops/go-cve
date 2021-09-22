package helpers

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

const githubURL string = "https://api.github.com/graphql"

type GHData struct {
	Data struct {
		SecurityVulnerabilities struct {
			PageInfo struct {
				HasNextPage bool   `json:"hasNextPage"`
				EndCursor   string `json:"endCursor"`
			}
			Nodes []struct {
				Package struct {
					Name string `json:"Name"`
				}
				VulnerableVersionRange string `json:"vulnerableVersionRange"`
				Advisory               struct {
					CVSS struct {
						Score float32 `json:"score"`
					}
					Identifiers []struct {
						Type  string `json:"type"`
						Value string `json:"value"`
					}
					CWES struct {
						Edges []struct {
							Node struct {
								CWEID string `json:"cweId"`
							}
						}
					}
				}
			}
		}
	}
}

func GetGithub(allCVEs *[]CVEs) {

	github_token, exists := os.LookupEnv("GITHUB_AUTH_TOKEN")

	if exists == false {
		log.Println("GITHUB_AUTH_TOKEN not set, cannot sync github")
		return
	}

	query := `
	{
		securityVulnerabilities(first: 100 %s) {
		  pageInfo {
			hasNextPage
			startCursor
			endCursor
		  }
		  nodes {
			package {
			  name
			}
			vulnerableVersionRange
			advisory {
				cvss {
					score
				}
			  cwes(first: 5) {
				edges {
				  node {
					cweId
				  }
				}
			  }
			  identifiers {
				  type
				  value
			  }
			}
		  }
		}
	  }
	  `
	//			  summary
	client := http.Client{}

	afterTxt := ""

	for {
		tosend := map[string]string{"query": fmt.Sprintf(query, afterTxt)}

		j, _ := json.Marshal(tosend)

		request, _ := http.NewRequest("POST", githubURL, bytes.NewBuffer(j))

		request.Header.Add("Authorization", "token "+github_token)
		request.Header.Add("Accept-Encoding", "gzip")

		resp, err := client.Do(request)

		if err != nil {
			log.Fatalln(err)
		}

		defer resp.Body.Close()

		reader, err := gzip.NewReader(resp.Body)

		defer reader.Close()

		bb := new(bytes.Buffer)
		_, err = bb.ReadFrom(reader)

		var data GHData

		json.Unmarshal(bb.Bytes(), &data)

		for _, d := range data.Data.SecurityVulnerabilities.Nodes {

			cve := ""
			for _, ids := range d.Advisory.Identifiers {
				if ids.Type == "CVE" {
					cve = ids.Value
				}
			}
			if cve == "" { // if no cve, then load the ghsa
				for _, ids := range d.Advisory.Identifiers {
					if ids.Type == "GHSA" {
						cve = ids.Value
					}
				}
			}

			c := CVEs{
				ID:          cve,
				Description: d.Package.Name,
				Impact:      d.Advisory.CVSS.Score,
			}

			for _, cwe := range d.Advisory.CWES.Edges {
				c.CWEs = append(c.CWEs, cwe.Node.CWEID)
			}

			if string(d.VulnerableVersionRange[0]) == "<" {
				c.Exclude = append(c.Exclude, Versions{End: d.VulnerableVersionRange[2:]})
			} else if string(d.VulnerableVersionRange[0]) == "=" {
				c.Exclude = append(c.Exclude, Versions{
					Start: d.VulnerableVersionRange[2:],
					End:   d.VulnerableVersionRange[2:],
				})
			} else { // assume >=, <
				ver := strings.Split(d.VulnerableVersionRange, ",")

				if len(ver) > 1 {

					if strings.Index(ver[0], ">=") != -1 {
						c.Exclude = append(c.Exclude, Versions{
							Start: strings.TrimSpace(strings.Replace(ver[0], ">=", "", 1)),
							End:   strings.TrimSpace(strings.Replace(ver[1], "<", "", 1)),
						})
						// treat it as an inclusion ==
						inclusion := strings.TrimSpace(strings.Replace(ver[0], ">=", "", 1))
						c.Include = append(c.Include, Versions{
							Start: inclusion,
							End:   inclusion,
						})
					} else {
						// >
						c.Exclude = append(c.Exclude, Versions{
							Start: strings.TrimSpace(strings.Replace(ver[0], ">", "", 1)),
							End:   strings.TrimSpace(strings.Replace(ver[1], "<", "", 1)),
						})
					}

				}
			}

			*allCVEs = append(*allCVEs, c)
		}

		if data.Data.SecurityVulnerabilities.PageInfo.HasNextPage == false {
			break
		} else {
			afterTxt = ", after: \"" + data.Data.SecurityVulnerabilities.PageInfo.EndCursor + "\""
		}
	}
}
