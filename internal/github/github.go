package github

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

type GitHub struct{}

const githubURL string = "https://api.github.com/graphql"

var GITHUB_TOKEN string = ""

type GitHubStore struct {
	gorm.Model
	CWEs  string
	CVEID string
	Name  string
	Range string
}

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

func init() {
	var exists bool
	GITHUB_TOKEN, exists = os.LookupEnv("GITHUB_AUTH_TOKEN")

	if exists == false {
		log.Info().Msg("GitHub: GITHUB_AUTH_TOKEN not set, cannot sync github")
		return
	}
}

func (gh GitHub) InitDB(db *gorm.DB) {
	log.Info().Msg("GitHub: Initialised table")
	db.AutoMigrate(&GitHubStore{})
}

func (gh GitHub) Gather(db *gorm.DB) {
	var count int64
	var cveList []GitHubStore

	if GITHUB_TOKEN == "" {
		return
	}

	db.Model(&(GitHubStore{})).Count(&count)

	if count == 0 {
		log.Info().Msg("GitHub: Doing batched insert")
	} else {
		log.Info().Msg("GitHub: Doing insert/update")
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

		request.Header.Add("Authorization", "token "+GITHUB_TOKEN)
		request.Header.Add("Accept-Encoding", "gzip")

		resp, err := client.Do(request)

		if err != nil {
			log.Fatal().Msg(err.Error())
		}

		defer resp.Body.Close()

		reader, err := gzip.NewReader(resp.Body)

		defer reader.Close()

		bb := new(bytes.Buffer)
		_, err = bb.ReadFrom(reader)

		var data GHData

		json.Unmarshal(bb.Bytes(), &data)

		for _, d := range data.Data.SecurityVulnerabilities.Nodes {

			s := GitHubStore{Name: d.Package.Name}

			for _, ids := range d.Advisory.Identifiers {
				if ids.Type == "CVE" {
					s.CVEID = ids.Value
				}
			}
			if s.CVEID == "" { // if no cve, then load the ghsa
				for _, ids := range d.Advisory.Identifiers {
					if ids.Type == "GHSA" {
						s.CVEID = ids.Value
					}
				}
			}

			var cwes []string

			for _, cwe := range d.Advisory.CWES.Edges {
				cwes = append(cwes, cwe.Node.CWEID)
			}

			s.CWEs = strings.Join(cwes, ",")
			s.Range = d.VulnerableVersionRange

			// if string(d.VulnerableVersionRange[0]) == "<" {
			// 	c.Exclude = append(c.Exclude, Versions{End: d.VulnerableVersionRange[2:]})
			// } else if string(d.VulnerableVersionRange[0]) == "=" {
			// 	c.Exclude = append(c.Exclude, Versions{
			// 		Start: d.VulnerableVersionRange[2:],
			// 		End:   d.VulnerableVersionRange[2:],
			// 	})
			// } else { // assume >=, <
			// 	ver := strings.Split(d.VulnerableVersionRange, ",")

			// 	if len(ver) > 1 {

			// 		if strings.Index(ver[0], ">=") != -1 {
			// 			c.Exclude = append(c.Exclude, Versions{
			// 				Start: strings.TrimSpace(strings.Replace(ver[0], ">=", "", 1)),
			// 				End:   strings.TrimSpace(strings.Replace(ver[1], "<", "", 1)),
			// 			})
			// 			// treat it as an inclusion ==
			// 			inclusion := strings.TrimSpace(strings.Replace(ver[0], ">=", "", 1))
			// 			c.Include = append(c.Include, Versions{
			// 				Start: inclusion,
			// 				End:   inclusion,
			// 			})
			// 		} else {
			// 			// >
			// 			c.Exclude = append(c.Exclude, Versions{
			// 				Start: strings.TrimSpace(strings.Replace(ver[0], ">", "", 1)),
			// 				End:   strings.TrimSpace(strings.Replace(ver[1], "<", "", 1)),
			// 			})
			// 		}

			// 	}
			// }
			var g GitHubStore
			if count > 0 {
				db.FirstOrCreate(&g, s)
			} else {
				cveList = append(cveList, s)
			}
		}

		if data.Data.SecurityVulnerabilities.PageInfo.HasNextPage == false {
			break
		} else {
			afterTxt = ", after: \"" + data.Data.SecurityVulnerabilities.PageInfo.EndCursor + "\""
		}

	}
	if count == 0 {
		db.CreateInBatches(&cveList, 100)
	}
}

func (gh GitHub) Update(db *gorm.DB) {
}

func (gh GitHub) Search(db *gorm.DB, term string, version string) {

}
