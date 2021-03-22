package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	helpers "github.com/mcoops/go-cve/pkg"
	"golang.org/x/mod/semver"
)

// https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2021.json.gz

var nvdURL string = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-"

var allCVEs []helpers.CVEs

func contains(s []string, e string) bool {
	for _, a := range s {
		if strings.Contains(a, e) {
			return true
		}
	}
	return false
}

func cleanVer(ver string) string {
	idx := strings.Index(ver, ".v")
	if idx != -1 {
		return ver[:idx]
	}
	return ver
}

func verCompare(needle string, compVersions []helpers.Versions) bool {
	for _, versions := range compVersions {
		// common case
		start := cleanVer(versions.Start)
		end := cleanVer(versions.End)

		if start == "" && end != "" {
			if semver.Compare(needle, "v"+end) == -1 {
				return true // vul
			}
		}

		if start != "" && end != "" {

			if semver.Compare(needle, "v"+start) == 1 {
				// needs to be less than end
				if semver.Compare(needle, "v"+end) == -1 {
					return true
				}
			}
		}

		if start != "" && start == end { // looking for == from github
			if semver.Compare(needle, "v"+start) == 0 {
				return true
			}
		}
	}

	return false
}

func mainSearch(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		nvr := r.URL.Query().Get("nvr")
		w.Header().Set("Content-Type", "application/json")

		if nvr != "" {
			req := strings.Split(nvr, "@")

			name := req[0]
			ver := ""
			if len(req) > 1 {
				ver = req[1]
			}

			for _, s := range allCVEs {
				// contains(s.CPEs, t) ||
				if strings.Contains(s.Description, name) || contains(s.References, name) {
					// do version
					if ver != "" {
						// check if leading 'v'
						if string(ver[0]) != "v" {
							ver = "v" + ver
						}
						if s.Exclude != nil {
							if verCompare(ver, s.Exclude) {
								json.NewEncoder(w).Encode(s)
							}
						}
						// hmmmm dunno if we care
						// TODO: checkout how mitre's inclusions actually work
						if s.Include != nil {
							if verCompare(ver, s.Exclude) {
								json.NewEncoder(w).Encode(s)
							}
						}

					} else {
						json.NewEncoder(w).Encode(s)
					}
				}
			}
		}
	}

}

func handleRequests() {
	http.HandleFunc("/search", mainSearch)
	log.Printf("Starting server on 7777\nQuery port on localhost:7777/search?nvr=[package]@[version]")
	log.Fatal(http.ListenAndServe(":7777", nil))
}

func fileVersions(start *string, end *string) (helpers.Versions, error) {
	c := helpers.Versions{}
	if start != nil || end != nil {
		if start != nil {
			c.Start = *start
		}
		if end != nil {
			c.End = *end
		}
		return c, nil
	}
	return helpers.Versions{}, errors.New("no data")
}

func main() {
	log.Println("Syncing GitHub")
	helpers.GetGithub(&allCVEs)
	// for i := 2002; i < 2022; i++ {
	log.Println("Syncing NVD")
	for i := 2019; i < 2022; i++ {
		var cve helpers.CVE
		url := fmt.Sprintf("%s%d.json.gz", nvdURL, i)

		client := new(http.Client)

		req, err := http.NewRequest("GET", url, nil)
		// resp, err := http.Get(url)
		if err != nil {
			log.Fatalln(err)
		}

		resp, err := client.Do(req)
		if err != nil {
			log.Fatalln(err)
		}

		defer resp.Body.Close()

		reader, err := gzip.NewReader(resp.Body)
		if err != nil {
			log.Fatalln(err)
		}
		defer reader.Close()

		// f, _ := os.Open(fmt.Sprintf("nvdcve-1.1-%d.json.gz", i))

		// defer f.Close()

		// reader, err := gzip.NewReader(f)
		// if err != nil {
		// 	log.Fatalln(err)
		// }

		// defer reader.Close()

		bb := new(bytes.Buffer)
		_, err = bb.ReadFrom(reader)

		json.Unmarshal(bb.Bytes(), &cve)

		for _, c := range cve.CVE_Items {
			load_cve := helpers.CVEs{
				ID:          c.CVE.CVE_data_meta.ID,
				Description: c.CVE.Description.Description_data[0].Value,
			}
			for _, o := range c.Configurations.Nodes {
				if o.Children != nil {
					for _, child := range *o.Children {
						for _, cpe := range child.Cpe_match {
							if cpe.Vulnerable {
								// load_cve.CPEs = append(load_cve.CPEs, cpe.CPE)

								// todo map start and end
								//  "versionStartIncluding" : "0.3.5",
								// 	"versionEndExcluding" : "0.3.5.10"
								// so after 0.3.5 but before 0.3.5.10
								// var exclude Excludings

								c, err := fileVersions(cpe.VersionStartExcluding, cpe.VersionEndExcluding)
								if err == nil {
									load_cve.Exclude = append(load_cve.Exclude, c)
								}

								// i doubt we care about includes but we'll see
								c, err = fileVersions(cpe.VersionStartIncluding, cpe.VersionEndIncluding)
								if err == nil {
									load_cve.Exclude = append(load_cve.Include, c)
								}
							}
						}
					}
				} else if o.Cpe_match != nil {
					for _, cpe := range *o.Cpe_match {
						if cpe.Vulnerable {
							c, err := fileVersions(cpe.VersionStartExcluding, cpe.VersionEndExcluding)
							if err == nil {
								load_cve.Exclude = append(load_cve.Exclude, c)
							}

							c, err = fileVersions(cpe.VersionStartIncluding, cpe.VersionEndIncluding)
							if err == nil {
								load_cve.Exclude = append(load_cve.Include, c)
							}
						}
					}
				}
			}

			for _, ref := range c.CVE.References.Reference_data {
				if strings.Contains(ref.URL, "github.com") || strings.Contains(ref.URL, "snyk") {
					load_cve.References = append(load_cve.References, ref.URL)
				}
			}

			allCVEs = append(allCVEs, load_cve)
		}
	}

	handleRequests()
}
