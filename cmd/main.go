package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	helpers "github.com/mcoops/go-cve/pkg"
	"golang.org/x/mod/semver"
)

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
		log.Println("Received search nvr: " + nvr)
		w.Header().Set("Content-Type", "application/json")

		if nvr != "" {
			var req []string
			if nvr[:1] == "@" {
				req = strings.Split(nvr[1:], "@")
			} else {
				req = strings.Split(nvr, "@")
			}

			name := req[0]
			ver := ""
			if len(req) > 1 {
				ver = req[1]
			}
			results := make([]helpers.CVEs, 0)
			for _, s := range allCVEs {
				// double check as the nvd results will be huge, github don't use references
				// we want to try and filter out small searches and we use contains later
				// TODO: on move to sql tag where the results come from
				// TODO: fix this hack
				if len(name) <= 4 {
					if s.References != nil {
						// search for the token
						if strings.Contains(s.Description, " "+name+" ") == false {
							continue
						}
					} else { // github, exact match name the package
						if s.Description != name {
							continue
						}
					}
				}

				if strings.Contains(s.Description, name) || contains(s.References, name) {
					// do version
					if ver != "" {
						// check if leading 'v'
						if string(ver[0]) != "v" {
							ver = "v" + ver
						}
						if s.Exclude != nil {
							if verCompare(ver, s.Exclude) {
								results = append(results, s)
							}
						}
						// hmmmm dunno if we care
						// TODO: checkout how mitre's inclusions actually work
						if s.Include != nil {
							if verCompare(ver, s.Exclude) {
								results = append(results, s)
							}
						}

					} else {
						results = append(results, s)
					}
				}
			}
			json.NewEncoder(w).Encode(results)
		}
	}

}

func handleRequests() {
	http.HandleFunc("/search", mainSearch)
	log.Printf("Starting server on 7777\nQuery port on localhost:7777/search?nvr=[package]@[version]")
	log.Fatal(http.ListenAndServe(":7777", nil))
}

func main() {
	log.Println("Syncing GitHub")
	helpers.GetGithub(&allCVEs)
	// for i := 2002; i < 2022; i++ {
	log.Println("Syncing NVD")

	helpers.GetNvd(&allCVEs)

	handleRequests()
}
