package main

import (
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"strings"

	helpers "github.com/mcoops/go-cve/pkg"
	"golang.org/x/mod/semver"
)

var allCVEs []helpers.CVEs

var githubCVEs []helpers.CVEs
var nvdCVEs []helpers.CVEs

var symbolRegex = regexp.MustCompile("[\\W]+")

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

func doVersionCompare(ver string, cve helpers.CVEs) bool {
	if ver == "" {
		return true // no ver supplied can't match, always a match!
	}

	if string(ver[0]) != "v" {
		ver = "v" + ver
	}

	if cve.Exclude != nil && verCompare(ver, cve.Exclude) {
		return true
	}

	if cve.Include != nil && verCompare(ver, cve.Include) {
		return true
	}

	return false
}

func hardRegexMatch(refs []string, regex *regexp.Regexp) bool {
	for _, r := range refs {
		if regex.MatchString(r) {
			return true
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
			results := make(map[string]helpers.CVEs)

			searchLen := len(name)
			// Until we split out functionality into their own files, handle
			// each search differently

			// are there symbols (:.@) included?
			if searchLen < 15 && symbolRegex.MatchString(name) == false {
				// not enough variation
				// github do exact matches
				for _, s := range githubCVEs {
					if s.Description == name && doVersionCompare(ver, s) {
						results[s.ID] = s
						// results = append(results, s)
					}
				}

				// tollerate /[name]/ or .[name]. and variations, but not -[name]-
				// at this point it'll false positive too much
				refRegex := regexp.MustCompile("[/]" + name + "[/]")
				for _, s := range nvdCVEs {
					// do the first search for a token key
					// then it must exist in the references section
					if strings.Contains(s.Description, " "+name+" ") && hardRegexMatch(s.References, refRegex) {
						if doVersionCompare(ver, s) {
							results[s.ID] = s
							// results = append(results, s)
							break
						}
					}
				}

			} else {
				for _, s := range githubCVEs {
					if strings.Contains(s.Description, name) && doVersionCompare(ver, s) {
						results[s.ID] = s
						// results = append(results, s)
					}
				}

				for _, s := range nvdCVEs {
					// there's enough variation where it's optional if it exists in references
					if strings.Contains(s.Description, name) || contains(s.References, name) {
						if doVersionCompare(ver, s) {
							// results = append(results, s)
							results[s.ID] = s
						}
					}
				}
			}

			// make array of results
			out := make([]helpers.CVEs, 0, len(results))
			for _, value := range results {
				out = append(out, value)
			}
			json.NewEncoder(w).Encode(out)
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
	helpers.GetGithub(&githubCVEs)
	// for i := 2002; i < 2022; i++ {
	log.Println("Syncing NVD")

	helpers.GetNvd(&nvdCVEs)

	handleRequests()
}
