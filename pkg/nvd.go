package helpers

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
)

var nvdURL string = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-"

func GetNvd(allCVEs *[]CVEs) {
	for i := 2019; i < 2022; i++ {
		var cve CVE
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

		loadCVE(allCVEs, &cve)
	}
}

func loadCVE(allCVEs *[]CVEs, cve *CVE) {
	for _, c := range cve.CVE_Items {
		load_cve := CVEs{
			ID:          c.CVE.CVE_data_meta.ID,
			Description: c.CVE.Description.Description_data[0].Value,
		}
		var cwes []string
		for _, cweData := range c.CVE.ProblemType.Problemtype_data[0].Description {
			if !strings.HasPrefix("NVD-CWE-", cweData.Value) {
				cwes = append(cwes, cweData.Value)
			}
		}
		load_cve.CWEs = cwes
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

							load_cve.CPEs = append(load_cve.CPEs, cpe.CPE)
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

						load_cve.CPEs = append(load_cve.CPEs, cpe.CPE)
					}
				}
			}
		}

		for _, ref := range c.CVE.References.Reference_data {
			// normalise url because of synk
			url := ref.URL
			if strings.Contains(url, "SNYK") {
				// normalize to lower
				url = strings.ToLower(url)
			}
			load_cve.References = append(load_cve.References, url)
		}

		*allCVEs = append(*allCVEs, load_cve)
	}
}

func fileVersions(start *string, end *string) (Versions, error) {
	c := Versions{}
	if start != nil || end != nil {
		if start != nil {
			c.Start = *start
		}
		if end != nil {
			c.End = *end
		}
		return c, nil
	}
	return Versions{}, errors.New("no data")
}
