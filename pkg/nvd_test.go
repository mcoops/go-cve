package helpers

import (
	"encoding/json"
	"io/ioutil"
	"testing"
)

func TestExtractCWE(t *testing.T) {
	testDataRaw, _ := ioutil.ReadFile("testdata/cwe.json")
	var allCVEs []CVEs
	var cve CVE
	json.Unmarshal(testDataRaw, &cve)
	expected := []string{"CWE-200", "CWE-120", "CWE-190"}
	loadCVE(&allCVEs, &cve)
	foundCWEs := make([]string, 0)
	for _, cve := range allCVEs {
		for _, cwe := range cve.CWEs {
			foundCWEs = append(foundCWEs, cwe)
		}
	}
	for _, expect := range expected {
		if !contains(foundCWEs, expect) {
			t.Errorf("Expected to find %s in data but didn't. I found %s", expect, foundCWEs)
		}
	}
	for _, found := range foundCWEs {
		if found == "NVD-CWE-Other" {
			t.Errorf("Found useless CWE string in CWES: %s", found)
		}
	}

}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
