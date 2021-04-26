package nvd

import "gorm.io/gorm"

type NVD struct{}

var nvdURL string = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-"

type NVDStore struct {
	gorm.Model
	CWEs        string
	CVEID       string
	Description string
	References  string
}
