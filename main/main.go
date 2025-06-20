package main

import (
	"fmt"
	"os"

	"github.com/niclabs/Observatorio/dataAnalyzer"
	"github.com/niclabs/Observatorio/dataCollector"
	"github.com/niclabs/Observatorio/geoIPUtils"
	"gopkg.in/yaml.v2"
)

// Config represents the structure of the configuration file used by the application.
// It contains settings for runtime arguments, database connection, and GeoIP database paths.
type Config struct {
	RunArguments struct {
		InputFilepath     string   `yaml:"inputfilepath"`
		DontProbeFilepath string   `yaml:"dontprobefilepath"`
		Verbose           bool     `yaml:"verbose"`
		Concurrency       int      `yaml:"concurrency"`
		DropDatabase      bool     `yaml:"dropdatabase"`
		Debug             bool     `yaml:"debug"`
		DnsServers        []string `yaml:"dnsservers"`
	} `yaml:"runargs"`
	Database struct {
		DatabaseName string `yaml:"dbname"`
		Username     string `yaml:"dbuser"`
		Password     string `yaml:"dbpass"`
		Host         string `yaml:"dbhost"`
		Port         int    `yaml:"dbport"`
	} `yaml:"database"`
	Geoip struct {
		GeoipPath            string `yaml:"geoippath"`
		GeoipAsnFilename     string `yaml:"geoipasnfilename"`
		GeoipCountryFilename string `yaml:"geoipcountryfilename"`
		GeoipLicenseKey      string `yaml:"geoiplicensekey"`
	} `yaml:"geoip"`
}

// CONFIG_FILE is the name of the configuration file to be loaded at startup.
var CONFIG_FILE = "config.yml"

// main is the entry point of the application.
// It loads the configuration from a YAML file, initializes the GeoIP databases,
// sets up the data collection process, starts data collection, and then analyzes the collected data.
func main() {

	//Read config file
	f, err := os.Open(CONFIG_FILE)
	if err != nil {
		fmt.Println("Can't open configuration file: " + err.Error())
		return
	}
	defer f.Close()

	var cfg Config
	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&cfg)
	if err != nil {
		fmt.Println("Can't decode configuration: " + err.Error())
		return
	}
	// Check if a DNS server is set in the config file
	if len(cfg.RunArguments.DnsServers) == 0 {
		fmt.Println("you must add at least one dns server in the config file.")
		return
	}

	// Initialize GeoIP databases
	var geoipDB = geoIPUtils.InitGeoIP(cfg.Geoip.GeoipPath, cfg.Geoip.GeoipCountryFilename, cfg.Geoip.GeoipAsnFilename, cfg.Geoip.GeoipLicenseKey)

	// Initialize data collection
	err = dataCollector.InitCollect(cfg.RunArguments.DontProbeFilepath, cfg.RunArguments.DropDatabase, cfg.Database.Username, cfg.Database.Password, cfg.Database.Host, cfg.Database.Port, cfg.Database.DatabaseName, geoipDB, cfg.RunArguments.DnsServers)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Start data collection
	runId := dataCollector.StartCollect(cfg.RunArguments.InputFilepath, cfg.RunArguments.Concurrency, cfg.Database.DatabaseName, cfg.Database.Username, cfg.Database.Password, cfg.Database.Host, cfg.Database.Port, cfg.RunArguments.Debug, cfg.RunArguments.Verbose)

	geoIPUtils.CloseGeoIP(geoipDB)
	// Analyze collected data
	fmt.Println("Analyzing Data...")
	dataAnalyzer.AnalyzeData(runId, cfg.Database.DatabaseName, cfg.Database.Username, cfg.Database.Password, cfg.Database.Host, cfg.Database.Port)

}
