package strictly

import (
	"time"
)

// SecurityHubFindingsImported EventBridge Event Format
type SecurityHubFindingsImported struct {
	Version    string    `json:"version"`
	ID         string    `json:"id"`
	DetailType string    `json:"detail-type"`
	Source     string    `json:"source"`
	Account    string    `json:"account"`
	Time       time.Time `json:"time"`
	Region     string    `json:"region"`
	Resources  []string  `json:"resources"`
	Detail     struct {
		Findings struct {
			ASFF
		} `json:"findings"`
	} `json:"detail"`
}

// SecurityHubFindingsCustomAction EventBridge Event Format
type SecurityHubFindingsCustomAction struct {
	Version    string    `json:"version"`
	ID         string    `json:"id"`
	DetailType string    `json:"detail-type"`
	Source     string    `json:"source"`
	Account    string    `json:"account"`
	Time       time.Time `json:"time"`
	Region     string    `json:"region"`
	Resources  []string  `json:"resources"`
	Detail     struct {
		Actionname        string `json:"actionName"`
		Actiondescription string `json:"actionDescription"`
		Findings          []struct {
			ASFF
		} `json:"findings"`
	} `json:"detail"`
}

// SecurityHubInsightResults EventBridge Event Format
type SecurityHubInsightResults struct {
	Version    string    `json:"version"`
	ID         string    `json:"id"`
	DetailType string    `json:"detail-type"`
	Source     string    `json:"source"`
	Account    string    `json:"account"`
	Time       time.Time `json:"time"`
	Region     string    `json:"region"`
	Resources  []string  `json:"resources"`
	Detail     struct {
		Actionname        string        `json:"actionName"`
		Actiondescription string        `json:"actionDescription"`
		Insightarn        string        `json:"insightArn"`
		Insightname       string        `json:"insightName"`
		Resulttype        string        `json:"resultType"`
		NumberOfResults   string        `json:"number of results"`
		Insightresults    []interface{} `json:"insightResults"`
	} `json:"detail"`
}
