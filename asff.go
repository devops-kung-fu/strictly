package strictly

// ASFF Struct
type ASFF []struct {
	Action struct {
		ActionType       string `json:"ActionType,omitempty"`
		AwsAPICallAction struct {
			AffectedResources struct {
				String string `json:"string,omitempty"`
			} `json:"AffectedResources,omitempty"`
			API           string `json:"Api,omitempty"`
			CallerType    string `json:"CallerType,omitempty"`
			DomainDetails struct {
				Domain string `json:"Domain,omitempty"`
			} `json:"DomainDetails,omitempty"`
			FirstSeen       string `json:"FirstSeen,omitempty"`
			LastSeen        string `json:"LastSeen,omitempty"`
			RemoteIPDetails struct {
				City struct {
					CityName string `json:"CityName,omitempty"`
				} `json:"City,omitempty"`
				Country struct {
					CountryCode string `json:"CountryCode,omitempty"`
					CountryName string `json:"CountryName,omitempty"`
				} `json:"Country,omitempty"`
				IPaddressV4 string `json:"IpAddressV4,omitempty"`
				Geolocation struct {
					Lat float64 `json:"Lat,omitempty"`
					Lon float64 `json:"Lon,omitempty"`
				} `json:"Geolocation,omitempty"`
				Organization struct {
					Asn    int    `json:"Asn,omitempty"`
					AsnOrg string `json:"AsnOrg,omitempty"`
					Isp    string `json:"Isp,omitempty"`
					Org    string `json:"Org,omitempty"`
				} `json:"Organization,omitempty"`
			} `json:"RemoteIpDetails,omitempty"`
			ServiceName string `json:"ServiceName,omitempty"`
		} `json:"AwsApiCallAction,omitempty"`
		DNSRequestAction struct {
			Blocked  bool   `json:"Blocked,omitempty"`
			Domain   string `json:"Domain,omitempty"`
			Protocol string `json:"Protocol,omitempty"`
		} `json:"DnsRequestAction,omitempty"`
		NetworkConnectionAction struct {
			Blocked             bool   `json:"Blocked,omitempty"`
			ConnectionDirection string `json:"ConnectionDirection,omitempty"`
			LocalPortDetails    struct {
				Port     int    `json:"Port,omitempty"`
				PortName string `json:"PortName,omitempty"`
			} `json:"LocalPortDetails,omitempty"`
			Protocol        string `json:"Protocol,omitempty"`
			RemoteIPDetails struct {
				City struct {
					CityName string `json:"CityName,omitempty"`
				} `json:"City,omitempty"`
				Country struct {
					CountryCode string `json:"CountryCode,omitempty"`
					CountryName string `json:"CountryName,omitempty"`
				} `json:"Country,omitempty"`
				IPaddressV4 string `json:"IpAddressV4,omitempty"`
				Geolocation struct {
					Lat float64 `json:"Lat,omitempty"`
					Lon float64 `json:"Lon,omitempty"`
				} `json:"Geolocation,omitempty"`
				Organization struct {
					Asn    int    `json:"Asn,omitempty"`
					AsnOrg string `json:"AsnOrg,omitempty"`
					Isp    string `json:"Isp,omitempty"`
					Org    string `json:"Org,omitempty"`
				} `json:"Organization,omitempty"`
			} `json:"RemoteIpDetails,omitempty"`
			RemotePortDetails struct {
				Port     int    `json:"Port,omitempty"`
				PortName string `json:"PortName,omitempty"`
			} `json:"RemotePortDetails,omitempty"`
		} `json:"NetworkConnectionAction,omitempty"`
		PortProbeAction struct {
			Blocked          bool `json:"Blocked,omitempty"`
			PortProbeDetails []struct {
				LocalIPDetails struct {
					IPaddressV4 string `json:"IpAddressV4,omitempty"`
				} `json:"LocalIpDetails,omitempty"`
				LocalPortDetails struct {
					Port     int    `json:"Port,omitempty"`
					PortName string `json:"PortName,omitempty"`
				} `json:"LocalPortDetails,omitempty"`
				RemoteIPDetails struct {
					City struct {
						CityName string `json:"CityName,omitempty"`
					} `json:"City,omitempty"`
					Country struct {
						CountryCode string `json:"CountryCode,omitempty"`
						CountryName string `json:"CountryName,omitempty"`
					} `json:"Country,omitempty"`
					Geolocation struct {
						Lat float64 `json:"Lat,omitempty"`
						Lon float64 `json:"Lon,omitempty"`
					} `json:"GeoLocation,omitempty"`
					IPaddressV4  string `json:"IpAddressV4,omitempty"`
					Organization struct {
						Asn    int    `json:"Asn,omitempty"`
						AsnOrg string `json:"AsnOrg,omitempty"`
						Isp    string `json:"Isp,omitempty"`
						Org    string `json:"Org,omitempty"`
					} `json:"Organization,omitempty"`
				} `json:"RemoteIpDetails,omitempty"`
			} `json:"PortProbeDetails,omitempty"`
		} `json:"PortProbeAction,omitempty"`
	} `json:"Action,omitempty"`
	AWSaccountID string `json:"AwsAccountId"`
	Compliance   struct {
		RelatedRequirements []string `json:"RelatedRequirements,omitempty"`
		Status              string   `json:"Status,omitempty"`
		StatusReasons       []struct {
			Description string `json:"Description,omitempty"`
			ReasonCode  string `json:"ReasonCode,omitempty"`
		} `json:"StatusReasons,omitempty"`
	} `json:"Compliance,omitempty"`
	Confidence            int    `json:"Confidence,omitempty"`
	CreatedAt             string `json:"CreatedAt"`
	Criticality           int    `json:"Criticality,omitempty"`
	Description           string `json:"Description"`
	FindingProviderFields struct {
		Confidence      int `json:"Confidence,omitempty"`
		Criticality     int `json:"Criticality,omitempty"`
		RelatedFindings []struct {
			ProductARN string `json:"ProductArn,omitempty"`
			ID         string `json:"Id,omitempty"`
		} `json:"RelatedFindings,omitempty"`
		Severity struct {
			Label    string `json:"Label,omitempty"`
			Original string `json:"Original,omitempty"`
		} `json:"Severity,omitempty"`
		Types []string `json:"Types,omitempty"`
	} `json:"FindingProviderFields,omitempty"`
	FirstObservedAt string `json:"FirstObservedAt,omitempty"`
	GeneratorID     string `json:"GeneratorId"`
	ID              string `json:"Id"`
	LastObservedAt  string `json:"LastObservedAt,omitempty"`
	Malware         []struct {
		Name  string `json:"Name,omitempty"`
		Path  string `json:"Path,omitempty"`
		State string `json:"State,omitempty"`
		Type  string `json:"Type,omitempty"`
	} `json:"Malware,omitempty"`
	Network struct {
		DestinationDomain string `json:"DestinationDomain,omitempty"`
		DestinationIPv4   string `json:"DestinationIpV4,omitempty"`
		DestinationIPv6   string `json:"DestinationIpV6,omitempty"`
		DestinationPort   int    `json:"DestinationPort,omitempty"`
		Direction         string `json:"Direction,omitempty"`
		OpenPortRange     struct {
			Begin int `json:"Begin,omitempty"`
			End   int `json:"End,omitempty"`
		} `json:"OpenPortRange,omitempty"`
		Protocol     string `json:"Protocol,omitempty"`
		SourceDomain string `json:"SourceDomain,omitempty"`
		SourceIPv4   string `json:"SourceIpV4,omitempty"`
		SourceIPv6   string `json:"SourceIpV6,omitempty"`
		SourceMAC    string `json:"SourceMac,omitempty"`
		SourcePort   int    `json:"SourcePort,omitempty"`
	} `json:"Network,omitempty"`
	NetworkPath []struct {
		ComponentID   string `json:"ComponentId,omitempty"`
		ComponentType string `json:"ComponentType,omitempty"`
		Egress        struct {
			Destination struct {
				Address    []string `json:"Address,omitempty"`
				PortRanges []struct {
					Begin int `json:"Begin,omitempty"`
					End   int `json:"End,omitempty"`
				} `json:"PortRanges,omitempty"`
			} `json:"Destination,omitempty"`
			Protocol string `json:"Protocol,omitempty"`
			Source   struct {
				Address    []string `json:"Address,omitempty"`
				PortRanges []struct {
					Begin int `json:"Begin,omitempty"`
					End   int `json:"End,omitempty"`
				} `json:"PortRanges,omitempty"`
			} `json:"Source,omitempty"`
		} `json:"Egress,omitempty"`
		Ingress struct {
			Destination struct {
				Address    []string `json:"Address,omitempty"`
				PortRanges []struct {
					Begin int `json:"Begin,omitempty"`
					End   int `json:"End,omitempty"`
				} `json:"PortRanges,omitempty"`
			} `json:"Destination,omitempty"`
			Protocol string `json:"Protocol,omitempty"`
			Source   struct {
				Address    []string `json:"Address,omitempty"`
				PortRanges []struct {
					Begin int `json:"Begin,omitempty"`
					End   int `json:"End,omitempty"`
				} `json:"PortRanges,omitempty"`
			} `json:"Source,omitempty"`
		} `json:"Ingress,omitempty"`
	} `json:"NetworkPath,omitempty"`
	Note struct {
		Text      string `json:"Text,omitempty"`
		UpdatedAt string `json:"UpdatedAt,omitempty"`
		UpdatedBy string `json:"UpdatedBy,omitempty"`
	} `json:"Note,omitempty"`
	PatchSummary struct {
		FailedCount            int    `json:"FailedCount,omitempty"`
		ID                     string `json:"Id,omitempty"`
		InstalledCount         int    `json:"InstalledCount,omitempty"`
		InstalledOtherCount    int    `json:"InstalledOtherCount,omitempty"`
		InstalledPendingReboot int    `json:"InstalledPendingReboot,omitempty"`
		InstalledRejectedCount int    `json:"InstalledRejectedCount,omitempty"`
		MissingCount           int    `json:"MissingCount,omitempty"`
		Operation              string `json:"Operation,omitempty"`
		OperationEndTime       string `json:"OperationEndTime,omitempty"`
		OperationStartTime     string `json:"OperationStartTime,omitempty"`
		RebootOption           string `json:"RebootOption,omitempty"`
	} `json:"PatchSummary,omitempty"`
	Process struct {
		LaunchedAt   string `json:"LaunchedAt,omitempty"`
		Name         string `json:"Name,omitempty"`
		ParentPID    int    `json:"ParentPid,omitempty"`
		Path         string `json:"Path,omitempty"`
		PID          int    `json:"Pid,omitempty"`
		TerminatedAt string `json:"TerminatedAt,omitempty"`
	} `json:"Process,omitempty"`
	ProductARN    string `json:"ProductArn"`
	ProductFields struct {
		String string `json:"string,omitempty"`
	} `json:"ProductFields,omitempty"`
	RecordState     string `json:"RecordState,omitempty"`
	RelatedFindings []struct {
		ID         string `json:"Id,omitempty"`
		ProductARN string `json:"ProductArn,omitempty"`
	} `json:"RelatedFindings,omitempty"`
	Remediation struct {
		Recommendation struct {
			Text string `json:"Text,omitempty"`
			URL  string `json:"Url,omitempty"`
		} `json:"Recommendation,omitempty"`
	} `json:"Remediation,omitempty"`
	Resources     `json:"Resources"`
	SchemaVersion string `json:"SchemaVersion"`
	Severity      struct {
		Label      string `json:"Label,omitempty"`
		Normalized int    `json:"Normalized,omitempty"`
		Original   string `json:"Original,omitempty"`
		Product    int    `json:"Product,omitempty"`
	} `json:"Severity"`
	SourceURL             string `json:"SourceUrl,omitempty"`
	ThreatIntelIndicators []struct {
		Category       string `json:"Category,omitempty"`
		Lastobservedat string `json:"LastObservedAt,omitempty"`
		Source         string `json:"Source,omitempty"`
		Sourceurl      string `json:"SourceUrl,omitempty"`
		Type           string `json:"Type,omitempty"`
		Value          string `json:"Value,omitempty"`
	} `json:"ThreatIntelIndicators,omitempty"`
	Title             string   `json:"Title"`
	Types             []string `json:"Types"`
	UpdatedAt         string   `json:"UpdatedAt"`
	UserDefinedFields struct {
		String string `json:"string,omitempty"`
	} `json:"UserDefinedFields,omitempty"`
	VerificationState string `json:"VerificationState,omitempty"`
	Workflow          struct {
		Status string `json:"Status,omitempty"`
	} `json:"Workflow,omitempty"`
	WorkflowState   string `json:"WorkflowState,omitempty"`
	Vulnerabilities []struct {
		CVSS []struct {
			BaseScore  int    `json:"BaseScore,omitempty"`
			BaseVector string `json:"BaseVector,omitempty"`
			Version    string `json:"Version,omitempty"`
		} `json:"Cvss,omitempty"`
		ID                     string   `json:"Id,omitempty"`
		ReferenceUrls          []string `json:"ReferenceUrls,omitempty"`
		RelatedVulnerabilities []string `json:"RelatedVulnerabilities,omitempty"`
		Vendor                 struct {
			Name            string `json:"Name,omitempty"`
			URL             string `json:"Url,omitempty"`
			VendorCreatedAt string `json:"VendorCreatedAt,omitempty"`
			VendorSeverity  string `json:"VendorSeverity,omitempty"`
			VendorUpdatedAt string `json:"VendorUpdatedAt,omitempty"`
		} `json:"Vendor,omitempty"`
		VulnerablePackages []struct {
			Architecture string `json:"Architecture,omitempty"`
			Epoch        string `json:"Epoch,omitempty"`
			Name         string `json:"Name,omitempty"`
			Release      string `json:"Release,omitempty"`
			Version      string `json:"Version,omitempty"`
		} `json:"VulnerablePackages,omitempty"`
	} `json:"Vulnerabilities,omitempty"`
}
