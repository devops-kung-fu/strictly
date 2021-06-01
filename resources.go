package strictly

// Resources ASFF Section
type Resources []struct {
	DataClassification struct {
		DetailedResultsLocation string `json:"DetailedResultsLocation,omitempty"`
		Result                  struct {
			AdditionalOccurrences bool `json:"AdditionalOccurrences,omitempty"`
			CustomDataIdentifiers struct {
				Detections []struct {
					ARN         string `json:"Arn,omitempty"`
					Count       int    `json:"Count,omitempty"`
					Name        string `json:"Name,omitempty"`
					Occurrences struct {
						Cells []struct {
							CellReference string `json:"CellReference,omitempty"`
							Column        int    `json:"Column,omitempty"`
							ColumnName    string `json:"ColumnName,omitempty"`
							Row           int    `json:"Row,omitempty"`
						} `json:"Cells,omitempty"`
						LineRanges []struct {
							End         int `json:"End,omitempty"`
							Start       int `json:"Start,omitempty"`
							StartColumn int `json:"StartColumn,omitempty"`
						} `json:"LineRanges,omitempty"`
						OffsetRanges []struct {
							End         int `json:"End,omitempty"`
							Start       int `json:"Start,omitempty"`
							StartColumn int `json:"StartColumn,omitempty"`
						} `json:"OffsetRanges,omitempty"`
						Pages []struct {
							LineRange struct {
								End         int `json:"End,omitempty"`
								Start       int `json:"Start,omitempty"`
								StartColumn int `json:"StartColumn,omitempty"`
							} `json:"LineRange,omitempty"`
							OffsetRange struct {
								End         int `json:"End,omitempty"`
								Start       int `json:"Start,omitempty"`
								StartColumn int `json:"StartColumn,omitempty"`
							} `json:"OffsetRange,omitempty"`
							Page1 int `json:"Page1,omitempty"`
						} `json:"Pages,omitempty"`
						Records []struct {
							JSONPath    string `json:"JsonPath,omitempty"`
							RecordIndex int    `json:"RecordIndex,omitempty"`
						} `json:"Records,omitempty"`
					} `json:"Occurrences,omitempty"`
				} `json:"Detections,omitempty"`
				TotalCount int `json:"TotalCount,omitempty"`
			} `json:"CustomDataIdentifiers,omitempty"`
			MimeType      string `json:"MimeType,omitempty"`
			SensitiveData []struct {
				Category   string `json:"Category,omitempty"`
				Detections []struct {
					Count       int `json:"Count,omitempty"`
					Occurrences struct {
						Cells []struct {
							CellReference string `json:"CellReference,omitempty"`
							Column        int    `json:"Column,omitempty"`
							ColumnName    string `json:"ColumnName,omitempty"`
							Row           int    `json:"Row,omitempty"`
						} `json:"Cells,omitempty"`
						LineRanges []struct {
							End         int `json:"End,omitempty"`
							Start       int `json:"Start,omitempty"`
							StartColumn int `json:"StartColumn,omitempty"`
						} `json:"LineRanges,omitempty"`
						OffsetRanges []struct {
							End         int `json:"End,omitempty"`
							Start       int `json:"Start,omitempty"`
							StartColumn int `json:"StartColumn,omitempty"`
						} `json:"OffsetRanges,omitempty"`
						Pages []struct {
							LineRange struct {
								End         int `json:"End,omitempty"`
								Start       int `json:"Start,omitempty"`
								StartColumn int `json:"StartColumn,omitempty"`
							} `json:"LineRange,omitempty"`
							OffsetRange struct {
								End         int `json:"End,omitempty"`
								Start       int `json:"Start,omitempty"`
								StartColumn int `json:"StartColumn,omitempty"`
							} `json:"OffsetRange,omitempty"`
							Page1 int `json:"Page1,omitempty"`
						} `json:"Pages,omitempty"`
						Records []struct {
							JSONPath    string `json:"JsonPath,omitempty"`
							RecordIndex int    `json:"RecordIndex,omitempty"`
						} `json:"Records,omitempty"`
					} `json:"Occurrences,omitempty"`
					Type string `json:"Type,omitempty"`
				} `json:"Detections,omitempty"`
				TotalCount int `json:"TotalCount,omitempty"`
			} `json:"SensitiveData,omitempty"`
			SizeClassified int `json:"SizeClassified,omitempty"`
			Status         struct {
				Code   string `json:"Code,omitempty"`
				Reason string `json:"Reason,omitempty"`
			} `json:"Status,omitempty"`
		} `json:"Result,omitempty"`
	} `json:"DataClassification,omitempty"`
	Details struct {
		AWSAPIGatewayRestAPI `json:"AwsApiGatewayRestApi,omitempty"`
		AWSAPIGatewayStage struct {
			AccessLogSettings struct {
				DestinationARN string `json:"DestinationArn,omitempty"`
				Format         string `json:"Format,omitempty"`
			} `json:"AccessLogSettings,omitempty"`
			CacheClusterEnabled bool   `json:"CacheClusterEnabled,omitempty"`
			CacheClusterSize    string `json:"CacheClusterSize,omitempty"`
			CacheClusterStatus  string `json:"CacheClusterStatus,omitempty"`
			CanarySettings      struct {
				DeploymentID           string `json:"DeploymentId,omitempty"`
				PercentTraffic         int    `json:"PercentTraffic,omitempty"`
				StageVariableOverrides []struct {
					String string `json:"string,omitempty"`
				} `json:"StageVariableOverrides,omitempty"`
				UseStageCache bool `json:"UseStageCache,omitempty"`
			} `json:"CanarySettings,omitempty"`
			ClientCertificateID  string `json:"ClientCertificateId,omitempty"`
			CreatedDate          string `json:"CreatedDate,omitempty"`
			DeploymentID         string `json:"DeploymentId,omitempty"`
			Description          string `json:"Description,omitempty"`
			DocumentationVersion string `json:"DocumentationVersion,omitempty"`
			LastUpdatedDate      string `json:"LastUpdatedDate,omitempty"`
			MethodSettings       []struct {
				CacheDataEncrypted                     bool   `json:"CacheDataEncrypted,omitempty"`
				CachingEnabled                         bool   `json:"CachingEnabled,omitempty"`
				CacheTTLInSeconds                      int    `json:"CacheTtlInSeconds,omitempty"`
				DataTraceEnabled                       bool   `json:"DataTraceEnabled,omitempty"`
				HTTPMethod                             string `json:"HttpMethod,omitempty"`
				LoggingLevel                           string `json:"LoggingLevel,omitempty"`
				MetricsEnabled                         bool   `json:"MetricsEnabled,omitempty"`
				RequireAuthorizationForCacheControl    bool   `json:"RequireAuthorizationForCacheControl,omitempty"`
				ResourcePath                           string `json:"ResourcePath,omitempty"`
				ThrottlingBurstLimit                   int    `json:"ThrottlingBurstLimit,omitempty"`
				ThrottlingRateLimit                    int    `json:"ThrottlingRateLimit,omitempty"`
				UnauthorizedCacheControlHeaderStrategy string `json:"UnauthorizedCacheControlHeaderStrategy,omitempty"`
			} `json:"MethodSettings,omitempty"`
			StageName      string `json:"StageName,omitempty"`
			TracingEnabled bool   `json:"TracingEnabled,omitempty"`
			Variables      struct {
				String string `json:"string,omitempty"`
			} `json:"Variables,omitempty"`
			WebACLArn string `json:"WebAclArn,omitempty"`
		} `json:"AwsApiGatewayStage,omitempty"`
		AwsAPIGatewayV2Api struct {
			APIEndpoint               string `json:"ApiEndpoint,omitempty"`
			APIID                     string `json:"ApiId,omitempty"`
			APIKeySelectionExpression string `json:"ApiKeySelectionExpression,omitempty"`
			CorsConfiguration         struct {
				AllowCredentials bool     `json:"AllowCredentials,omitempty"`
				AllowHeaders     []string `json:"AllowHeaders,omitempty"`
				AllowMethods     []string `json:"AllowMethods,omitempty"`
				AllowOrigins     []string `json:"AllowOrigins,omitempty"`
				ExposeHeaders    []string `json:"ExposeHeaders,omitempty"`
				MaxAge           int      `json:"MaxAge,omitempty"`
			} `json:"CorsConfiguration,omitempty"`
			CreatedDate              string `json:"CreatedDate,omitempty"`
			Description              string `json:"Description,omitempty"`
			Name                     string `json:"Name,omitempty"`
			ProtocolType             string `json:"ProtocolType,omitempty"`
			RouteSelectionExpression string `json:"RouteSelectionExpression,omitempty"`
			Version                  string `json:"Version,omitempty"`
		} `json:"AwsApiGatewayV2Api,omitempty"`
		AwsAPIGatewayV2Stage struct {
			AccessLogSettings struct {
				DestinationARN string `json:"DestinationArn,omitempty"`
				Format         string `json:"Format,omitempty"`
			} `json:"AccessLogSettings,omitempty"`
			APIGatewayManaged    bool   `json:"ApiGatewayManaged,omitempty"`
			AutoDeploy           bool   `json:"AutoDeploy,omitempty"`
			CreatedDate          string `json:"CreatedDate,omitempty"`
			DefaultRouteSettings struct {
				DataTraceEnabled       bool   `json:"DataTraceEnabled,omitempty"`
				DetailedMetricsEnabled bool   `json:"DetailedMetricsEnabled,omitempty"`
				LoggingLevel           string `json:"LoggingLevel,omitempty"`
				ThrottlingBurstLimit   int    `json:"ThrottlingBurstLimit,omitempty"`
				ThrottlingRatelLimit    int    `json:"ThrottlingRateLimit,omitempty"`
			} `json:"DefaultRouteSettings,omitempty"`
			DeploymentID                string `json:"DeploymentId,omitempty"`
			Description                 string `json:"Description,omitempty"`
			LastDeploymentStatusMessage string `json:"LastDeploymentStatusMessage,omitempty"`
			LastUpdatedDate             string `json:"LastUpdatedDate,omitempty"`
			RouteSettings               struct {
				DetailedMetricsEnabled bool   `json:"DetailedMetricsEnabled,omitempty"`
				LoggingLevel           string `json:"LoggingLevel,omitempty"`
				DataTraceEnabled       bool   `json:"DataTraceEnabled,omitempty"`
				ThrottlingBurstLimit   int    `json:"ThrottlingBurstLimit,omitempty"`
				ThrottlingRateLimit    int    `json:"ThrottlingRateLimit,omitempty"`
			} `json:"RouteSettings,omitempty"`
			StageName      string `json:"StageName,omitempty"`
			StageVariables []struct {
				String string `json:"string,omitempty"`
			} `json:"StageVariables,omitempty"`
		} `json:"AwsApiGatewayV2Stage,omitempty"`
		Awsautoscalingautoscalinggroup struct {
			Createdtime             string   `json:"CreatedTime,omitempty"`
			Healthcheckgraceperiod  int      `json:"HealthCheckGracePeriod,omitempty"`
			Healthchecktype         string   `json:"HealthCheckType,omitempty"`
			Launchconfigurationname string   `json:"LaunchConfigurationName,omitempty"`
			Loadbalancernames       []string `json:"LoadBalancerNames,omitempty"`
		} `json:"AwsAutoScalingAutoScalingGroup,omitempty"`
		Awscertificatemanagercertificate struct {
			Certificateauthorityarn string `json:"CertificateAuthorityArn,omitempty"`
			Createdat               string `json:"CreatedAt,omitempty"`
			Domainname              string `json:"DomainName,omitempty"`
			Domainvalidationoptions []struct {
				Domainname     string `json:"DomainName,omitempty"`
				Resourcerecord struct {
					Name  string `json:"Name,omitempty"`
					Type  string `json:"Type,omitempty"`
					Value string `json:"Value,omitempty"`
				} `json:"ResourceRecord,omitempty"`
				Validationdomain string   `json:"ValidationDomain,omitempty"`
				Validationemails []string `json:"ValidationEmails,omitempty"`
				Validationmethod string   `json:"ValidationMethod,omitempty"`
				Validationstatus string   `json:"ValidationStatus,omitempty"`
			} `json:"DomainValidationOptions,omitempty"`
			Extendedkeyusages []struct {
				Name string `json:"Name,omitempty"`
				Oid  string `json:"OId,omitempty"`
			} `json:"ExtendedKeyUsages,omitempty"`
			Failurereason string   `json:"FailureReason,omitempty"`
			Importedat    string   `json:"ImportedAt,omitempty"`
			Inuseby       []string `json:"InUseBy,omitempty"`
			Issuedat      string   `json:"IssuedAt,omitempty"`
			Issuer        string   `json:"Issuer,omitempty"`
			Keyalgorithm  string   `json:"KeyAlgorithm,omitempty"`
			Keyusages     []struct {
				Name string `json:"Name,omitempty"`
			} `json:"KeyUsages,omitempty"`
			Notafter  string `json:"NotAfter,omitempty"`
			Notbefore string `json:"NotBefore,omitempty"`
			Options   struct {
				Certificatetransparencyloggingpreference string `json:"CertificateTransparencyLoggingPreference,omitempty"`
			} `json:"Options,omitempty"`
			Renewaleligibility string `json:"RenewalEligibility,omitempty"`
			Renewalsummary     struct {
				Domainvalidationoptions []struct {
					Domainname     string `json:"DomainName,omitempty"`
					Resourcerecord struct {
						Name  string `json:"Name,omitempty"`
						Type  string `json:"Type,omitempty"`
						Value string `json:"Value,omitempty"`
					} `json:"ResourceRecord,omitempty"`
					Validationdomain string   `json:"ValidationDomain,omitempty"`
					Validationemails []string `json:"ValidationEmails,omitempty"`
					Validationmethod string   `json:"ValidationMethod,omitempty"`
					Validationstatus string   `json:"ValidationStatus,omitempty"`
				} `json:"DomainValidationOptions,omitempty"`
				Renewalstatus       string `json:"RenewalStatus,omitempty"`
				Renewalstatusreason string `json:"RenewalStatusReason,omitempty"`
				Updatedat           string `json:"UpdatedAt,omitempty"`
			} `json:"RenewalSummary,omitempty"`
			Serial                  string   `json:"Serial,omitempty"`
			Signaturealgorithm      string   `json:"SignatureAlgorithm,omitempty"`
			Status                  string   `json:"Status,omitempty"`
			Subject                 string   `json:"Subject,omitempty"`
			Subjectalternativenames []string `json:"SubjectAlternativeNames,omitempty"`
			Type                    string   `json:"Type,omitempty"`
		} `json:"AwsCertificateManagerCertificate,omitempty"`
		Awscloudfrontdistribution struct {
			Cachebehaviors struct {
				Items []struct {
					Viewerprotocolpolicy string `json:"ViewerProtocolPolicy,omitempty"`
				} `json:"Items,omitempty"`
			} `json:"CacheBehaviors,omitempty"`
			Defaultcachebehavior struct {
				Viewerprotocolpolicy string `json:"ViewerProtocolPolicy,omitempty"`
			} `json:"DefaultCacheBehavior,omitempty"`
			Defaultrootobject string `json:"DefaultRootObject,omitempty"`
			Domainname        string `json:"DomainName,omitempty"`
			Etag              string `json:"Etag,omitempty"`
			Lastmodifiedtime  string `json:"LastModifiedTime,omitempty"`
			Logging           struct {
				Bucket         string `json:"Bucket,omitempty"`
				Enabled        bool   `json:"Enabled,omitempty"`
				Includecookies bool   `json:"IncludeCookies,omitempty"`
				Prefix         string `json:"Prefix,omitempty"`
			} `json:"Logging,omitempty"`
			Origingroups struct {
				Items []struct {
					Failovercriteria struct {
						Statuscodes struct {
							Items    []int `json:"Items,omitempty"`
							Quantity int   `json:"Quantity,omitempty"`
						} `json:"StatusCodes,omitempty"`
					} `json:"FailoverCriteria,omitempty"`
				} `json:"Items,omitempty"`
			} `json:"OriginGroups,omitempty"`
			Origins struct {
				Items []struct {
					Domainname     string `json:"DomainName,omitempty"`
					ID             string `json:"Id,omitempty"`
					Originpath     string `json:"OriginPath,omitempty"`
					S3Originconfig struct {
						Originaccessidentity string `json:"OriginAccessIdentity,omitempty"`
					} `json:"S3OriginConfig,omitempty"`
				} `json:"Items,omitempty"`
			} `json:"Origins,omitempty"`
			Status   string `json:"Status,omitempty"`
			Webaclid string `json:"WebAclId,omitempty"`
		} `json:"AwsCloudFrontDistribution,omitempty"`
		Awscloudtrailtrail struct {
			Cloudwatchlogsloggrouparn  string `json:"CloudWatchLogsLogGroupArn,omitempty"`
			Cloudwatchlogsrolearn      string `json:"CloudWatchLogsRoleArn,omitempty"`
			Hascustomeventselectors    bool   `json:"HasCustomEventSelectors,omitempty"`
			Homeregion                 string `json:"HomeRegion,omitempty"`
			Includeglobalserviceevents bool   `json:"IncludeGlobalServiceEvents,omitempty"`
			Ismultiregiontrail         bool   `json:"IsMultiRegionTrail,omitempty"`
			Isorganizationtrail        bool   `json:"IsOrganizationTrail,omitempty"`
			Kmskeyid                   string `json:"KmsKeyId,omitempty"`
			Logfilevalidationenabled   bool   `json:"LogFileValidationEnabled,omitempty"`
			Name                       string `json:"Name,omitempty"`
			S3Bucketname               string `json:"S3BucketName,omitempty"`
			S3Keyprefix                string `json:"S3KeyPrefix,omitempty"`
			Snstopicarn                string `json:"SnsTopicArn,omitempty"`
			Snstopicname               string `json:"SnsTopicName,omitempty"`
			Trailarn                   string `json:"TrailArn,omitempty"`
		} `json:"AwsCloudTrailTrail,omitempty"`
		Awscodebuildproject struct {
			Encryptionkey string `json:"EncryptionKey,omitempty"`
			Environment   struct {
				Type                     string `json:"Type,omitempty"`
				Certificate              string `json:"Certificate,omitempty"`
				Imagepullcredentialstype string `json:"ImagePullCredentialsType,omitempty"`
				Registrycredential       struct {
					Credential         string `json:"Credential,omitempty"`
					Credentialprovider string `json:"CredentialProvider,omitempty"`
				} `json:"RegistryCredential,omitempty"`
			} `json:"Environment,omitempty"`
			Name        string `json:"Name,omitempty"`
			Servicerole string `json:"ServiceRole,omitempty"`
			Source      struct {
				Type          string `json:"Type,omitempty"`
				Location      string `json:"Location,omitempty"`
				Gitclonedepth int    `json:"GitCloneDepth,omitempty"`
			} `json:"Source,omitempty"`
			Vpcconfig struct {
				Vpcid            string   `json:"VpcId,omitempty"`
				Subnets          []string `json:"Subnets,omitempty"`
				Securitygroupids []string `json:"SecurityGroupIds,omitempty"`
			} `json:"VpcConfig,omitempty"`
		} `json:"AwsCodeBuildProject,omitempty"`
		Awsdynamodbtable struct {
			Attributedefinitions []struct {
				Attributename string `json:"AttributeName,omitempty"`
				Attributetype string `json:"AttributeType,omitempty"`
			} `json:"AttributeDefinitions,omitempty"`
			Billingmodesummary struct {
				Billingmode                       string `json:"BillingMode,omitempty"`
				Lastupdatetopayperrequestdatetime string `json:"LastUpdateToPayPerRequestDateTime,omitempty"`
			} `json:"BillingModeSummary,omitempty"`
			Creationdatetime       string `json:"CreationDateTime,omitempty"`
			Globalsecondaryindexes []struct {
				Backfilling    bool   `json:"Backfilling,omitempty"`
				Indexarn       string `json:"IndexArn,omitempty"`
				Indexname      string `json:"IndexName,omitempty"`
				Indexsizebytes int    `json:"IndexSizeBytes,omitempty"`
				Indexstatus    string `json:"IndexStatus,omitempty"`
				Itemcount      int    `json:"ItemCount,omitempty"`
				Keyschema      []struct {
					Attributename string `json:"AttributeName,omitempty"`
					Keytype       string `json:"KeyType,omitempty"`
				} `json:"KeySchema,omitempty"`
				Projection struct {
					Nonkeyattributes []string `json:"NonKeyAttributes,omitempty"`
					Projectiontype   string   `json:"ProjectionType,omitempty"`
				} `json:"Projection,omitempty"`
				Provisionedthroughput struct {
					Lastdecreasedatetime string `json:"LastDecreaseDateTime,omitempty"`
					Lastincreasedatetime string `json:"LastIncreaseDateTime,omitempty"`
					OneOfdecreasestoday  int    `json:"1OfDecreasesToday,omitempty"`
					Readcapacityunits    int    `json:"ReadCapacityUnits,omitempty"`
					Writecapacityunits   int    `json:"WriteCapacityUnits,omitempty"`
				} `json:"ProvisionedThroughput,omitempty"`
			} `json:"GlobalSecondaryIndexes,omitempty"`
			Globaltableversion string `json:"GlobalTableVersion,omitempty"`
			Itemcount          int    `json:"ItemCount,omitempty"`
			Keyschema          []struct {
				Attributename string `json:"AttributeName,omitempty"`
				Keytype       string `json:"KeyType,omitempty"`
			} `json:"KeySchema,omitempty"`
			Lateststreamarn       string `json:"LatestStreamArn,omitempty"`
			Lateststreamlabel     string `json:"LatestStreamLabel,omitempty"`
			Localsecondaryindexes []struct {
				Indexarn  string `json:"IndexArn,omitempty"`
				Indexname string `json:"IndexName,omitempty"`
				Keyschema []struct {
					Attributename string `json:"AttributeName,omitempty"`
					Keytype       string `json:"KeyType,omitempty"`
				} `json:"KeySchema,omitempty"`
				Projection struct {
					Nonkeyattributes []string `json:"NonKeyAttributes,omitempty"`
					Projectiontype   string   `json:"ProjectionType,omitempty"`
				} `json:"Projection,omitempty"`
			} `json:"LocalSecondaryIndexes,omitempty"`
			Provisionedthroughput struct {
				Lastdecreasedatetime string `json:"LastDecreaseDateTime,omitempty"`
				Lastincreasedatetime string `json:"LastIncreaseDateTime,omitempty"`
				OneOfdecreasestoday  int    `json:"1OfDecreasesToday,omitempty"`
				Readcapacityunits    int    `json:"ReadCapacityUnits,omitempty"`
				Writecapacityunits   int    `json:"WriteCapacityUnits,omitempty"`
			} `json:"ProvisionedThroughput,omitempty"`
			Replicas []struct {
				Globalsecondaryindexes []struct {
					Indexname                     string `json:"IndexName,omitempty"`
					Provisionedthroughputoverride struct {
						Readcapacityunits int `json:"ReadCapacityUnits,omitempty"`
					} `json:"ProvisionedThroughputOverride,omitempty"`
				} `json:"GlobalSecondaryIndexes,omitempty"`
				Kmsmasterkeyid                string `json:"KmsMasterKeyId,omitempty"`
				Provisionedthroughputoverride struct {
					Readcapacityunits int `json:"ReadCapacityUnits,omitempty"`
				} `json:"ProvisionedThroughputOverride,omitempty"`
				Regionname               string `json:"RegionName,omitempty"`
				Replicastatus            string `json:"ReplicaStatus,omitempty"`
				Replicastatusdescription string `json:"ReplicaStatusDescription,omitempty"`
			} `json:"Replicas,omitempty"`
			Restoresummary struct {
				Restoredatetime   string `json:"RestoreDateTime,omitempty"`
				Restoreinprogress bool   `json:"RestoreInProgress,omitempty"`
				Sourcebackuparn   string `json:"SourceBackupArn,omitempty"`
				Sourcetablearn    string `json:"SourceTableArn,omitempty"`
			} `json:"RestoreSummary,omitempty"`
			Ssedescription struct {
				Inaccessibleencryptiondatetime string `json:"InaccessibleEncryptionDateTime,omitempty"`
				Kmsmasterkeyarn                string `json:"KmsMasterKeyArn,omitempty"`
				Ssetype                        string `json:"SseType,omitempty"`
				Status                         string `json:"Status,omitempty"`
			} `json:"SseDescription,omitempty"`
			Streamspecification struct {
				Streamenabled  bool   `json:"StreamEnabled,omitempty"`
				Streamviewtype string `json:"StreamViewType,omitempty"`
			} `json:"StreamSpecification,omitempty"`
			Tableid        string `json:"TableId,omitempty"`
			Tablename      string `json:"TableName,omitempty"`
			Tablesizebytes int    `json:"TableSizeBytes,omitempty"`
			Tablestatus    string `json:"TableStatus,omitempty"`
		} `json:"AwsDynamoDbTable,omitempty"`
		Awsec2Eip struct {
			Allocationid            string `json:"AllocationId,omitempty"`
			Associationid           string `json:"AssociationId,omitempty"`
			Domain                  string `json:"Domain,omitempty"`
			Instanceid              string `json:"InstanceId,omitempty"`
			Networkbordergroup      string `json:"NetworkBorderGroup,omitempty"`
			Networkinterfaceid      string `json:"NetworkInterfaceId,omitempty"`
			Networkinterfaceownerid string `json:"NetworkInterfaceOwnerId,omitempty"`
			Privateipaddress        string `json:"PrivateIpAddress,omitempty"`
			Publicip                string `json:"PublicIp,omitempty"`
			Publicipv4Pool          string `json:"PublicIpv4Pool,omitempty"`
		} `json:"AwsEc2Eip,omitempty"`
		Awsec2Instance struct {
			Iaminstanceprofilearn string   `json:"IamInstanceProfileArn,omitempty"`
			Imageid               string   `json:"ImageId,omitempty"`
			Ipv4Addresses         []string `json:"IpV4Addresses,omitempty"`
			Ipv6Addresses         []string `json:"IpV6Addresses,omitempty"`
			Keyname               string   `json:"KeyName,omitempty"`
			Launchedat            string   `json:"LaunchedAt,omitempty"`
			Subnetid              string   `json:"SubnetId,omitempty"`
			Type                  string   `json:"Type,omitempty"`
			Vpcid                 string   `json:"VpcId,omitempty"`
		} `json:"AwsEc2Instance,omitempty"`
		Awsec2Networkacl struct {
			Associations []struct {
				Networkaclassociationid string `json:"NetworkAclAssociationId,omitempty"`
				Networkaclid            string `json:"NetworkAclId,omitempty"`
				Subnetid                string `json:"SubnetId,omitempty"`
			} `json:"Associations,omitempty"`
			Entries []struct {
				Cidrblock    string `json:"CidrBlock,omitempty"`
				Egress       bool   `json:"Egress,omitempty"`
				Icmptypecode struct {
					Code int `json:"Code,omitempty"`
					Type int `json:"Type,omitempty"`
				} `json:"IcmpTypeCode,omitempty"`
				Ipv6Cidrblock string `json:"Ipv6CidrBlock,omitempty"`
				Portrange     struct {
					From int `json:"From,omitempty"`
					To   int `json:"To,omitempty"`
				} `json:"PortRange,omitempty"`
				Protocol   string `json:"Protocol,omitempty"`
				Ruleaction string `json:"RuleAction,omitempty"`
				Rule1      int    `json:"Rule1,omitempty"`
			} `json:"Entries,omitempty"`
			Isdefault    bool   `json:"IsDefault,omitempty"`
			Networkaclid string `json:"NetworkAclId,omitempty"`
			Ownerid      string `json:"OwnerId,omitempty"`
			Vpcid        string `json:"VpcId,omitempty"`
		} `json:"AwsEc2NetworkAcl,omitempty"`
		Awsec2Networkinterface struct {
			Attachment struct {
				Attachmentid        string `json:"AttachmentId,omitempty"`
				Attachtime          string `json:"AttachTime,omitempty"`
				Deleteontermination bool   `json:"DeleteOnTermination,omitempty"`
				Deviceindex         int    `json:"DeviceIndex,omitempty"`
				Instanceid          string `json:"InstanceId,omitempty"`
				Instanceownerid     string `json:"InstanceOwnerId,omitempty"`
				Status              string `json:"Status,omitempty"`
			} `json:"Attachment,omitempty"`
			Ipv6Addresses []struct {
				Ipv6Address string `json:"Ipv6Address,omitempty"`
			} `json:"Ipv6Addresses,omitempty"`
			Networkinterfaceid string `json:"NetworkInterfaceId,omitempty"`
			Privateipaddresses []struct {
				Privatednsname   string `json:"PrivateDnsName,omitempty"`
				Privateipaddress string `json:"PrivateIpAddress,omitempty"`
			} `json:"PrivateIpAddresses,omitempty"`
			Publicdnsname  string `json:"PublicDnsName,omitempty"`
			Publicip       string `json:"PublicIp,omitempty"`
			Securitygroups []struct {
				Groupid   string `json:"GroupId,omitempty"`
				Groupname string `json:"GroupName,omitempty"`
			} `json:"SecurityGroups,omitempty"`
			Sourcedestcheck bool `json:"SourceDestCheck,omitempty"`
		} `json:"AwsEc2NetworkInterface,omitempty"`
		Awsec2Securitygroup struct {
			Groupid       string `json:"GroupId,omitempty"`
			Groupname     string `json:"GroupName,omitempty"`
			Ippermissions []struct {
				Fromport   int    `json:"FromPort,omitempty"`
				Ipprotocol string `json:"IpProtocol,omitempty"`
				Ipranges   []struct {
					Cidrip string `json:"CidrIp,omitempty"`
				} `json:"IpRanges,omitempty"`
				Prefixlistids []struct {
					Prefixlistid string `json:"PrefixListId,omitempty"`
				} `json:"PrefixListIds,omitempty"`
				Toport           int `json:"ToPort,omitempty"`
				Useridgrouppairs []struct {
					Userid  string `json:"UserId,omitempty"`
					Groupid string `json:"GroupId,omitempty"`
				} `json:"UserIdGroupPairs,omitempty"`
			} `json:"IpPermissions,omitempty"`
			Ippermissionsegress []struct {
				Fromport   int    `json:"FromPort,omitempty"`
				Ipprotocol string `json:"IpProtocol,omitempty"`
				Ipranges   []struct {
					Cidrip string `json:"CidrIp,omitempty"`
				} `json:"IpRanges,omitempty"`
				Prefixlistids []struct {
					Prefixlistid string `json:"PrefixListId,omitempty"`
				} `json:"PrefixListIds,omitempty"`
				Toport           int `json:"ToPort,omitempty"`
				Useridgrouppairs []struct {
					Userid  string `json:"UserId,omitempty"`
					Groupid string `json:"GroupId,omitempty"`
				} `json:"UserIdGroupPairs,omitempty"`
			} `json:"IpPermissionsEgress,omitempty"`
			Ownerid string `json:"OwnerId,omitempty"`
			Vpcid   string `json:"VpcId,omitempty"`
		} `json:"AwsEc2SecurityGroup,omitempty"`
		Awsec2Subnet struct {
			Assignipv6Addressoncreation bool   `json:"AssignIpv6AddressOnCreation,omitempty"`
			Availabilityzone            string `json:"AvailabilityZone,omitempty"`
			Availabilityzoneid          string `json:"AvailabilityZoneId,omitempty"`
			Availableipaddresscount     int    `json:"AvailableIpAddressCount,omitempty"`
			Cidrblock                   string `json:"CidrBlock,omitempty"`
			Defaultforaz                bool   `json:"DefaultForAz,omitempty"`
			Ipv6Cidrblockassociationset []struct {
				Associationid  string `json:"AssociationId,omitempty"`
				Ipv6Cidrblock  string `json:"Ipv6CidrBlock,omitempty"`
				Cidrblockstate string `json:"CidrBlockState,omitempty"`
			} `json:"Ipv6CidrBlockAssociationSet,omitempty"`
			Mappubliciponlaunch bool   `json:"MapPublicIpOnLaunch,omitempty"`
			Ownerid             string `json:"OwnerId,omitempty"`
			State               string `json:"State,omitempty"`
			Subnetarn           string `json:"SubnetArn,omitempty"`
			Subnetid            string `json:"SubnetId,omitempty"`
			Vpcid               string `json:"VpcId,omitempty"`
		} `json:"AwsEc2Subnet,omitempty"`
		Awsec2Volume struct {
			Attachments []struct {
				Attachtime          string `json:"AttachTime,omitempty"`
				Deleteontermination bool   `json:"DeleteOnTermination,omitempty"`
				Instanceid          string `json:"InstanceId,omitempty"`
				Status              string `json:"Status,omitempty"`
			} `json:"Attachments,omitempty"`
			Createtime string `json:"CreateTime,omitempty"`
			Encrypted  bool   `json:"Encrypted,omitempty"`
			Kmskeyid   string `json:"KmsKeyId,omitempty"`
			Size       int    `json:"Size,omitempty"`
			Snapshotid string `json:"SnapshotId,omitempty"`
			Status     string `json:"Status,omitempty"`
		} `json:"AwsEc2Volume,omitempty"`
		Awsec2Vpc struct {
			Cidrblockassociationset []struct {
				Associationid  string `json:"AssociationId,omitempty"`
				Cidrblock      string `json:"CidrBlock,omitempty"`
				Cidrblockstate string `json:"CidrBlockState,omitempty"`
			} `json:"CidrBlockAssociationSet,omitempty"`
			Dhcpoptionsid               string `json:"DhcpOptionsId,omitempty"`
			Ipv6Cidrblockassociationset []struct {
				Associationid  string `json:"AssociationId,omitempty"`
				Cidrblockstate string `json:"CidrBlockState,omitempty"`
				Ipv6Cidrblock  string `json:"Ipv6CidrBlock,omitempty"`
			} `json:"Ipv6CidrBlockAssociationSet,omitempty"`
			State string `json:"State,omitempty"`
		} `json:"AwsEc2Vpc,omitempty"`
		Awselasticbeanstalkenvironment struct {
			Applicationname  string `json:"ApplicationName,omitempty"`
			Cname            string `json:"Cname,omitempty"`
			Datecreated      string `json:"DateCreated,omitempty"`
			Dateupdated      string `json:"DateUpdated,omitempty"`
			Description      string `json:"Description,omitempty"`
			Endpointurl      string `json:"EndpointUrl,omitempty"`
			Environmentarn   string `json:"EnvironmentArn,omitempty"`
			Environmentid    string `json:"EnvironmentId,omitempty"`
			Environmentlinks []struct {
				Environmentname string `json:"EnvironmentName,omitempty"`
				Linkname        string `json:"LinkName,omitempty"`
			} `json:"EnvironmentLinks,omitempty"`
			Environmentname string `json:"EnvironmentName,omitempty"`
			Optionsettings  []struct {
				Namespace    string `json:"Namespace,omitempty"`
				Optionname   string `json:"OptionName,omitempty"`
				Resourcename string `json:"ResourceName,omitempty"`
				Value        string `json:"Value,omitempty"`
			} `json:"OptionSettings,omitempty"`
			Platformarn       string `json:"PlatformArn,omitempty"`
			Solutionstackname string `json:"SolutionStackName,omitempty"`
			Status            string `json:"Status,omitempty"`
			Tier              struct {
				Name    string `json:"Name,omitempty"`
				Type    string `json:"Type,omitempty"`
				Version string `json:"Version,omitempty"`
			} `json:"Tier,omitempty"`
			Versionlabel string `json:"VersionLabel,omitempty"`
		} `json:"AwsElasticBeanstalkEnvironment,omitempty"`
		Awselasticsearchdomain struct {
			Accesspolicies string `json:"AccessPolicies,omitempty"`
			Domainstatus   struct {
				Domainid   string `json:"DomainId,omitempty"`
				Domainname string `json:"DomainName,omitempty"`
				Endpoint   string `json:"Endpoint,omitempty"`
				Endpoints  struct {
					String string `json:"string,omitempty"`
				} `json:"Endpoints,omitempty"`
			} `json:"DomainStatus,omitempty"`
			Domainendpointoptions struct {
				Enforcehttps      bool   `json:"EnforceHTTPS,omitempty"`
				Tlssecuritypolicy string `json:"TLSSecurityPolicy,omitempty"`
			} `json:"DomainEndpointOptions,omitempty"`
			Elasticsearchversion    string `json:"ElasticsearchVersion,omitempty"`
			Encryptionatrestoptions struct {
				Enabled  bool   `json:"Enabled,omitempty"`
				Kmskeyid string `json:"KmsKeyId,omitempty"`
			} `json:"EncryptionAtRestOptions,omitempty"`
			Nodetonodeencryptionoptions struct {
				Enabled bool `json:"Enabled,omitempty"`
			} `json:"NodeToNodeEncryptionOptions,omitempty"`
			Vpcoptions struct {
				Availabilityzones []string `json:"AvailabilityZones,omitempty"`
				Securitygroupids  []string `json:"SecurityGroupIds,omitempty"`
				Subnetids         []string `json:"SubnetIds,omitempty"`
				Vpcid             string   `json:"VPCId,omitempty"`
			} `json:"VPCOptions,omitempty"`
		} `json:"AwsElasticSearchDomain,omitempty"`
		Awselbloadbalancer struct {
			Availabilityzones         []string `json:"AvailabilityZones,omitempty"`
			Backendserverdescriptions []struct {
				Instanceport int      `json:"InstancePort,omitempty"`
				Policynames  []string `json:"PolicyNames,omitempty"`
			} `json:"BackendServerDescriptions,omitempty"`
			Canonicalhostedzonename   string `json:"CanonicalHostedZoneName,omitempty"`
			Canonicalhostedzonenameid string `json:"CanonicalHostedZoneNameID,omitempty"`
			Createdtime               string `json:"CreatedTime,omitempty"`
			Dnsname                   string `json:"DnsName,omitempty"`
			Healthcheck               struct {
				Healthythreshold   int    `json:"HealthyThreshold,omitempty"`
				Interval           int    `json:"Interval,omitempty"`
				Target             string `json:"Target,omitempty"`
				Timeout            int    `json:"Timeout,omitempty"`
				Unhealthythreshold int    `json:"UnhealthyThreshold,omitempty"`
			} `json:"HealthCheck,omitempty"`
			Instances []struct {
				Instanceid string `json:"InstanceId,omitempty"`
			} `json:"Instances,omitempty"`
			Listenerdescriptions []struct {
				Listener struct {
					Instanceport     int    `json:"InstancePort,omitempty"`
					Instanceprotocol string `json:"InstanceProtocol,omitempty"`
					Loadbalancerport int    `json:"LoadBalancerPort,omitempty"`
					Protocol         string `json:"Protocol,omitempty"`
					Sslcertificateid string `json:"SslCertificateId,omitempty"`
				} `json:"Listener,omitempty"`
				Policynames []string `json:"PolicyNames,omitempty"`
			} `json:"ListenerDescriptions,omitempty"`
			Loadbalancerattributes struct {
				Accesslog struct {
					Emitinterval   int    `json:"EmitInterval,omitempty"`
					Enabled        bool   `json:"Enabled,omitempty"`
					S3Bucketname   string `json:"S3BucketName,omitempty"`
					S3Bucketprefix string `json:"S3BucketPrefix,omitempty"`
				} `json:"AccessLog,omitempty"`
				Connectiondraining struct {
					Enabled bool `json:"Enabled,omitempty"`
					Timeout int  `json:"Timeout,omitempty"`
				} `json:"ConnectionDraining,omitempty"`
				Connectionsettings struct {
					Idletimeout int `json:"IdleTimeout,omitempty"`
				} `json:"ConnectionSettings,omitempty"`
				Crosszoneloadbalancing struct {
					Enabled bool `json:"Enabled,omitempty"`
				} `json:"CrossZoneLoadBalancing,omitempty"`
			} `json:"LoadBalancerAttributes,omitempty"`
			Loadbalancername string `json:"LoadBalancerName,omitempty"`
			Policies         struct {
				Appcookiestickinesspolicies []struct {
					Cookiename string `json:"CookieName,omitempty"`
					Policyname string `json:"PolicyName,omitempty"`
				} `json:"AppCookieStickinessPolicies,omitempty"`
				Lbcookiestickinesspolicies []struct {
					Cookieexpirationperiod int    `json:"CookieExpirationPeriod,omitempty"`
					Policyname             string `json:"PolicyName,omitempty"`
				} `json:"LbCookieStickinessPolicies,omitempty"`
				Otherpolicies []string `json:"OtherPolicies,omitempty"`
			} `json:"Policies,omitempty"`
			Scheme              string   `json:"Scheme,omitempty"`
			Securitygroups      []string `json:"SecurityGroups,omitempty"`
			Sourcesecuritygroup struct {
				Groupname  string `json:"GroupName,omitempty"`
				Owneralias string `json:"OwnerAlias,omitempty"`
			} `json:"SourceSecurityGroup,omitempty"`
			Subnets []string `json:"Subnets,omitempty"`
			Vpcid   string   `json:"VpcId,omitempty"`
		} `json:"AwsElbLoadBalancer,omitempty"`
		Awselbv2Loadbalancer struct {
			Availabilityzones struct {
				Subnetid string `json:"SubnetId,omitempty"`
				Zonename string `json:"ZoneName,omitempty"`
			} `json:"AvailabilityZones,omitempty"`
			Canonicalhostedzoneid string   `json:"CanonicalHostedZoneId,omitempty"`
			Createdtime           string   `json:"CreatedTime,omitempty"`
			Dnsname               string   `json:"DNSName,omitempty"`
			Ipaddresstype         string   `json:"IpAddressType,omitempty"`
			Scheme                string   `json:"Scheme,omitempty"`
			Securitygroups        []string `json:"SecurityGroups,omitempty"`
			State                 struct {
				Code   string `json:"Code,omitempty"`
				Reason string `json:"Reason,omitempty"`
			} `json:"State,omitempty"`
			Type  string `json:"Type,omitempty"`
			Vpcid string `json:"VpcId,omitempty"`
		} `json:"AwsElbv2LoadBalancer,omitempty"`
		Awsiamaccesskey struct {
			Accesskeyid    string `json:"AccessKeyId,omitempty"`
			Accountid      string `json:"AccountId,omitempty"`
			Createdat      string `json:"CreatedAt,omitempty"`
			Principalid    string `json:"PrincipalId,omitempty"`
			Principalname  string `json:"PrincipalName,omitempty"`
			Principaltype  string `json:"PrincipalType,omitempty"`
			Sessioncontext struct {
				Attributes struct {
					Creationdate     string `json:"CreationDate,omitempty"`
					Mfaauthenticated bool   `json:"MfaAuthenticated,omitempty"`
				} `json:"Attributes,omitempty"`
				Sessionissuer struct {
					Accountid   string `json:"AccountId,omitempty"`
					Arn         string `json:"Arn,omitempty"`
					Principalid string `json:"PrincipalId,omitempty"`
					Type        string `json:"Type,omitempty"`
					Username    string `json:"UserName,omitempty"`
				} `json:"SessionIssuer,omitempty"`
			} `json:"SessionContext,omitempty"`
			Status string `json:"Status,omitempty"`
		} `json:"AwsIamAccessKey,omitempty"`
		Awsiamgroup struct {
			Attachedmanagedpolicies []struct {
				Policyarn  string `json:"PolicyArn,omitempty"`
				Policyname string `json:"PolicyName,omitempty"`
			} `json:"AttachedManagedPolicies,omitempty"`
			Createdate      string `json:"CreateDate,omitempty"`
			Groupid         string `json:"GroupId,omitempty"`
			Groupname       string `json:"GroupName,omitempty"`
			Grouppolicylist []struct {
				Policyname string `json:"PolicyName,omitempty"`
			} `json:"GroupPolicyList,omitempty"`
			Path string `json:"Path,omitempty"`
		} `json:"AwsIamGroup,omitempty"`
		Awsiampolicy struct {
			Attachmentcount               int    `json:"AttachmentCount,omitempty"`
			Createdate                    string `json:"CreateDate,omitempty"`
			Defaultversionid              string `json:"DefaultVersionId,omitempty"`
			Description                   string `json:"Description,omitempty"`
			Isattachable                  bool   `json:"IsAttachable,omitempty"`
			Path                          string `json:"Path,omitempty"`
			Permissionsboundaryusagecount int    `json:"PermissionsBoundaryUsageCount,omitempty"`
			Policyid                      string `json:"PolicyId,omitempty"`
			Policyname                    string `json:"PolicyName,omitempty"`
			Policyversionlist             []struct {
				Createdate       string `json:"CreateDate,omitempty"`
				Isdefaultversion bool   `json:"IsDefaultVersion,omitempty"`
				Versionid        string `json:"VersionId,omitempty"`
			} `json:"PolicyVersionList,omitempty"`
			Updatedate string `json:"UpdateDate,omitempty"`
		} `json:"AwsIamPolicy,omitempty"`
		Awsiamrole struct {
			Assumerolepolicydocument string `json:"AssumeRolePolicyDocument,omitempty"`
			Attachedmanagedpolicies  []struct {
				Policyarn  string `json:"PolicyArn,omitempty"`
				Policyname string `json:"PolicyName,omitempty"`
			} `json:"AttachedManagedPolicies,omitempty"`
			Createdate          string `json:"CreateDate,omitempty"`
			Instanceprofilelist []struct {
				Arn                 string `json:"Arn,omitempty"`
				Createdate          string `json:"CreateDate,omitempty"`
				Instanceprofileid   string `json:"InstanceProfileId,omitempty"`
				Instanceprofilename string `json:"InstanceProfileName,omitempty"`
				Path                string `json:"Path,omitempty"`
				Roles               []struct {
					Arn                      string `json:"Arn,omitempty"`
					Assumerolepolicydocument string `json:"AssumeRolePolicyDocument,omitempty"`
					Createdate               string `json:"CreateDate,omitempty"`
					Path                     string `json:"Path,omitempty"`
					Roleid                   string `json:"RoleId,omitempty"`
					Rolename                 string `json:"RoleName,omitempty"`
				} `json:"Roles,omitempty"`
			} `json:"InstanceProfileList,omitempty"`
			Maxsessionduration  int    `json:"MaxSessionDuration,omitempty"`
			Path                string `json:"Path,omitempty"`
			Permissionsboundary struct {
				Permissionsboundaryarn  string `json:"PermissionsBoundaryArn,omitempty"`
				Permissionsboundarytype string `json:"PermissionsBoundaryType,omitempty"`
			} `json:"PermissionsBoundary,omitempty"`
			Roleid         string `json:"RoleId,omitempty"`
			Rolename       string `json:"RoleName,omitempty"`
			Rolepolicylist []struct {
				Policyname string `json:"PolicyName,omitempty"`
			} `json:"RolePolicyList,omitempty"`
		} `json:"AwsIamRole,omitempty"`
		Awsiamuser struct {
			Attachedmanagedpolicies []struct {
				Policyarn  string `json:"PolicyArn,omitempty"`
				Policyname string `json:"PolicyName,omitempty"`
			} `json:"AttachedManagedPolicies,omitempty"`
			Createdate          string   `json:"CreateDate,omitempty"`
			Grouplist           []string `json:"GroupList,omitempty"`
			Path                string   `json:"Path,omitempty"`
			Permissionsboundary struct {
				Permissionsboundaryarn  string `json:"PermissionsBoundaryArn,omitempty"`
				Permissionsboundarytype string `json:"PermissionsBoundaryType,omitempty"`
			} `json:"PermissionsBoundary,omitempty"`
			Userid         string `json:"UserId,omitempty"`
			Username       string `json:"UserName,omitempty"`
			Userpolicylist []struct {
				Policyname string `json:"PolicyName,omitempty"`
			} `json:"UserPolicyList,omitempty"`
		} `json:"AwsIamUser,omitempty"`
		Awskmskey struct {
			Awsaccountid string `json:"AWSAccountId,omitempty"`
			Creationdate string `json:"CreationDate,omitempty"`
			Description  string `json:"Description,omitempty"`
			Keyid        string `json:"KeyId,omitempty"`
			Keymanager   string `json:"KeyManager,omitempty"`
			Keystate     string `json:"KeyState,omitempty"`
			Origin       string `json:"Origin,omitempty"`
		} `json:"AwsKmsKey,omitempty"`
		Awslambdafunction struct {
			Code struct {
				S3Bucket        string `json:"S3Bucket,omitempty"`
				S3Key           string `json:"S3Key,omitempty"`
				S3Objectversion string `json:"S3ObjectVersion,omitempty"`
				Zipfile         string `json:"ZipFile,omitempty"`
			} `json:"Code,omitempty"`
			Codesha256       string `json:"CodeSha256,omitempty"`
			Deadletterconfig struct {
				Targetarn string `json:"TargetArn,omitempty"`
			} `json:"DeadLetterConfig,omitempty"`
			Environment struct {
				Variables struct {
					String string `json:"string,omitempty"`
				} `json:"Variables,omitempty"`
				Error struct {
					Errorcode string `json:"ErrorCode,omitempty"`
					Message   string `json:"Message,omitempty"`
				} `json:"Error,omitempty"`
			} `json:"Environment,omitempty"`
			Functionname string `json:"FunctionName,omitempty"`
			Handler      string `json:"Handler,omitempty"`
			Kmskeyarn    string `json:"KmsKeyArn,omitempty"`
			Lastmodified string `json:"LastModified,omitempty"`
			Layers       struct {
				Arn      string `json:"Arn,omitempty"`
				Codesize int    `json:"CodeSize,omitempty"`
			} `json:"Layers,omitempty"`
			Revisionid    string `json:"RevisionId,omitempty"`
			Role          string `json:"Role,omitempty"`
			Runtime       string `json:"Runtime,omitempty"`
			Timeout       string `json:"Timeout,omitempty"`
			Tracingconfig struct {
				TracingconfigMode string `json:"TracingConfig.Mode,omitempty"`
			} `json:"TracingConfig,omitempty"`
			Version   string `json:"Version,omitempty"`
			Vpcconfig struct {
				Securitygroupids []string `json:"SecurityGroupIds,omitempty"`
				Subnetids        []string `json:"SubnetIds,omitempty"`
			} `json:"VpcConfig,omitempty"`
			Masterarn  string `json:"MasterArn,omitempty"`
			Memorysize int    `json:"MemorySize,omitempty"`
		} `json:"AwsLambdaFunction,omitempty"`
		Awslambdalayerversion struct {
			Compatibleruntimes []string `json:"CompatibleRuntimes,omitempty"`
			Createddate        string   `json:"CreatedDate,omitempty"`
			Version            int      `json:"Version,omitempty"`
		} `json:"AwsLambdaLayerVersion,omitempty"`
		Awsrdsdbcluster struct {
			Activitystreamstatus string `json:"ActivityStreamStatus,omitempty"`
			Allocatedstorage     int    `json:"AllocatedStorage,omitempty"`
			Associatedroles      []struct {
				Rolearn string `json:"RoleArn,omitempty"`
				Status  string `json:"Status,omitempty"`
			} `json:"AssociatedRoles,omitempty"`
			Availabilityzones     []string `json:"AvailabilityZones,omitempty"`
			Backupretentionperiod int      `json:"BackupRetentionPeriod,omitempty"`
			Clustercreatetime     string   `json:"ClusterCreateTime,omitempty"`
			Copytagstosnapshot    bool     `json:"CopyTagsToSnapshot,omitempty"`
			Crossaccountclone     bool     `json:"CrossAccountClone,omitempty"`
			Customendpoints       []string `json:"CustomEndpoints,omitempty"`
			Databasename          string   `json:"DatabaseName,omitempty"`
			Dbclusteridentifier   string   `json:"DbClusterIdentifier,omitempty"`
			Dbclustermembers      []struct {
				Dbclusterparametergroupstatus string `json:"DbClusterParameterGroupStatus,omitempty"`
				Dbinstanceidentifier          string `json:"DbInstanceIdentifier,omitempty"`
				Isclusterwriter               bool   `json:"IsClusterWriter,omitempty"`
				Promotiontier                 int    `json:"PromotionTier,omitempty"`
			} `json:"DbClusterMembers,omitempty"`
			Dbclusteroptiongroupmemberships []struct {
				Dbclusteroptiongroupname string `json:"DbClusterOptionGroupName,omitempty"`
				Status                   string `json:"Status,omitempty"`
			} `json:"DbClusterOptionGroupMemberships,omitempty"`
			Dbclusterparametergroup string `json:"DbClusterParameterGroup,omitempty"`
			Dbclusterresourceid     string `json:"DbClusterResourceId,omitempty"`
			Dbsubnetgroup           string `json:"DbSubnetGroup,omitempty"`
			Deletionprotection      bool   `json:"DeletionProtection,omitempty"`
			Domainmemberships       []struct {
				Domain      string `json:"Domain,omitempty"`
				Fqdn        string `json:"Fqdn,omitempty"`
				Iamrolename string `json:"IamRoleName,omitempty"`
				Status      string `json:"Status,omitempty"`
			} `json:"DomainMemberships,omitempty"`
			Enabledcloudwatchlogsexports     []string `json:"EnabledCloudwatchLogsExports,omitempty"`
			Endpoint                         string   `json:"Endpoint,omitempty"`
			Engine                           string   `json:"Engine,omitempty"`
			Enginemode                       string   `json:"EngineMode,omitempty"`
			Engineversion                    string   `json:"EngineVersion,omitempty"`
			Hostedzoneid                     string   `json:"HostedZoneId,omitempty"`
			Httpendpointenabled              bool     `json:"HttpEndpointEnabled,omitempty"`
			Iamdatabaseauthenticationenabled bool     `json:"IamDatabaseAuthenticationEnabled,omitempty"`
			Kmskeyid                         string   `json:"KmsKeyId,omitempty"`
			Masterusername                   string   `json:"MasterUsername,omitempty"`
			Multiaz                          bool     `json:"MultiAz,omitempty"`
			Port                             int      `json:"Port,omitempty"`
			Preferredbackupwindow            string   `json:"PreferredBackupWindow,omitempty"`
			Preferredmaintenancewindow       string   `json:"PreferredMaintenanceWindow,omitempty"`
			Readerendpoint                   string   `json:"ReaderEndpoint,omitempty"`
			Readreplicaidentifiers           []string `json:"ReadReplicaIdentifiers,omitempty"`
			Status                           string   `json:"Status,omitempty"`
			Storageencrypted                 bool     `json:"StorageEncrypted,omitempty"`
			Vpcsecuritygroups                []struct {
				Status             string `json:"Status,omitempty"`
				Vpcsecuritygroupid string `json:"VpcSecurityGroupId,omitempty"`
			} `json:"VpcSecurityGroups,omitempty"`
		} `json:"AwsRdsDbCluster,omitempty"`
		Awsrdsdbclustersnapshot struct {
			Allocatedstorage                 int      `json:"AllocatedStorage,omitempty"`
			Availabilityzones                []string `json:"AvailabilityZones,omitempty"`
			Clustercreatetime                string   `json:"ClusterCreateTime,omitempty"`
			Dbclusteridentifier              string   `json:"DbClusterIdentifier,omitempty"`
			Dbclustersnapshotidentifier      string   `json:"DbClusterSnapshotIdentifier,omitempty"`
			Engine                           string   `json:"Engine,omitempty"`
			Engineversion                    string   `json:"EngineVersion,omitempty"`
			Iamdatabaseauthenticationenabled bool     `json:"IamDatabaseAuthenticationEnabled,omitempty"`
			Kmskeyid                         string   `json:"KmsKeyId,omitempty"`
			Licensemodel                     string   `json:"LicenseModel,omitempty"`
			Masterusername                   string   `json:"MasterUsername,omitempty"`
			Percentprogress                  int      `json:"PercentProgress,omitempty"`
			Port                             int      `json:"Port,omitempty"`
			Snapshotcreatetime               string   `json:"SnapshotCreateTime,omitempty"`
			Snapshottype                     string   `json:"SnapshotType,omitempty"`
			Status                           string   `json:"Status,omitempty"`
			Storageencrypted                 bool     `json:"StorageEncrypted,omitempty"`
			Vpcid                            string   `json:"VpcId,omitempty"`
		} `json:"AwsRdsDbClusterSnapshot,omitempty"`
		Awsrdsdbinstance struct {
			Allocatedstorage int `json:"AllocatedStorage,omitempty"`
			Associatedroles  []struct {
				Rolearn     string `json:"RoleArn,omitempty"`
				Featurename string `json:"FeatureName,omitempty"`
				Status      string `json:"Status,omitempty"`
			} `json:"AssociatedRoles,omitempty"`
			Autominorversionupgrade bool   `json:"AutoMinorVersionUpgrade,omitempty"`
			Availabilityzone        string `json:"AvailabilityZone,omitempty"`
			Backupretentionperiod   int    `json:"BackupRetentionPeriod,omitempty"`
			Cacertificateidentifier string `json:"CACertificateIdentifier,omitempty"`
			Charactersetname        string `json:"CharacterSetName,omitempty"`
			Copytagstosnapshot      bool   `json:"CopyTagsToSnapshot,omitempty"`
			Dbclusteridentifier     string `json:"DBClusterIdentifier,omitempty"`
			Dbinstanceclass         string `json:"DBInstanceClass,omitempty"`
			Dbinstanceidentifier    string `json:"DBInstanceIdentifier,omitempty"`
			Dbinstanceport          int    `json:"DbInstancePort,omitempty"`
			Dbinstancestatus        string `json:"DbInstanceStatus,omitempty"`
			Dbiresourceid           string `json:"DbiResourceId,omitempty"`
			Dbname                  string `json:"DBName,omitempty"`
			Dbparametergroups       []struct {
				Dbparametergroupname string `json:"DbParameterGroupName,omitempty"`
				Parameterapplystatus string `json:"ParameterApplyStatus,omitempty"`
			} `json:"DbParameterGroups,omitempty"`
			Dbsecuritygroups []string `json:"DbSecurityGroups,omitempty"`
			Dbsubnetgroup    struct {
				Dbsubnetgrouparn         string `json:"DbSubnetGroupArn,omitempty"`
				Dbsubnetgroupdescription string `json:"DbSubnetGroupDescription,omitempty"`
				Dbsubnetgroupname        string `json:"DbSubnetGroupName,omitempty"`
				Subnetgroupstatus        string `json:"SubnetGroupStatus,omitempty"`
				Subnets                  []struct {
					Subnetavailabilityzone struct {
						Name string `json:"Name,omitempty"`
					} `json:"SubnetAvailabilityZone,omitempty"`
					Subnetidentifier string `json:"SubnetIdentifier,omitempty"`
					Subnetstatus     string `json:"SubnetStatus,omitempty"`
				} `json:"Subnets,omitempty"`
				Vpcid string `json:"VpcId,omitempty"`
			} `json:"DbSubnetGroup,omitempty"`
			Deletionprotection bool `json:"DeletionProtection,omitempty"`
			Endpoint           struct {
				Address      string `json:"Address,omitempty"`
				Port         int    `json:"Port,omitempty"`
				Hostedzoneid string `json:"HostedZoneId,omitempty"`
			} `json:"Endpoint,omitempty"`
			Domainmemberships []struct {
				Domain      string `json:"Domain,omitempty"`
				Fqdn        string `json:"Fqdn,omitempty"`
				Iamrolename string `json:"IamRoleName,omitempty"`
				Status      string `json:"Status,omitempty"`
			} `json:"DomainMemberships,omitempty"`
			Enabledcloudwatchlogsexports     []string `json:"EnabledCloudwatchLogsExports,omitempty"`
			Engine                           string   `json:"Engine,omitempty"`
			Engineversion                    string   `json:"EngineVersion,omitempty"`
			Enhancedmonitoringresourcearn    string   `json:"EnhancedMonitoringResourceArn,omitempty"`
			Iamdatabaseauthenticationenabled bool     `json:"IAMDatabaseAuthenticationEnabled,omitempty"`
			Instancecreatetime               string   `json:"InstanceCreateTime,omitempty"`
			Iops                             int      `json:"Iops,omitempty"`
			Kmskeyid                         string   `json:"KmsKeyId,omitempty"`
			Latestrestorabletime             string   `json:"LatestRestorableTime,omitempty"`
			Licensemodel                     string   `json:"LicenseModel,omitempty"`
			Listenerendpoint                 struct {
				Address      string `json:"Address,omitempty"`
				Hostedzoneid string `json:"HostedZoneId,omitempty"`
				Port         int    `json:"Port,omitempty"`
			} `json:"ListenerEndpoint,omitempty"`
			Masterusername         string `json:"MasterUsername,omitempty"`
			Maxallocatedstorage    int    `json:"MaxAllocatedStorage,omitempty"`
			Monitoringinterval     int    `json:"MonitoringInterval,omitempty"`
			Monitoringrolearn      string `json:"MonitoringRoleArn,omitempty"`
			Multiaz                bool   `json:"MultiAz,omitempty"`
			Optiongroupmemberships []struct {
				Optiongroupname string `json:"OptionGroupName,omitempty"`
				Status          string `json:"Status,omitempty"`
			} `json:"OptionGroupMemberships,omitempty"`
			Pendingmodifiedvalues struct {
				Allocatedstorage             int    `json:"AllocatedStorage,omitempty"`
				Backupretentionperiod        int    `json:"BackupRetentionPeriod,omitempty"`
				Cacertificateidentifier      string `json:"CaCertificateIdentifier,omitempty"`
				Dbinstanceclass              string `json:"DbInstanceClass,omitempty"`
				Dbinstanceidentifier         string `json:"DbInstanceIdentifier,omitempty"`
				Dbsubnetgroupname            string `json:"DbSubnetGroupName,omitempty"`
				Engineversion                string `json:"EngineVersion,omitempty"`
				Iops                         int    `json:"Iops,omitempty"`
				Licensemodel                 string `json:"LicenseModel,omitempty"`
				Masteruserpassword           string `json:"MasterUserPassword,omitempty"`
				Multiaz                      bool   `json:"MultiAZ,omitempty"`
				Pendingcloudwatchlogsexports struct {
					Logtypestodisable []string `json:"LogTypesToDisable,omitempty"`
					Logtypestoenable  []string `json:"LogTypesToEnable,omitempty"`
				} `json:"PendingCloudWatchLogsExports,omitempty"`
				Port              int `json:"Port,omitempty"`
				Processorfeatures []struct {
					Name  string `json:"Name,omitempty"`
					Value string `json:"Value,omitempty"`
				} `json:"ProcessorFeatures,omitempty"`
				Storagetype string `json:"StorageType,omitempty"`
			} `json:"PendingModifiedValues,omitempty"`
			Performanceinsightsenabled         bool   `json:"PerformanceInsightsEnabled,omitempty"`
			Performanceinsightskmskeyid        string `json:"PerformanceInsightsKmsKeyId,omitempty"`
			Performanceinsightsretentionperiod int    `json:"PerformanceInsightsRetentionPeriod,omitempty"`
			Preferredbackupwindow              string `json:"PreferredBackupWindow,omitempty"`
			Preferredmaintenancewindow         string `json:"PreferredMaintenanceWindow,omitempty"`
			Processorfeatures                  []struct {
				Name  string `json:"Name,omitempty"`
				Value string `json:"Value,omitempty"`
			} `json:"ProcessorFeatures,omitempty"`
			Promotiontier                         int      `json:"PromotionTier,omitempty"`
			Publiclyaccessible                    bool     `json:"PubliclyAccessible,omitempty"`
			Readreplicadbclusteridentifiers       []string `json:"ReadReplicaDBClusterIdentifiers,omitempty"`
			Readreplicadbinstanceidentifiers      []string `json:"ReadReplicaDBInstanceIdentifiers,omitempty"`
			Readreplicasourcedbinstanceidentifier string   `json:"ReadReplicaSourceDBInstanceIdentifier,omitempty"`
			Secondaryavailabilityzone             string   `json:"SecondaryAvailabilityZone,omitempty"`
			Statusinfos                           []struct {
				Message    string `json:"Message,omitempty"`
				Normal     bool   `json:"Normal,omitempty"`
				Status     string `json:"Status,omitempty"`
				Statustype string `json:"StatusType,omitempty"`
			} `json:"StatusInfos,omitempty"`
			Storageencrypted  bool   `json:"StorageEncrypted,omitempty"`
			Tdecredentialarn  string `json:"TdeCredentialArn,omitempty"`
			Timezone          string `json:"Timezone,omitempty"`
			Vpcsecuritygroups []struct {
				Vpcsecuritygroupid string `json:"VpcSecurityGroupId,omitempty"`
				Status             string `json:"Status,omitempty"`
			} `json:"VpcSecurityGroups,omitempty"`
		} `json:"AwsRdsDbInstance,omitempty"`
		Awsrdsdbsnapshot struct {
			Allocatedstorage                 int           `json:"AllocatedStorage,omitempty"`
			Availabilityzone                 string        `json:"AvailabilityZone,omitempty"`
			Dbinstanceidentifier             string        `json:"DbInstanceIdentifier,omitempty"`
			Dbiresourceid                    string        `json:"DbiResourceId,omitempty"`
			Dbsnapshotidentifier             string        `json:"DbSnapshotIdentifier,omitempty"`
			Encrypted                        bool          `json:"Encrypted,omitempty"`
			Engine                           string        `json:"Engine,omitempty"`
			Engineversion                    string        `json:"EngineVersion,omitempty"`
			Iamdatabaseauthenticationenabled bool          `json:"IamDatabaseAuthenticationEnabled,omitempty"`
			Instancecreatetime               string        `json:"InstanceCreateTime,omitempty"`
			Iops                             int           `json:"Iops,omitempty"`
			Kmskeyid                         string        `json:"KmsKeyId,omitempty"`
			Licensemodel                     string        `json:"LicenseModel,omitempty"`
			Masterusername                   string        `json:"MasterUsername,omitempty"`
			Optiongroupname                  string        `json:"OptionGroupName,omitempty"`
			Percentprogress                  int           `json:"PercentProgress,omitempty"`
			Port                             int           `json:"Port,omitempty"`
			Processorfeatures                []interface{} `json:"ProcessorFeatures,omitempty"`
			Snapshotcreatetime               string        `json:"SnapshotCreateTime,omitempty"`
			Snapshottype                     string        `json:"SnapshotType,omitempty"`
			Sourcedbsnapshotidentifier       string        `json:"SourceDbSnapshotIdentifier,omitempty"`
			Sourceregion                     string        `json:"SourceRegion,omitempty"`
			Status                           string        `json:"Status,omitempty"`
			Storagetype                      string        `json:"StorageType,omitempty"`
			Tdecredentialarn                 string        `json:"TdeCredentialArn,omitempty"`
			Timezone                         string        `json:"Timezone,omitempty"`
			Vpcid                            string        `json:"VpcId,omitempty"`
		} `json:"AwsRdsDbSnapshot,omitempty"`
		Awsredshiftcluster struct {
			Allowversionupgrade              bool   `json:"AllowVersionUpgrade,omitempty"`
			Automatedsnapshotretentionperiod int    `json:"AutomatedSnapshotRetentionPeriod,omitempty"`
			Availabilityzone                 string `json:"AvailabilityZone,omitempty"`
			Clusteravailabilitystatus        string `json:"ClusterAvailabilityStatus,omitempty"`
			Clustercreatetime                string `json:"ClusterCreateTime,omitempty"`
			Clusteridentifier                string `json:"ClusterIdentifier,omitempty"`
			Clusternodes                     []struct {
				Noderole         string `json:"NodeRole,omitempty"`
				Privateipaddress string `json:"PrivateIPAddress,omitempty"`
				Publicipaddress  string `json:"PublicIPAddress,omitempty"`
			} `json:"ClusterNodes,omitempty"`
			Clusterparametergroups []struct {
				Clusterparameterstatuslist []struct {
					Parameterapplyerrordescription string `json:"ParameterApplyErrorDescription,omitempty"`
					Parameterapplystatus           string `json:"ParameterApplyStatus,omitempty"`
					Parametername                  string `json:"ParameterName,omitempty"`
				} `json:"ClusterParameterStatusList,omitempty"`
				Parameterapplystatus string `json:"ParameterApplyStatus,omitempty"`
				Parametergroupname   string `json:"ParameterGroupName,omitempty"`
			} `json:"ClusterParameterGroups,omitempty"`
			Clusterpublickey      string `json:"ClusterPublicKey,omitempty"`
			Clusterrevision1      string `json:"ClusterRevision1,omitempty"`
			Clustersecuritygroups []struct {
				Clustersecuritygroupname string `json:"ClusterSecurityGroupName,omitempty"`
				Status                   string `json:"Status,omitempty"`
			} `json:"ClusterSecurityGroups,omitempty"`
			Clustersnapshotcopystatus struct {
				Destinationregion             string `json:"DestinationRegion,omitempty"`
				Manualsnapshotretentionperiod int    `json:"ManualSnapshotRetentionPeriod,omitempty"`
				Retentionperiod               int    `json:"RetentionPeriod,omitempty"`
				Snapshotcopygrantname         string `json:"SnapshotCopyGrantName,omitempty"`
			} `json:"ClusterSnapshotCopyStatus,omitempty"`
			Clusterstatus              string `json:"ClusterStatus,omitempty"`
			Clustersubnetgroupname     string `json:"ClusterSubnetGroupName,omitempty"`
			Clusterversion             string `json:"ClusterVersion,omitempty"`
			Dbname                     string `json:"DBName,omitempty"`
			Deferredmaintenancewindows []struct {
				Defermaintenanceendtime    string `json:"DeferMaintenanceEndTime,omitempty"`
				Defermaintenanceidentifier string `json:"DeferMaintenanceIdentifier,omitempty"`
				Defermaintenancestarttime  string `json:"DeferMaintenanceStartTime,omitempty"`
			} `json:"DeferredMaintenanceWindows,omitempty"`
			Elasticipstatus struct {
				Elasticip string `json:"ElasticIp,omitempty"`
				Status    string `json:"Status,omitempty"`
			} `json:"ElasticIpStatus,omitempty"`
			Elasticresize1Ofnodeoptions string `json:"ElasticResize1OfNodeOptions,omitempty"`
			Encrypted                   bool   `json:"Encrypted,omitempty"`
			Endpoint                    struct {
				Address string `json:"Address,omitempty"`
				Port    int    `json:"Port,omitempty"`
			} `json:"Endpoint,omitempty"`
			Enhancedvpcrouting                     bool   `json:"EnhancedVpcRouting,omitempty"`
			Expectednextsnapshotscheduletime       string `json:"ExpectedNextSnapshotScheduleTime,omitempty"`
			Expectednextsnapshotscheduletimestatus string `json:"ExpectedNextSnapshotScheduleTimeStatus,omitempty"`
			Hsmstatus                              struct {
				Hsmclientcertificateidentifier string `json:"HsmClientCertificateIdentifier,omitempty"`
				Hsmconfigurationidentifier     string `json:"HsmConfigurationIdentifier,omitempty"`
				Status                         string `json:"Status,omitempty"`
			} `json:"HsmStatus,omitempty"`
			Iamroles []struct {
				Applystatus string `json:"ApplyStatus,omitempty"`
				Iamrolearn  string `json:"IamRoleArn,omitempty"`
			} `json:"IamRoles,omitempty"`
			Kmskeyid                       string   `json:"KmsKeyId,omitempty"`
			Maintenancetrackname           string   `json:"MaintenanceTrackName,omitempty"`
			Manualsnapshotretentionperiod  string   `json:"ManualSnapshotRetentionPeriod,omitempty"`
			Masterusername                 string   `json:"MasterUsername,omitempty"`
			Nextmaintenancewindowstarttime string   `json:"NextMaintenanceWindowStartTime,omitempty"`
			Nodetype                       string   `json:"NodeType,omitempty"`
			OneOfnodes                     int      `json:"1OfNodes,omitempty"`
			Pendingactions                 []string `json:"PendingActions,omitempty"`
			Pendingmodifiedvalues          struct {
				Automatedsnapshotretentionperiod int    `json:"AutomatedSnapshotRetentionPeriod,omitempty"`
				Clusteridentifier                string `json:"ClusterIdentifier,omitempty"`
				Clustertype                      string `json:"ClusterType,omitempty"`
				Clusterversion                   string `json:"ClusterVersion,omitempty"`
				Encryptiontype                   string `json:"EncryptionType,omitempty"`
				Enhancedvpcrouting               bool   `json:"EnhancedVpcRouting,omitempty"`
				Maintenancetrackname             string `json:"MaintenanceTrackName,omitempty"`
				Masteruserpassword               string `json:"MasterUserPassword,omitempty"`
				Nodetype                         string `json:"NodeType,omitempty"`
				OneOfnodes                       int    `json:"1OfNodes,omitempty"`
				Publiclyaccessible               string `json:"PubliclyAccessible,omitempty"`
			} `json:"PendingModifiedValues,omitempty"`
			Preferredmaintenancewindow string `json:"PreferredMaintenanceWindow,omitempty"`
			Publiclyaccessible         bool   `json:"PubliclyAccessible,omitempty"`
			Resizeinfo                 struct {
				Allowcancelresize bool   `json:"AllowCancelResize,omitempty"`
				Resizetype        string `json:"ResizeType,omitempty"`
			} `json:"ResizeInfo,omitempty"`
			Restorestatus struct {
				Currentrestorerateinmegabytespersecond int    `json:"CurrentRestoreRateInMegaBytesPerSecond,omitempty"`
				Elapsedtimeinseconds                   int    `json:"ElapsedTimeInSeconds,omitempty"`
				Estimatedtimetocompletioninseconds     int    `json:"EstimatedTimeToCompletionInSeconds,omitempty"`
				Progressinmegabytes                    int    `json:"ProgressInMegaBytes,omitempty"`
				Snapshotsizeinmegabytes                int    `json:"SnapshotSizeInMegaBytes,omitempty"`
				Status                                 string `json:"Status,omitempty"`
			} `json:"RestoreStatus,omitempty"`
			Snapshotscheduleidentifier string `json:"SnapshotScheduleIdentifier,omitempty"`
			Snapshotschedulestate      string `json:"SnapshotScheduleState,omitempty"`
			Vpcid                      string `json:"VpcId,omitempty"`
			Vpcsecuritygroups          []struct {
				Status             string `json:"Status,omitempty"`
				Vpcsecuritygroupid string `json:"VpcSecurityGroupId,omitempty"`
			} `json:"VpcSecurityGroups,omitempty"`
		} `json:"AwsRedshiftCluster,omitempty"`
		Awss3Accountpublicaccessblock struct {
			Blockpublicacls       bool `json:"BlockPublicAcls,omitempty"`
			Blockpublicpolicy     bool `json:"BlockPublicPolicy,omitempty"`
			Ignorepublicacls      bool `json:"IgnorePublicAcls,omitempty"`
			Restrictpublicbuckets bool `json:"RestrictPublicBuckets,omitempty"`
		} `json:"AwsS3AccountPublicAccessBlock,omitempty"`
		Awss3Bucket struct {
			Createdat                      string `json:"CreatedAt,omitempty"`
			Ownerid                        string `json:"OwnerId,omitempty"`
			Ownername                      string `json:"OwnerName,omitempty"`
			Publicaccessblockconfiguration struct {
				Blockpublicacls       bool `json:"BlockPublicAcls,omitempty"`
				Blockpublicpolicy     bool `json:"BlockPublicPolicy,omitempty"`
				Ignorepublicacls      bool `json:"IgnorePublicAcls,omitempty"`
				Restrictpublicbuckets bool `json:"RestrictPublicBuckets,omitempty"`
			} `json:"PublicAccessBlockConfiguration,omitempty"`
			Serversideencryptionconfiguration struct {
				Rules []struct {
					Applyserversideencryptionbydefault struct {
						Kmsmasterkeyid string `json:"KMSMasterKeyID,omitempty"`
						Ssealgorithm   string `json:"SSEAlgorithm,omitempty"`
					} `json:"ApplyServerSideEncryptionByDefault,omitempty"`
				} `json:"Rules,omitempty"`
			} `json:"ServerSideEncryptionConfiguration,omitempty"`
		} `json:"AwsS3Bucket,omitempty"`
		Awss3Object struct {
			Contenttype          string `json:"ContentType,omitempty"`
			Etag                 string `json:"ETag,omitempty"`
			Lastmodified         string `json:"LastModified,omitempty"`
			Serversideencryption string `json:"ServerSideEncryption,omitempty"`
			Ssekmskeyid          string `json:"SSEKMSKeyId,omitempty"`
			Versionid            string `json:"VersionId,omitempty"`
		} `json:"AwsS3Object,omitempty"`
		Awssecretsmanagersecret struct {
			Deleted                         bool   `json:"Deleted,omitempty"`
			Description                     string `json:"Description,omitempty"`
			Kmskeyid                        string `json:"KmsKeyId,omitempty"`
			Name                            string `json:"Name,omitempty"`
			Rotationenabled                 bool   `json:"RotationEnabled,omitempty"`
			Rotationlambdaarn               string `json:"RotationLambdaArn,omitempty"`
			Rotationoccurredwithinfrequency bool   `json:"RotationOccurredWithinFrequency,omitempty"`
			Rotationrules                   struct {
				Automaticallyafterdays int `json:"AutomaticallyAfterDays,omitempty"`
			} `json:"RotationRules,omitempty"`
		} `json:"AwsSecretsManagerSecret,omitempty"`
		Awsssmpatchcompliance struct {
			Patch struct {
				Compliancesummary struct {
					Compliancetype                 string `json:"ComplianceType,omitempty"`
					Compliantcriticalcount         int    `json:"CompliantCriticalCount,omitempty"`
					Complianthighcount             int    `json:"CompliantHighCount,omitempty"`
					Compliantinformationalcount    int    `json:"CompliantInformationalCount,omitempty"`
					Compliantlowcount              int    `json:"CompliantLowCount,omitempty"`
					Compliantmediumcount           int    `json:"CompliantMediumCount,omitempty"`
					Compliantunspecifiedcount      int    `json:"CompliantUnspecifiedCount,omitempty"`
					Executiontype                  string `json:"ExecutionType,omitempty"`
					Noncompliantcriticalcount      int    `json:"NonCompliantCriticalCount,omitempty"`
					Noncomplianthighcount          int    `json:"NonCompliantHighCount,omitempty"`
					Noncompliantinformationalcount int    `json:"NonCompliantInformationalCount,omitempty"`
					Noncompliantlowcount           int    `json:"NonCompliantLowCount,omitempty"`
					Noncompliantmediumcount        int    `json:"NonCompliantMediumCount,omitempty"`
					Noncompliantunspecifiedcount   int    `json:"NonCompliantUnspecifiedCount,omitempty"`
					Overallseverity                string `json:"OverallSeverity,omitempty"`
					Patchbaselineid                string `json:"PatchBaselineId,omitempty"`
					Patchgroup                     string `json:"PatchGroup,omitempty"`
					Status                         string `json:"Status,omitempty"`
				} `json:"ComplianceSummary,omitempty"`
			} `json:"Patch,omitempty"`
		} `json:"AwsSsmPatchCompliance,omitempty"`
		Awssnstopic struct {
			Kmsmasterkeyid string `json:"KmsMasterKeyId,omitempty"`
			Owner          string `json:"Owner,omitempty"`
			Subscription   struct {
				Endpoint string `json:"Endpoint,omitempty"`
				Protocol string `json:"Protocol,omitempty"`
			} `json:"Subscription,omitempty"`
			Topicname string `json:"TopicName,omitempty"`
		} `json:"AwsSnsTopic,omitempty"`
		Awssqsqueue struct {
			Deadlettertargetarn          string `json:"DeadLetterTargetArn,omitempty"`
			Kmsdatakeyreuseperiodseconds int    `json:"KmsDataKeyReusePeriodSeconds,omitempty"`
			Kmsmasterkeyid               string `json:"KmsMasterKeyId,omitempty"`
			Queuename                    string `json:"QueueName,omitempty"`
		} `json:"AwsSqsQueue,omitempty"`
		Awswafwebacl struct {
			Defaultaction string `json:"DefaultAction,omitempty"`
			Name          string `json:"Name,omitempty"`
			Rules         []struct {
				Action struct {
					Type string `json:"Type,omitempty"`
				} `json:"Action,omitempty"`
				Excludedrules []struct {
					Ruleid string `json:"RuleId,omitempty"`
				} `json:"ExcludedRules,omitempty"`
				Overrideaction struct {
					Type string `json:"Type,omitempty"`
				} `json:"OverrideAction,omitempty"`
				Priority int    `json:"Priority,omitempty"`
				Ruleid   string `json:"RuleId,omitempty"`
				Type     string `json:"Type,omitempty"`
			} `json:"Rules,omitempty"`
			Webaclid string `json:"WebAclId,omitempty"`
		} `json:"AwsWafWebAcl,omitempty"`
		Container struct {
			Imageid    string `json:"ImageId,omitempty"`
			Imagename  string `json:"ImageName,omitempty"`
			Launchedat string `json:"LaunchedAt,omitempty"`
			Name       string `json:"Name,omitempty"`
		} `json:"Container,omitempty"`
		Other struct {
			String string `json:"string,omitempty"`
		} `json:"Other,omitempty"`
	} `json:"Details,omitempty"`
	ID           string `json:"Id,omitempty"`
	Partition    string `json:"Partition,omitempty"`
	Region       string `json:"Region,omitempty"`
	Resourcerole string `json:"ResourceRole,omitempty"`
	Tags         struct {
		String string `json:"string,omitempty"`
	} `json:"Tags,omitempty"`
	Type string `json:"Type,omitempty"`
}

// AWSAPIGatewayRestAPI ASFF Resource Detail
type AWSAPIGatewayRestAPI struct {
	APIKeySource          string   `json:"ApiKeySource,omitempty"`
	BinaryMediaTypes      []string `json:"BinaryMediaTypes,omitempty"`
	CreatedDate           string   `json:"CreatedDate,omitempty"`
	Description           string   `json:"Description,omitempty"`
	EndpointConfiguration struct {
		Types []string `json:"Types,omitempty"`
	} `json:"EndpointConfiguration,omitempty"`
	ID                     string `json:"Id,omitempty"`
	MinimumCompressionSize int    `json:"MinimumCompressionSize,omitempty"`
	Name                   string `json:"Name,omitempty"`
	Version                string `json:"Version,omitempty"`
}