[comment]: # "Auto-generated SOAR connector documentation"
# Cyware CTIX

Publisher: Cyware Labs  
Connector Version: 1\.0\.1  
Product Vendor: Cyware Labs  
Product Name: Cyware Threat Intel eXchange  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.9\.39220  

Cyware Threat Intel eXchange is an intelligent client\-server intelligence exchange that provides subscriber with full Threat Intel collection management from multiple internal and external sources

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Cyware Threat Intel eXchange asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**access\_id** |  required  | password | Access ID
**secret\_key** |  required  | password | Authentication Secret Key
**baseurl** |  required  | string | Base URL for CTIX REST API
**verify\_server\_cert** |  optional  | boolean | Verify server certificate

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity  
[lookup domain](#action-lookup-domain) - Search IOCs in CTIX for matching Domain  
[lookup hash](#action-lookup-hash) - Search IOCs in CTIX for matching Hash  
[lookup ip](#action-lookup-ip) - Search IOCs in CTIX for matching IP Address  
[lookup url](#action-lookup-url) - Search IOCs in CTIX for matching URL  

## action: 'test connectivity'
Validate the asset configuration for connectivity

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'lookup domain'
Search IOCs in CTIX for matching Domain

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to run the lookup on | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.data\.\*\.result\.score | numeric | 
action\_result\.data\.\*\.result\.created | numeric | 
action\_result\.data\.\*\.result\.updated | numeric | 
action\_result\.data\.\*\.result\.domain\_data | string | 
action\_result\.data\.\*\.result\.package\_count | string | 
action\_result\.data\.\*\.result\.packages\_list | string | 
action\_result\.data\.\*\.result\.stix\_object\_id | string | 
action\_result\.data\.\*\.result\.misp\_warninglist\_status | string | 
action\_result\.data\.\*\.result\.zscaler\_enrichment\_status | string | 
action\_result\.data\.\*\.result\.cisco\_umbrella\_status | string | 
action\_result\.data\.\*\.result\.geoip\_report | string | 
action\_result\.data\.\*\.result\.cisco\_umbrella\_status | string | 
action\_result\.data\.\*\.result\.cisco\_umbrella\_malicious | string | 
action\_result\.data\.\*\.result\.misp\_warninglist\_malicious | string | 
action\_result\.data\.\*\.result\.misp\_warninglist\_domain\_report | string | 
action\_result\.data\.\*\.result\.cisco\_umbrella\_domain\_report | string | 
action\_result\.data\.\*\.result\.zscaler\_enrichment\_malicious | string | 
action\_result\.data\.\*\.result\.zscaler\_enrichment\_domain\_report | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup hash'
Search IOCs in CTIX for matching Hash

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash to run the lookup on | string |  `hash` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.hash | string |  `hash` 
action\_result\.data\.\*\.result\.score | numeric | 
action\_result\.data\.\*\.result\.created | numeric | 
action\_result\.data\.\*\.result\.updated | numeric | 
action\_result\.data\.\*\.result\.hash\_data | string | 
action\_result\.data\.\*\.result\.package\_count | string | 
action\_result\.data\.\*\.result\.packages\_list | string | 
action\_result\.data\.\*\.result\.stix\_object\_id | string | 
action\_result\.data\.\*\.result\.misp\_warninglist\_status | string | 
action\_result\.data\.\*\.result\.zscaler\_enrichment\_status | string | 
action\_result\.data\.\*\.result\.virus\_total\_hash\_report | string | 
action\_result\.data\.\*\.result\.zscaler\_enrichment\_hash\_report | string | 
action\_result\.data\.\*\.result\.mandiant\_threat\_intelligence\_hash\_report | string | 
action\_result\.data\.\*\.result\.cisco\_umbrella\_malicious | string | 
action\_result\.data\.\*\.result\.misp\_warninglist\_malicious | string | 
action\_result\.data\.\*\.result\.alien\_vault\_hash\_report | string | 
action\_result\.data\.\*\.result\.cisco\_umbrella\_domain\_report | string | 
action\_result\.data\.\*\.result\.zscaler\_enrichment\_malicious | string | 
action\_result\.data\.\*\.result\.comodo\_hash\_report | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup ip'
Search IOCs in CTIX for matching IP Address

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP Address to run the lookup on | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.data\.\*\.result\.score | numeric | 
action\_result\.data\.\*\.result\.created | numeric | 
action\_result\.data\.\*\.result\.updated | numeric | 
action\_result\.data\.\*\.result\.hash\_data | string | 
action\_result\.data\.\*\.result\.package\_count | string | 
action\_result\.data\.\*\.result\.packages\_list | string | 
action\_result\.data\.\*\.result\.stix\_object\_id | string | 
action\_result\.data\.\*\.result\.misp\_warninglist\_status | string | 
action\_result\.data\.\*\.result\.zscaler\_enrichment\_status | string | 
action\_result\.data\.\*\.result\.virus\_total\_hash\_report | string | 
action\_result\.data\.\*\.result\.zscaler\_enrichment\_hash\_report | string | 
action\_result\.data\.\*\.result\.mandiant\_threat\_intelligence\_hash\_report | string | 
action\_result\.data\.\*\.result\.cisco\_umbrella\_malicious | string | 
action\_result\.data\.\*\.result\.misp\_warninglist\_malicious | string | 
action\_result\.data\.\*\.result\.alien\_vault\_hash\_report | string | 
action\_result\.data\.\*\.result\.cisco\_umbrella\_domain\_report | string | 
action\_result\.data\.\*\.result\.zscaler\_enrichment\_malicious | string | 
action\_result\.data\.\*\.result\.comodo\_hash\_report | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup url'
Search IOCs in CTIX for matching URL

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to run the lookup on | string |  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.url | string |  `url` 
action\_result\.data\.\*\.result\.score | numeric | 
action\_result\.data\.\*\.result\.created | numeric | 
action\_result\.data\.\*\.result\.updated | numeric | 
action\_result\.data\.\*\.result\.hash\_data | string | 
action\_result\.data\.\*\.result\.package\_count | string | 
action\_result\.data\.\*\.result\.packages\_list | string | 
action\_result\.data\.\*\.result\.stix\_object\_id | string | 
action\_result\.data\.\*\.result\.misp\_warninglist\_status | string | 
action\_result\.data\.\*\.result\.zscaler\_enrichment\_status | string | 
action\_result\.data\.\*\.result\.virus\_total\_hash\_report | string | 
action\_result\.data\.\*\.result\.zscaler\_enrichment\_hash\_report | string | 
action\_result\.data\.\*\.result\.mandiant\_threat\_intelligence\_hash\_report | string | 
action\_result\.data\.\*\.result\.cisco\_umbrella\_malicious | string | 
action\_result\.data\.\*\.result\.misp\_warninglist\_malicious | string | 
action\_result\.data\.\*\.result\.alien\_vault\_hash\_report | string | 
action\_result\.data\.\*\.result\.cisco\_umbrella\_domain\_report | string | 
action\_result\.data\.\*\.result\.zscaler\_enrichment\_malicious | string | 
action\_result\.data\.\*\.result\.comodo\_hash\_report | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 