# RITAA
Rudimentary Intelligence and Threat Analysis Application,
An ancillary application to add cloud based reputation and analysis web services to provide value to my Graylog instance.

Project Moved to a Private Repo. May be back in the future. 

POC Objectives:
- Pull IP and DNS Data from Graylog HTTP REST API Streams - Complete
- Queue IP and DNS information into MongoDB for processing - Complete
- Process records from mongoDB by:
- Making a local lookup to the MongoDB Threat Cache
- Make a cloud lookup if no Cached record, or cached record is stale
- Cache Record locally after Cloud lookup
- Delete Queued Record
- If a potential threat is detected then create an incident record.
- Validate incident threat via additional cloud resources
- Push gathered incident data to Graylog via GELF


Future Objectives: 
- Add capibilites for multi-threading. 
- Rewrite modules to be OO instead of procedural.
