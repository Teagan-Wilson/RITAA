# RITAA
Rudimentary Intelligence and Threat Analysis Application
An ancillary application to add cloud based reputation and analysis web services to provide value to my Graylog instance.

POC Objectives:
- Pull IP and DNS Data from Graylog HTTP REST API Streams
- Queue IP and DNS information into MongoDB for processing
- Process records from mongoDB by:
    -Making a local lookup to the MongoDB Threat Cache
    -Make a cloud lookup if no Cached record, or cached record is stale
    -Cache Record locally after Cloud lookup
    -If a potential threat is detected then Push record to graylog threat alarm input.
    -Delete Queued Record
