# RITAA
Rudimentary Intelligence and Threat Analysis Application,
An ancillary application to add cloud based reputation and analysis web services to provide value to my Graylog instance.


POC Objectives:
- Pull IP and DNS Data from Graylog HTTP REST API Streams     - Complete
- Queue IP and DNS information into MongoDB for processing    - Complete
- Process records from mongoDB by:
- Making a local lookup to the MongoDB Threat Cache           - Complete
- Make a cloud lookup if no Cached record                     - Complete
- Cache Record locally after Cloud lookup                     - Complete
- Delete Queued Record  - Complete
- If a potential threat is detected then create an incident record.  - Complete
- Validate incident threat via additional cloud resources            - Complete
- Push gathered incident data to Graylog via GELF                    - Complete


Future Objectives: 
- Add capibilites for multi-threading. - Multiple itterations of the Process Module can now be ran at the same time - Complete
- Rewrite modules to be OO instead of procedural. 
