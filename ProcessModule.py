from pymongo import MongoClient
import json
import requests
import time

#Setup Database Connection
client = MongoClient()
db = client.test

#Static Variables
timestamp = int(time.time())
#Passive Total
url = 'https://api.passivetotal.org/v2/enrichment/malware'
auth = ()


# Lookup function
def locallookup( ip ):
	result = db.find({ "ip": ip})
	if result.count() == 1:
		for record in result:
			threat = record
		if threat == 1:                                                       #ADD THREAT Number (binary for threatcroud, some others have 1-10)
			
	 
 
 
 
 
 
 
 
 
# Insert Function
def insert( ip, threat ):
	result = db.test.insert_one({ "ip": ip,"threat": threat, "Count": 1, "query":""})


# Check Function
def check( ip ):
	params = {'query': 'noorno.com'}
	response = requests.get(url, auth=auth, params=params)
	loaded_content = json.loads(response.content)
	return loaded_content
 
 
 
 
 
