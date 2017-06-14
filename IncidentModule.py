#Graylog Stream Incident Service
#Teagan Wilson
#9/29/16
#Grabs incident records, makes a second lookup for enrichment to passive total and posts results to graylog.

from pymongo import MongoClient
import pymongo
import json
import requests
import time
import urllib2
import re
import graypy
import logging
import time

from passivetotal.libs.enrichment import EnrichmentRequest
from passivetotal.response import Response

#Setup Database Connection
client = MongoClient()
db = client.queue

#GrayPy Handler Setup for alarming
my_logger = logging.getLogger('RITTA-ALARM')
my_logger.setLevel(logging.WARNING)
handler = graypy.GELFHandler('localhost', 5547)
my_logger.addHandler(handler)

#GrayPy Handler Setup for logging
my_logger2 = logging.getLogger('RITTA-LOG')
my_logger2.setLevel(logging.DEBUG)
handler2 = graypy.GELFHandler('localhost', 12299)
my_logger2.addHandler(handler2)

#Cloud Lookup Functions
def passivetotallookup( query ):
	params = {'query': query}
	response = requests.get(PTurl, auth=PTauth, params=PTheaders)
	loaded_content = json.loads(response.content)
	return loaded_content
	
#Passive Total
PTurl = 'https://api.passivetotal.org/v2/enrichment/malware'

PTheaders = {'Accept': 'application/json','fields': 'IP'}


#Static Variables
timestamp = int(time.time())
ipurl = 'https://graylog.shickusa.com:12900/search/universal/relative?query=*&range=60&limit=1000&filter=streams:5798f1ad4894b436df435fa6'
dnsurl = 'https://graylog.shickusa.com:12900/search/universal/relative?query=*&range=60&limit=1000&filter=streams:579a55dc4894b42940bbad7f'
auth = ("graylog username", "graylog password")
params = {'fields': 'IP,Name', 'Accept' : 'application/json'}
headers = {'Accept': 'application/json','fields': 'IP'}


#Query Passive Total
def secondLevelCheck( type , record ):
	if record is not None:
		client = EnrichmentRequest('Passive Total Username', 'Passive Total Password')
		
		if type == "ip":
			payload = {'query': record['ip']}
			response = client.get_malware(**payload)
			
			#Malware hashes have been associated with this query
			if len(response['results']) > 0:
				#include and alarm
				my_logger.debug('IP,' + record["ip"] + ',' + record["timestamp"] + ',' + record["OTXCount"] + ',' + len(response["results"]) + ';' + response)
			else:
				my_logger.debug('IP,' + record["ip"] + ',' + record["timestamp"] + ',' + record["OTXCount"] + ',' + ';')
		if type == "DNS":
			payload = {'query': record['url']}
			response = client.get_malware(**payload)
			
			#Malware hashes have been associated with this query
			if len(response['results']) > 0:
				#include and alarm
				my_logger.debug('DNS,' + record["url"] + ',' + record["timestamp"] + ',' + record["OTXCount"] + ',' + len(response["results"]) +  ';' + response)
			else:
				my_logger.debug('DNS,' + record["url"] + ',' + record["timestamp"] + ',' + record["OTXCount"] + ',' + ';')
				
#Query Stream Function
def getNextIncident():
	result = db.incident.find().limit( 1 )
	for record in result:
		result = db.incident.delete_one({'timestamp': record['timestamp']})
		return record	
				

my_logger2.debug('RITAA Incident Module started')	

while True:	
	record = getNextIncident()
	print "Found No Record"
	if record:
		if hasattr(record, 'ip'):
			print "Found IP Record"
			my_logger2.debug('RITTA Incident Module Found IP Incident')
			secondLevelCheck('IP',record)
			time.sleep(1)
			
		if hasattr(record, 'url'):
			print "Found DNS Record"
			my_logger2.debug('RITTA Incident Module Found DNS Incident')
			secondLevelCheck('DNS',record)
			time.sleep(1)
	else:
		time.sleep(1)