from pymongo import MongoClient
import pymongo
import json
import requests
import time
import logging
import graypy
import re



#   -------------------=================================STATIC VARS===============================-----------------------------
#Setup Database Connection
client = MongoClient()
db = client.queue

#Static Variables
timestamp = int(time.time())

#LocalIP RegEX
regex = re.compile("((192\\..*\\..*\\..*)|(10\\..*\\.*\\..*\\..*))")

#Passive Total
PTurl = 'https://api.passivetotal.org/v2/enrichment/malware'
PTauth = ('teagan.wilson@shicksolutions.com', '4017f666d65c167ed401d05100be3cba7087f3f1eaefaa4c6928ee550907b376') #keys have been regenerated... so don't bother.
PTheaders = {'Accept': 'application/json','fields': 'IP'}

#Open Threat Exchange
headers = {'X-OTX-API-KEY': 'b53c9c947d2340ee6a141a3345522a4e49f4f16fb7a61b02de2da99b82909aa3' , 'Accept': 'application/json'} #keys have been regenerated... so don't bother.


#GrayPy Handler Setup for alarming
my_logger = logging.getLogger('RITTA-ALARM')
my_logger.setLevel(logging.DEBUG)
handler = graypy.GELFHandler('localhost', 5547)
my_logger.addHandler(handler)
#   -------------------================================= END STATIC VARS ===============================-----------------------------

#   -------------------================================= Functions ===============================-----------------------------
#Cache Lookup Function
def locallookup( type, value ):
	if type == "ip":
		result = db.cache.find({ "ip": value }).sort( [ ( "timestamp", pymongo.ASCENDING ) ] ).limit( 1 )
		if result is not None:
			for record in result:
				return record
			
			
	if type == "DNS":
		result = db.cache.find({ "url": value }).sort( [ ( "timestamp", pymongo.ASCENDING ) ] ).limit( 1 )
		if result is not None:
			for record in result:
				return record
			

 
 #Cloud Lookup Functions
def passivetotallookup( query ):
	params = {'query': query}
	response = requests.get(PTurl, auth=PTauth, params=PTheaders)
	loaded_content = json.loads(response.content)
	return loaded_content
	
def OpenThreatExchangelookupDNS( query ):
	url = 'https://otx.alienvault.com:443/api/v1/indicators/domain/' +  query   + '/general'
	print url
	response = requests.get(url, headers=headers)
	loaded_content = json.loads(response.content)
	return loaded_content	

#insert cloud lookup into cache
def cachequeuedlookup( type , record, threat ):
	timestamp = int(time.time())
	if type == "ip":
		result = db.cache.insert_one({ "ip": record, "timestamp": timestamp,"threat": threat})
		return result
		
	if type == "DNS":
		result = db.cache.insert_one({ "url": record, "timestamp": timestamp,"threat": threat})
		return result

def openincident(type,record,pulsecount)	
	timestamp = int(time.time())	
	if type == "ip":
		result = db.incident.insert_one({ "ip": record, "timestamp": timestamp,"OTXCount": pulsecount})
		return result
		
	if type == "DNS":
		result = db.incident.insert_one({ "url": record, "timestamp": timestamp,"OTXCount": pulsecount})
		return result
		
		
#Get Queued Lookup
def lookupnext( type ):	
	if type == "ip":
		result = db.tolookupip.find().sort( [ ( "timestamp", pymongo.ASCENDING ) ] ).limit( 1 )
		if result.count() == 1:
			for record in result:
				
				#Make sure we are not trying to lookup a local ip range.
				if re.match(regex, record['ip']) is not None:
					deletequeued("ip",record['ip'])
				else:
					my_logger.debug('IP-Record Grabed')
					return record
					
				
	if type == "DNS":
		result = db.tolookupdnso.find().sort( [ ( "timestamp", pymongo.ASCENDING ) ] ).limit( 1 )
		for record in result:
			if 'local' not in record['url']:
				if 'arpa' not in record['url']:
					my_logger.debug('DNS-Record Grabed')
					return record
				else:
					deletequeued("DNS",record['url'])
				
			else:
				deletequeued("DNS",record['url'])
				
#Delete queued lookup
def deletequeued( type, query ): 
	if type == "ip":
		result = db.tolookupip.delete_one({'ip': query})
		return result
		
	if type == "DNS":
		result = db.tolookupdnso.delete_one({'url': query})
		return result
#   -------------------================================= END Functions ===============================-----------------------------	
	
	
#   -------------------================================= Begin Main ===============================-----------------------------	

while True:

# -------------------================================= Begin DNS Processing ===============================-----------------------------	
	activerecord = lookupnext("DNS")
	if activerecord is not None:
		result = locallookup("DNS",activerecord['url'])
		if result is None: #cache miss
			print 'cache miss'
			time.sleep(2)
			my_logger.debug('CacheMiss')
			if len(activerecord['url']) < 30:
				if activerecord['url'][:1] == ".":
					result = OpenThreatExchangelookupDNS(activerecord['url'][1:])
					print(result)
					print(result['pulse_info']['count'] >= 1)
					if result['pulse_info']['count'] >= 1:
						#QUEUE AIR RAID SIREN!
						print(activerecord['url'])
						openincident('DNS',activerecord['url'], result['pulse_info']['count'])	
						#my_logger.debug('RITAA Indicates Potential Threat - ' + activerecord['url'])               # Moving Alerting to Incident Module
						
						cache = cachequeuedlookup("DNS",activerecord['url'],1)
						change = deletequeued("DNS",activerecord['url'])
					else:
						cache = cachequeuedlookup("DNS",activerecord['url'],0)
						change = deletequeued("DNS",activerecord['url'])
				else:
					result = OpenThreatExchangelookupDNS(activerecord['url'])
					print(result)
					print(result['pulse_info']['count'] >= 1)
					if result['pulse_info']['count'] >= 1:
						#QUEUE AIR RAID SIREN!
						print(activerecord['url'])
						openincident('DNS',activerecord['url'], result['pulse_info']['count'])	
						#my_logger.debug('RITAA Indicates Potential Threat - ' + activerecord['url'])                # Moving Alerting to Incident Module
						
						cache = cachequeuedlookup("DNS",activerecord['url'],1)
						change = deletequeued("DNS",activerecord['url'])
					else:
						cache = cachequeuedlookup("DNS",activerecord['url'],0)
						change = deletequeued("DNS",activerecord['url'])
			else:
				change = deletequeued("DNS",activerecord['url'])
		else:
			print 'Cache Hit'
			my_logger.debug('CacheHit')
			print(activerecord['url'])
			if result['threat'] == 1:
				#QUEUE AIR RAID SIREN!
				print(activerecord['url'])
				openincident('DNS',activerecord['url'], result['pulse_info']['count'])	
				#my_logger.debug('RITAA Indicates Potential Threat - ' + activerecord['url'])                        # Moving Alerting to Incident Module
				change = deletequeued("DNS",activerecord['url'])
			else:
				change = deletequeued("DNS",activerecord['url'])
	else:
		print 'No DNS record to process. Checking DNS.' 
		
		
#         -------------------================================= Begin END DNS Processing ===============================-----------------------------	

#         -------------------=================================  Begin IP Processing   ===============================-----------------------------

#Get Next
activerecord = lookupnext("ip")

	#Did we return a record?
	if activerecord is not None:
	
		#Yes, Attempt Local Lookup
		result = locallookup("ip",activerecord['ip'])
		
		#Was it in the Local Cache?
		if result is None: #cache miss
			print 'cache miss'
			
			#Sleep Timer in the loop to slow down OTX lookups
			time.sleep(2)
			
			#Send Cache Miss event to GrayLog
			my_logger.debug('CacheMiss')
			
			
			#Validate Input Length
			if len(activerecord['ip']) <= 16:
					
					#Attempt OTX lookup   
					result = OpenThreatExchangelookupIP(activerecord['ip'])
					
					print(result)
					print(result['pulse_info']['count'] >= 1)
					
					#QUEUE AIR RAID SIREN?
					if result['pulse_info']['count'] >= 1:
						
						print(activerecord['ip'])
						#my_logger.debug('RITAA Indicates Potential Threat - ' + activerecord['url'])               # Moving Alerting to Incident Module
						
						#Log Incident Record
						openincident('ip',activerecord['ip'], result['pulse_info']['count'])
						
						#Cache OTX lookup and Delete Queued Record
						cache = cachequeuedlookup("ip",activerecord['ip'],1)
						change = deletequeued("ip",activerecord['ip'])
					else:
						#Cache OTX lookup and Delete Queued Record
						cache = cachequeuedlookup("ip",activerecord['ip'],0)
						change = deletequeued("ip",activerecord['ip'])

			else:
				#ip malformed, delete queued
				change = deletequeued("ip",activerecord['ip'])
		else:
			
			print 'Cache Hit'
			my_logger.debug('CacheHit')
			
			print(activerecord['ip'])
			#QUEUE AIR RAID SIREN?
			if result['threat'] == 1:
				
				print(activerecord['ip'])
				#my_logger.debug('RITAA Indicates Potential Threat - ' + activerecord['url'])                        # Moving Alerting to Incident Module
				
				#Log Incident Record
				openincident('ip',activerecord['ip'], result['pulse_info']['count'])				
				
				#Delete Queued Record
				change = deletequeued("ip",activerecord['ip'])
			else:
				#Delete Queued Record
				change = deletequeued("ip",activerecord['ip'])
	else:
		print 'No IP record to process. Checking DNS.' 

#         -------------------=================================   End IP Processing   ===============================-----------------------------

#         -------------------=================================   End Main   ===============================-----------------------------
