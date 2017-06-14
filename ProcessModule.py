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
regex = re.compile("((192\\..*\\..*\\..*)|(10\\..*\\..*\\..*\\..*))")


ipregex = re.compile("..*\\..*\\..*\\..*")

#Open Threat Exchange
headers = {'X-OTX-API-KEY': 'KEY GOES HERE' , 'Accept': 'application/json'} #keys have been regenerated... so don't bother.

#GrayPy Handler Setup for logging
my_logger = logging.getLogger('RITTA-LOG')
my_logger.setLevel(logging.DEBUG)
handler = graypy.GELFHandler('localhost', 12299)
my_logger.addHandler(handler)


#   -------------------================================= END STATIC VARS ===============================-----------------------------

#   -------------------================================= Functions ===============================-----------------------------
#Cache Lookup Function
def locallookup( type, value ):
	if type == "ip":
		result = db.cache.find({ "ip": value }).limit( 1 )
		if result is not None:
			for record in result:
				return record
			
			
	if type == "DNS":
		result = db.cache.find({ "url": value }).limit( 1 )
		if result is not None:
			for record in result:
				return record
			

 
 #Cloud Lookup Functions
def passivetotallookup( query ):
	params = {'query': query}
	response = requests.get(PTurl, auth=PTauth, params=PTheaders)
	loaded_content = json.loads(response.content)
	return loaded_content
	
#query OTX
def OpenThreatExchangelookupDNS( query ):
	url = 'https://otx.alienvault.com:443/api/v1/indicators/domain/' +  query   + '/general'
	print url
	response = requests.get(url, headers=headers)
	if (response.status_code != 200):
		my_logger.debug('BAD Responce Code recived from OTX - EXITING! ' + response.status_code)
		quit()
	loaded_content = json.loads(response.content)
	return loaded_content	
	
	
#query OTX
def OpenThreatExchangelookupIP( query ):
	url = 'https://otx.alienvault.com:443/api/v1/indicators/IPv4/' +  query   + '/general'
	print url
	response = requests.get(url, headers=headers)
	if (response.status_code != 200):
		my_logger.debug('BAD Responce Code recived from OTX - EXITING! ' + response.status_code)
		quit()
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

def openincident(type,record,pulsecount):	
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
		print 'making DB lookup'
		result = db.tolookupip.find().limit( 1 )
		if result is not None:
			for record in result:
				print 'result recived'
				print record['ip']
				#Make sure we are not trying to lookup a local ip range.
				if re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",record['ip']):
					if re.match('/(^127\.0\.0\.1)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)|localhost/', record['ip']):
						deletequeued("ip",record['ip'])
					else:
						my_logger.debug('IP-Record Grabed')
						return record
				else:
					deletequeued("ip",record['ip'])
				
	if type == "DNS":
		result = db.tolookupdnso.find().sort( [ ( "timestamp", pymongo.ASCENDING ) ] ).limit( 1 )
		for record in result:
			if 'local' not in record['url']:
				if 'arpa' not in record['url']:
					my_logger.debug('DNS-Record Grabed')
					return record
					deletequeued("DNS",record['url'])
				else:
					yet = 1
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

	activerecord = None
# -------------------================================= Begin DNS Processing ===============================-----------------------------	
	activerecord = lookupnext("DNS")
	if activerecord is not None:
		result = locallookup("DNS",activerecord['url'])
		print 'DNS cache lookup'
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
						my_logger.debug('RITAA Indicates Potential Threat - ' + activerecord['url'])               # Moving Alerting to Incident Module
						
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
						my_logger.debug('RITAA Indicates Potential Threat - ' + activerecord['url'])                # Moving Alerting to Incident Module
						
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
				my_logger.debug('RITAA Indicates Potential Threat - ' + activerecord['url'])                        # Moving Alerting to Incident Module
				change = deletequeued("DNS",activerecord['url'])
			else:
				change = deletequeued("DNS",activerecord['url'])
	else:
		print 'No DNS record to process. Checking DNS.' 
		time.sleep(2)
		
#         -------------------================================= Begin END DNS Processing ===============================-----------------------------	

#         -------------------=================================  Begin IP Processing   ===============================-----------------------------

	#Get Next
	activerecord = lookupnext("ip")

	#Did we return a record?
	if activerecord is not None:
		#Yes, Attempt Local Lookup
		result = locallookup("ip",activerecord['ip'])
		print 'ip cache lookup'
		#Was it in the Local Cache?
		if result is None: #cache miss
			print 'cache miss'
			
			
			
			#Send Cache Miss event to GrayLog
			my_logger.debug('CacheMiss')
			
			
			#Validate Input Length
			if (activerecord['ip'].isupper() or activerecord['ip'].islower()) is not True:
				#Sleep Timer in the loop to slow down OTX lookups
				time.sleep(2)
				
				#Attempt OTX lookup   
				result = OpenThreatExchangelookupIP(activerecord['ip'])
				
				print(result)
				
				
				#QUEUE AIR RAID SIREN?
				if result['pulse_info']['count'] >= 1:
					print(activerecord['ip'])
					my_logger.debug('RITAA Indicates Potential Threat - ' + activerecord['ip'])               # Moving Alerting to Incident Module
					
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
				my_logger.debug('RITAA Indicates Potential Threat - ' + activerecord['ip'])                        # Moving Alerting to Incident Module
				
				#Log Incident Record
				openincident('ip',activerecord['ip'])				
				
				#Delete Queued Record
				change = deletequeued("ip",activerecord['ip'])
			else:
				#Delete Queued Record
				change = deletequeued("ip",activerecord['ip'])
	else:
		print 'No IP record to process. Checking DNS.' 
		time.sleep(2)
#         -------------------=================================   End IP Processing   ===============================-----------------------------

#         -------------------=================================   End Main   ===============================-----------------------------