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
regex = re.compile("")

#Passive Total
PTurl = 'https://api.passivetotal.org/v2/enrichment/malware'
PTauth = ('', '')
PTheaders = {'Accept': 'application/json','fields': 'IP'}

#Open Threat Exchange
headers = {'X-OTX-API-KEY': '' , 'Accept': 'application/json'}



#GrayPy Handler Setup for alarming
my_logger = logging.getLogger('RITTA-ALARM')
my_logger.setLevel(logging.DEBUG)
handler = graypy.GELFHandler('localhost', ****)
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
	
def OpenThreatExchangelookup( query ):
	url = 'https://otx.alienvault.com:443/api/v1/indicators/domain/' +  query   + '/general'
	print url
	response = requests.get(url, headers=headers)
	loaded_content = json.loads(response.content)
	return loaded_content	

#insert cloud lookup into cache
def cachequeuedlookup( type , record, threat ):
	if type == "ip":
		result = db.cache.insert_one({ "ip": record, "timestamp": timestamp,"threat": threat})
		return result
		
	if type == "DNS":
		result = db.cache.insert_one({ "url": record, "timestamp": timestamp,"threat": threat})
		return result

def openincident( , , )		

		
		
#Get Queued Lookup
def lookupnext( type ):	
	if type == "ip":
		result = db.tolookupip.find().sort( [ ( "timestamp", pymongo.ASCENDING ) ] ).limit( 1 )
		if result.count() == 1:
			for record in result:
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
					result = OpenThreatExchangelookup(activerecord['url'][1:])
					print(result)
					print(result['pulse_info']['count'] >= 1)
					if result['pulse_info']['count'] >= 1:
						#QUEUE AIR RAID SIREN!
						print(activerecord['url'])
						#my_logger.debug('RITAA Indicates Potential Threat - ' + activerecord['url'])               # Moving Alerting to Incident Module
						
						cache = cachequeuedlookup("DNS",activerecord['url'],1)
						change = deletequeued("DNS",activerecord['url'])
					else:
						cache = cachequeuedlookup("DNS",activerecord['url'],0)
						change = deletequeued("DNS",activerecord['url'])
				else:
					result = OpenThreatExchangelookup(activerecord['url'])
					print(result)
					print(result['pulse_info']['count'] >= 1)
					if result['pulse_info']['count'] >= 1:
						#QUEUE AIR RAID SIREN!
						print(activerecord['url'])
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
				#my_logger.debug('RITAA Indicates Potential Threat - ' + activerecord['url'])                        # Moving Alerting to Incident Module
				change = deletequeued("DNS",activerecord['url'])
			else:
				change = deletequeued("DNS",activerecord['url'])
	else:
		print 'Waiting For Record' 
		
		
#         -------------------================================= Begin END DNS Processing ===============================-----------------------------	

#         -------------------=================================  Begin IP Processing   ===============================-----------------------------






#         -------------------=================================   End IP Processing   ===============================-----------------------------
