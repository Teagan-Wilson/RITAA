from pymongo import MongoClient
import pymongo
import json
import requests
import time
import logging
import graypy
import re
import threading
import urllib2
from passivetotal.libs.enrichment import EnrichmentRequest
from passivetotal.response import Response
import pdb

querythreads = 1
processthreads = 3
incidentthreads = 1

def processModule():
	#Setup Database Connection
	client = MongoClient()
	db = client.queue

	#Static Variables
	timestamp = int(time.time())

	#LocalIP RegEX
	regex = re.compile("((192\\..*\\..*\\..*)|(10\\..*\\..*\\..*\\..*))")


	ipregex = re.compile("..*\\..*\\..*\\..*")

	#Open Threat Exchange
	headers = {'X-OTX-API-KEY': '' , 'Accept': 'application/json'} 

	#GrayPy Handler Setup for logging

	my_logger = logging.getLogger('RITTA-LOG')
	my_logger.setLevel(logging.DEBUG)
	handler = graypy.GELFHandler('localhost', 12299) #Hostname, port
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
		my_logger.debug('DNS OTX lookup made for ' + query )
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
		my_logger.debug('IP OTX lookup made ' + query )
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
			result = db.tolookupip.find_one_and_delete({})
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
			result = db.tolookupdnso.find_one_and_delete({})
			for record in result:
				if 'local' not in record['url']:
					if 'arpa' not in record['url']:
						my_logger.debug('DNS-Record Grabed')
						return record
						
					else:
						yet = 1
				else:
					deletequeued("DNS",record['url'])
					
	#Delete queued lookup
	def deletequeued( type, query ): 
		if type == "ip":
			result = db.tolookupip.delete_many({'ip': query})
			return result
			
		if type == "DNS":
			result = db.tolookupdnso.delete_many({'url': query})
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
					openincident('ip',activerecord['ip'],1)				
					
					#Delete Queued Record
					change = deletequeued("ip",activerecord['ip'])
				else:
					#Delete Queued Record
					change = deletequeued("ip",activerecord['ip'])
		else:
			print 'No IP record to process. Checking DNS.' 
			time.sleep(2)

def incidentModule():
	#   -------------------================================= Begin Incident Module==============================-----------------------------
	#Setup Database Connection
	client = MongoClient()
	db = client.queue

	#GrayPy Handler Setup for alarming
	my_logger = logging.getLogger('RITTA-ALARM')
	my_logger.setLevel(logging.WARNING)
	handler = graypy.GELFHandler('localhost', 5547) #Hostname, port
	my_logger.addHandler(handler)

	#GrayPy Handler Setup for logging
	my_logger2 = logging.getLogger('RITTA-LOG')
	my_logger2.setLevel(logging.DEBUG)
	handler2 = graypy.GELFHandler('localhost', 12299) #Hostname, port
	my_logger2.addHandler(handler2)

	#Cloud Lookup Functions
	def passivetotallookup( query ):
		params = {'query': query}
		response = requests.get(PTurl, auth=PTauth, params=PTheaders)
		loaded_content = json.loads(response.content)
		return loaded_content
		
	#Passive Total
	PTurl = 'https://api.passivetotal.org/v2/enrichment/malware'
	PTauth = ('', '') #Passive Total Username, password
	PTheaders = {'Accept': 'application/json','fields': 'IP'}


	#Static Variables
	timestamp = int(time.time())

	#Query Passive Total
	def secondLevelCheck( type , record ):
		if record is not None:
			client = EnrichmentRequest('', '') #Passive Total Username, api key
			
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
		#   -------------------================================= END Incident Module==============================-----------------------------

def queryModule():
		#   -------------------================================= Begin Query Module==============================-----------------------------
	#Setup Database Connection
	client = MongoClient()
	db = client.queue

	#Static Variables
	timestamp = int(time.time())
	ipurl = '' #URL for Graylog IP Stream
	dnsurl = '' #URL for Graylog DNS Stream
	auth = ("", "") #Username, Password
	params = {'fields': 'DestinationIP,Name', 'Accept' : 'application/json'}
	headers = {'Accept': 'application/json','fields': 'DestinationIP,Name'}


	#Query Stream Function
	def QueryGLS(url):
		response = requests.get(url, auth=auth, params=params, headers=headers,verify=False)
		loaded_content = json.loads(response.content)
		return loaded_content

	#Insert IP Function
	def insertIP( ip, timestamp ):
		result = db.tolookupip.insert_one({ "ip": ip, "timestamp": timestamp})

	#Insert DNS Function
	def insertDNS( url , timestamp ):
		result = db.tolookupdnso.insert_one({ "url": url, "timestamp": timestamp})
		print result.inserted_id
		
	while True:	
		#Get Streams from Graylog
		slipstreamIP = QueryGLS(ipurl)
		slipstreamDNS = QueryGLS(dnsurl)

		#Process IP Stream and Insert into Queue
		for ip in slipstreamIP['messages']:
			print(ip['message']['DestinationIP'])
			insertIP(ip['message']['DestinationIP'],timestamp)
			
		time.sleep(60)
	#Process DNS logs and Insert into Queue
		for ip in slipstreamDNS['messages']:
			pat = re.compile("\(0\)")
			ip['message']['Name'] = pat.sub("",ip['message']['Name'])
			pat = re.compile("^\.")
			ip['message']['Name'] = pat.sub("",ip['message']['Name'])
			pat = re.compile("(\(\w+\))+")
			ip['message']['Name'] = pat.sub(".",ip['message']['Name'])
			insertDNS(ip['message']['Name'],timestamp)
		#   -------------------================================= Begin Process Module==============================-----------------------------
		
qthreads = []
pthreads = []
ithreads = []
for x in range(querythreads):
	t = threading.Thread(target=queryModule)
	qthreads.append(t)
	t.start()

for x in range(processthreads):
	t = threading.Thread(target=processModule)
	pthreads.append(t)
	t.start()
for x in range(incidentthreads):
	t = threading.Thread(target=incidentModule)
	ithreads.append(t)
	t.start()
