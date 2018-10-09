#!/usr/bin/python
#
#DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
#                    Version 3, August 2017
#Everyone is permitted to copy and distribute verbatim or modified
#copies of this license document, and changing it is allowed as long
#as the name is changed.
#           DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
# TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
#
#1. You just DO WHAT THE FUCK YOU WANT TO.
#2. As the "THE BEER-WARE LICENSE", if we meet some day, and you
# think this stuff is worth it, you can buy me a beer in return.
#
#         ///\\\  ( Have Fun )
#        / ^  ^ \ /
#      __\  __  /__
#     / _ `----' _ \
#     \__\   _   |__\
#      (..) _| _ (..)
#       |____(___|     Mynameisv
#_ __ _ (____)____) _ _________________________________ _'
###########################################################
# MS Update retriever
#############################
# Download and parse single MS security update
#
# [ History ]
# * 2017-07
#  o creation
#
#############################
#
##
###
###########################################################
# Python Imports
#############################
import copy
import datetime
import json
import os
import re
import sys
from lxml import etree
from obj_RequestsWrap import objRequestsWrap
#
##
###
################################################################
## Parameters, Config and Prerequisites
################################
#
##
###
###########################################################
# Object
#############################
class objMsUpdate:
	#
	################################
	def __init__(self, dUpdateConfig):
		"""
		:param dict dUpdateConfig: a json dictionnary containing informations about this ms update. For details see "obj_MsUpdates.py->def get(self, dConfig={})". One important point, here we add elements like : u'isoob':true|false, for a out of band bulletin
		"""
		#
		# API Key
		self.sApiKey = u''
		#
		# XML Object containing the update (after fetching)
		self.oXml = None
		#
		################################
		# Bulletin's products list
		# { 'ProductId':{'vendorname':..., 'famillyname':..., 'fullname':...}, 'ProductId2':{}, 'ProductId3':...
		self.dProducts ={}
		#
		# Bulletins titles, loaded from a json file
		self.lBulletinsNames = []
		#
		# Hard coded bulletin titles
		self.dHCBulletinsName = {
				u'HARD-CODED-MIXEDGEIE': u'**MixEdgeOrIe**',
				u'HARD-CODED-IE': u'Internet Explorer',
				u'HARD-CODED-EDGE': u'Edge',
				u'HARD-CODED-FLASH': u'Adobe Flash'
		}
		#
		# Hard coded severity
		# To calculate an average value, we sum each affected product severy
		# to avoid problems, we assume the can be more than 100 affected products if we do a sum (a way to proceed, the other is to keep the max)
		self.lHCSeverity = [
				{u'severity':u'low', u'grade': 1},
				{u'severity':u'moderate', u'grade': 1*100},
				{u'severity':u'important', u'grade': 1*100*100},
				{u'severity':u'critical', u'grade': 1*100*100*100}
		]
		#
		################################
		# Number of vulns
		self.iVulnerabilitiesCount = 0
		#
		# MS Bulletin fixed with real references
		# it's last bulletin ref of the date	
		self.dMsBulletinRealReferences = [
			{u'date':201604, u'ref':36},
			{u'date':201704, u'ref':23}
		]
		#
		# Bulletin Reference Prefix
		self.sBulletinReferencePrefix = u'MS'
		# Shared current year of bulletin, changed during processing
		self.iBulletinReferenceCurrentYear = 0
		# Shared current bulletin ref, like 10 in MS17-010, changed during processing
		self.iBulletinReferenceCurrentRef = 0
		#
		# Unsorted dictionnary of bulletins. For details see buildMsBulletins
		self.dMSBulletins = {}
		# Sorted (after sort) list of link to self.dMSBulletins
		# { 'bulletinname':bulletin-name, 'severity': 12345 }
		self.lMSBulletinsSortedBySeverity = []		
		#
		# Local dictionnary of all processes bulletin number, just to remember ;-)
		self.dMSBulletinReferences = {}
		#
		################################
		#
		# Check the dictionnary minimum needs
		if (type(dUpdateConfig)!=dict):
			print u' [!] Config is not a dictionnary'
			return None
		#
		lIndexes = [u'CvrfUrl', u'ID', u'RealReleaseDate']
		for sCeil in lIndexes:
			if (sCeil not in dUpdateConfig):
				print u' [!] Missing %s in Update Config' % (sCeil)
				return None
		#
		# Duplicate local update config dictionnary, to make this object independant
		self.dUpdateConfig = copy.deepcopy(dUpdateConfig)
		#
		# Load bulletins names
		self.loadBulletinsNamesFromFileFromFile()
		#
	#end __init__
	#
	#############################
	def iso8601ToDatetime(self, sDate):
		"""
		Convert release date from  ISO 8601 to datetime.datetime
		Dirty way, without supporting real UTC :-/
		
		:param str sDate: date as ISO 8601 to convert
		:return: datetime.datetime
		"""
		oDate = datetime.datetime.strptime(sDate, '%Y-%m-%dT%H:%M:%SZ')
		return oDate
	#end iso8601ToDatetime
	#
	#############################
	def setApiKey(self, value):
		"""
		Set Microsoft Security Update REST API Key

		:param str value: api key
		"""
		"""
		Set api key
		:param str value:		api key, as string
		"""
		self.sApiKey = value.strip()
	#end setApiKey
	#
	#############################
	def setLastBulletinYear(self, iYear):
		"""
		Set release year of the last bulletin, usefull when year change during processing between 2 bulletins

		:param int iYear: year
		"""
		self.iBulletinReferenceCurrentYear = iYear
	#end setLastBulletinYear
	#
	#############################
	def loadBulletinsNamesFromFileFromFile(self, sFilePath=u'bulletins_names.json'):
		"""
		Load hard coded bulletins names from a json file
		:param str sFilePath: Json file path
		"""
		#
		# Load local bulletin title hard coded file
		if os.path.isfile(sFilePath):
			#
			# Get file contents
			with open(sFilePath,'rb') as oFile:
				sContent = oFile.read()
			#
			# Remove comments for parsing
			sContent = re.sub('\#.*\r\n', '\n', sContent)
			#
			# Dirty patch 'cause Microsoft is dirty !
			for sIndex in self.dHCBulletinsName:
				sContent = sContent.replace(sIndex, self.dHCBulletinsName[sIndex])
			#
			# Parse Json content
			try:
				self.lBulletinsNames = json.loads(sContent)
			except Exception, e:
				print '[!] Error, parsing Json file content, exception:{%s}' % (str(e))
				sys.exit()
		else:
			print '[!] Error, Bulletins names file do not exists:{%s}' % (sFilePath)
			sys.exit()
	# end loadBulletinsNamesFromFile
	#
	#############################
	def getUpdateConfigElement(self, sIdx):
		if sIdx in self.dUpdateConfig:
			return self.dUpdateConfig[sIdx]
		else:
			return u''
	#end getUpdateConfigElement
	#
	#############################
	def getId(self):
		sIdx = u'ID'
		return self.getUpdateConfigElement(sIdx)
	#end getId
	#
	#############################
	def getCurrentReleaseDate(self):
		sIdx = u'CurrentReleaseDate'
		return self.getUpdateConfigElement(sIdx)
	#end getId
	#
	#############################
	def getRealReleaseDate(self):
		sIdx = u'RealReleaseDate'
		return self.getUpdateConfigElement(sIdx)
	#end getId
	#
	#############################
	def getAlias(self):
		sIdx = u'Alias'
		return self.getUpdateConfigElement(sIdx)
	#end getId
	#
	#############################
	def getDocumentTitle(self):
		sIdx = u'DocumentTitle'
		return self.getUpdateConfigElement(sIdx)
	#end getId
	#
	#############################
	def get(self, dConfig={}, sXmlFile=u''):
		"""
		:param dict dConfig: proxy config, as a dictionnary
		:return: a json dictionnary of ms updates
		"""
		if (sXmlFile==u''):
			# Use real release year and month
			sXmlFile = u'localcache_%d-%02d_%s.xml' % (self.getBulletinRealYear(),self.getBulletinRealMonth(),self.getAlias())
		else:
			pass
			
		if (os.path.isfile(sXmlFile)):
				# Get file contents
				with open(sXmlFile,'rb') as oFile:
					sContent = oFile.read()
		else:
			#
			# Build URL
			sUrl = self.dUpdateConfig[u'CvrfUrl']
			#
			# Create request obj
			oReq = objRequestsWrap()
			#
			# Set api key header
			oReq.setHeaders({u'api-key':self.sApiKey})
			#
			if (type(dConfig)!=dict):
				print u' [!] Config not a dictionnary'
				return u''
			elif (len(dConfig)>0):
				# Request headers and proxy
				oReq.buildRequestFromDict(dConfig)
			else:
				# No conf
				pass
			#
			# Do the request
			oResp = oReq.get(sUrl)
			sContent = oResp.text
			#
			# Write to file cache
			with open(sXmlFile,'wb') as oFile:
				oFile.write(oResp.text.encode('utf-8'))
		#
		# Response is fracking XML, seriously !! ? Whhyyyyyyyy...
		if (type(sContent)==unicode):
			# Ok, we have an Unicode string with a utf-8 declaration in headers, seriously !!?
			#
			# Convert to UTF-8
			sContent = sContent.encode('utf-8')
			#
			# Remove every non-ascii char
			sEmpty = u''.encode('utf-8')
			sSpace = u' '.encode('utf-8')
			sContent = sEmpty.join([c if ord(c) < 128 else sSpace for c in sContent])
			#
			# Here we have a UTF-8 String with UTF-8 encoding declared in header \o/
			#
		else:
			# UTF-8 string
			# We just remove every non-ascii char to avoid crash
			sEmpty = u''.encode('utf-8')
			sSpace = u' '.encode('utf-8')
			sContent = sEmpty.join([c if ord(c) < 128 else sSpace for c in sContent])
		#
		# Parse XML as an UTF-8 string
		try:	
			self.oXml = etree.fromstring(sContent)
			return True
		except Exception, e:
			print ' [!] Error, parsing XML Bulletin, exception:{%s}' % (str(e))
			return False
	#end get
	#
	#############################
	def getVulnerabilities(self):
		"""
		get <vuln:Vulnerability> elements from self.oXml
		"""
		lVulns = []
		# Xpath expression : all element with defined tag
		sTag = u'vuln:Vulnerability'
		sXpathExpression = u'//'+sTag
		#
		# Get all descendants regardless of depth
		lDescendants = self.oXml.xpath(sXpathExpression, namespaces=self.oXml.nsmap)
		#
		# Keep the number of vulns
		self.iVulnerabilitiesCount = len(lDescendants)
		#
		return lDescendants
		#
		# Old way
		#for oVuln in self.oXml.findall(u'vuln:Vulnerability', namespaces=self.oXml.nsmap):
		#	lVulns.append(oVuln)
		#return lVulns
	#end getVulnsFromBulletin
	#
	#############################
	def getVulnerabilitiesCount(self):
		return self.iVulnerabilitiesCount
	#end getVulnerabilitiesCount
	#
	#############################
	def getBulletinRealYear(self):
		# Use real release date and get year and month
		sDate = self.getRealReleaseDate()
		oDate = self.iso8601ToDatetime(sDate)
		return oDate.year
	#end getBulletinRealYear
	#
	#############################
	def getBulletinRealMonth(self):
		# Use real release date and get year and month
		sDate = self.getRealReleaseDate()
		oDate = self.iso8601ToDatetime(sDate)
		return oDate.month
	#end getBulletinRealMonth
	#
	#############################
	def getBulletinsCount(self):
		return len(self.dMSBulletins)
	#end getBulletinsCount
	#
	#############################
	def getBulletinsReferenceCount(self):
		return self.iBulletinReferenceCurrentRef
	#end getBulletinsReferenceCount
	#
	#############################
	def setBulletinsReferenceCount(self, iValue):
		self.iBulletinReferenceCurrentRef = iValue
	#end getBulletinsReferenceCount
	#
	#############################
	def getValueFromElement(self, oElement, sName, sTitle=u''):
		#
		# Xpath expression : all element with defined tag
		#sXpathExpression = u'//vuln:Vulnerability/'+sName
		#
		# Get first descendant
		#oDescendant = oElement.xpath(sXpathExpression, namespaces=self.oXml.nsmap)[0]
		sNote = u''
		oDescendant = oElement.find(sName, namespaces=self.oXml.nsmap)
		#
		if oDescendant is not None:
			if (sTitle==u''):
				# return .text
				if oDescendant.text is not None:
					sNote = oDescendant.text.strip()
				else:
					return sNote
			elif u'Title' in oDescendant.attrib:
				if (oDescendant.attrib[u'Title'] == sTitle):
					sNote = oDescendant.text.strip()
				else:
					return sNote
			else:
				return sNote
		else:
			return sNote
		#
		#if (type(sNote)==unicode):
		#	return sNote.encode('utf8')
		#else:
		return sNote
	#end getValueFromParent
	#
	#############################
	def getCveFromVulnerability(self, oVuln):
		return self.getValueFromElement(oVuln, u'vuln:CVE')
	#end getCveFromVulnerability
	#
	#############################
	def getTitleFromVulnerability(self, oVuln):
		return self.getValueFromElement(oVuln, u'vuln:Title')
	#end getTitleFromVulnerability
	#
	#############################
	def getNoteFromVulnerability(self, oVuln):
		# Note child of Notes
		# First get parent "Notes" and the request "Note"
		oElement = oVuln.find(u'vuln:Notes', namespaces=self.oXml.nsmap)
		if (oElement==None):
			return u''
		else:
			return self.getValueFromElement(oElement, u'vuln:Note', u'Description')
	#end getNoteFromVulnerability
	#
	#############################	
	def getAffectedProductsFromVuln(self, oVuln):
		"""
		Get the list of affected product by the vuln and calculate severity grade
		
		:param oVuln: lxml object from witch to retrieve affected products and threats
		:return: dictionnary like {
						u'affected product 1 id':{
							u'status':'Known Affected' or other values
							u'impact': 'Remote Code Execution' or ...
							u'severity': 'Important' or ...
						}
						u'affected product 2 id':{
							...
						}
		"""
		#
		# Product ID
		# returned dictionnary
		dAffectedProductsAndThreats = {}
		#		
		# Get current CVE
		sCve = self.getCveFromVulnerability(oVuln)
		################################
		# Get affected products
		#
		#<vuln:ProductStatuses>
		#	<vuln:Status Type="Known Affected">
		#		<vuln:ProductID>10378</vuln:ProductID>
		# Xpath doent seems working with sub element, so we use .find()
		#
		# Only one <vuln:ProductStatuses>
		sTag = u'vuln:ProductStatuses'
		oDescendant = oVuln.find(sTag, namespaces=self.oXml.nsmap)
		if oDescendant is None:
			print ' [!] Error, XML missing tag:{%s} for vulnerability %s' % (sCve)
			sys.exit()
		else:
			pass
		#
		# May have multiple <vuln:Status
		sTag = u'vuln:Status'
		lChilds = oDescendant.findall(sTag, namespaces=self.oXml.nsmap)
		if (len(lChilds)==0):
			print ' [!] Error, XML no product status, meaning no affected product for vulnerability %s' % (sCve)
		else:
			for oChild in lChilds:
				# Type: 'Known Affected', ...
				sTypeValue = oChild.attrib[u'Type']
				#
				# Get products ID
				sTag = u'vuln:ProductID'
				lProductId = oChild.findall(sTag, namespaces=self.oXml.nsmap)
				for oProductId in lProductId:
					sProductId = oProductId.text.strip()
					if sProductId not in dAffectedProductsAndThreats:
						dAffectedProductsAndThreats[sProductId] = {}
					else:
						pass
					#
					# Set status
					dAffectedProductsAndThreats[sProductId][u'status'] = sTypeValue
		#
		################################
		# Get Threat
		#
		#<vuln:ProductStatuses>
		#	<vuln:Status Type="Known Affected">
		#		<vuln:ProductID>10378</vuln:ProductID>
		# Xpath doent seems working with sub element, so we use .find()
		#
		# Only one <vuln:Threats>
		sTag = u'vuln:Threats'
		oDescendant = oVuln.find(sTag, namespaces=self.oXml.nsmap)
		if oDescendant is None:
			print ' [!] Error, XML missing tag:{%s} for vulnerability %s' % (sTag, sCve)
			sys.exit()
		else:
			pass
		#
		# May have multiple <vuln:Threat
		sTag = u'vuln:Threat'
		lChilds = oDescendant.findall(sTag, namespaces=self.oXml.nsmap)
		if (len(lChilds)==0):
			print ' [!] Error, XML no product status, meaning no affected product for vulnerability %s' % (sTag, sCve)
			sys.exit()
		else:
			pass
		for oChild in lChilds:
			# Type : 'Severity', 'Impact', 'Exploit Status'
			sTypeValue = oChild.attrib[u'Type']
			#
			# One or zero <vuln:ProductID>
			sProductId = self.getValueFromElement(oChild, u'vuln:ProductID')
			#
			# One <vuln:Description>
			sDescription = self.getValueFromElement(oChild, u'vuln:Description')
			#
			if (sTypeValue == u'Severity'):
				dAffectedProductsAndThreats[sProductId][u'severity'] = sDescription
			elif (sTypeValue == u'Impact'):
				dAffectedProductsAndThreats[sProductId][u'impact'] = sDescription
			elif (sTypeValue == u'Exploit Status'):
				for sElt in sDescription.strip().split(u';'):
					lParam = sElt.split(u':')
					if (lParam[0].strip().lower()==u'publicly disclosed'):
						if u'0' in dAffectedProductsAndThreats:
							dAffectedProductsAndThreats[u'0'][u'disclosed'] = lParam[1].strip().lower()
						else:
							dAffectedProductsAndThreats[u'0'] = {u'disclosed': lParam[1].strip().lower()}
					elif (lParam[0].strip().lower()==u'exploited'):
						if u'0' in dAffectedProductsAndThreats:
							dAffectedProductsAndThreats[u'0'][u'exploited'] = lParam[1].strip().lower()
						else:
							dAffectedProductsAndThreats[u'0'] = {u'exploited': lParam[1].strip().lower()}
					else:
						pass
			else:
				pass
		#
		################################
		# Calculate a severity grade
		#
		"""
		sTag = u'severity'
		iSeverityGrade = 0
		for sProductId in dAffectedProductsAndThreats:
			if (sTag in dAffectedProductsAndThreats[sProductId]):
				sSeverity = dAffectedProductsAndThreats[sProductId][sTag].lower().strip()
				#
				# Check the severity exists in our hard coded list
				for dSeverity in self.lHCSeverity:
					if (sSeverity == dSeverity[sTag]):
						# sum the severity
						iSeverityGrade += dSeverity[u'grade']
					else:
						pass
			else:
				# Ok, that odd again...
				pass
		#end for
		"""
		sTag = u'severity'
		iSeverityGrade = 0
		for sProductId in dAffectedProductsAndThreats:
			if (sTag in dAffectedProductsAndThreats[sProductId]):
				sProductSeverity = dAffectedProductsAndThreats[sProductId][sTag].lower().strip()
				#
				# Check the severity exists in our hard coded list
				iProductSeverityGrade = self.getSeverityGrade(sProductSeverity)
				if (iProductSeverityGrade > iSeverityGrade):
					# Keep only the maximum value, as a max
					iSeverityGrade = iProductSeverityGrade
				else:
					pass
			else:
				# Ok, that odd again...
				pass
		#end for
		#
		# Ok, that's not clean... storing as a 0 product id
		# oh yeah, that's dirty and your eyes are bleeding ;-)
		if (u'0' in dAffectedProductsAndThreats):
			dAffectedProductsAndThreats[u'0'][u'severity'] = iSeverityGrade
		else:
			dAffectedProductsAndThreats[u'0'] = {u'severity': iSeverityGrade }
		return dAffectedProductsAndThreats
	#end getAffectedProductsFromVuln
	#
	#############################	
	def getSeverityGrade(self, sSeverity):
		"""
		Get the severity grade from a severity string (important, low...)
		:return: Severity as a grade from self.lHCSeverity 
		"""
		for dSeverity in self.lHCSeverity:
			if (sSeverity == dSeverity[u'severity']):
				return dSeverity[u'grade']
		return 0
	#end getSeverityGrade
	#
	#############################	
	def getAffectedProductFromProductId(self, sProductId, iType=0, sMsg=u''):
		"""
		Return the product fullname, familly or vendor store in self.dProducts, from Product ID 
		:param str sProductId: product id, ie. "10024" that corresponds to  "Microsoft Office for Mac 2011"
		:param int iType: 0=fullname, 1=familly, 2=vendor
		:param str sMsg: a message to specify things ;)
		:return: a string with the product fullname
		"""
		# 
		# Check affected products
		if sProductId not in self.dProducts:
			return u'Unkown product'
		else:
			if (iType==2):
				if (u'vendorname' in self.dProducts[sProductId]):
					return self.dProducts[sProductId][u'vendorname']
				else:
					if (len(sMsg)>0):
						sMsg = '%s, %s' % (sMsg, u'no vendor')
					else:
						sMsg = u'no vendor'
					return self.getAffectedProductFromProductId(sProductId, 1, sMsg)
			elif (iType==1):
				if (u'familly' in self.dProducts[sProductId]):
					if (len(sMsg)>0):
						return u'%s (%s)' % (self.dProducts[sProductId][u'familly'], sMsg)
					else:
						return self.dProducts[sProductId][u'familly']
				else:
					if (len(sMsg)>0):
						sMsg = '%s, %s' % (sMsg, u'no familly')
					else:
						sMsg = u'no familly'
					return self.getAffectedProductFromProductId(sProductId, 2, sMsg)
			elif (iType==0):
				if (u'fullname' in self.dProducts[sProductId]):
					if (len(sMsg)>0):
						return u'%s (%s)' % (self.dProducts[sProductId][u'fullname'], sMsg)
					else:
						return self.dProducts[sProductId][u'fullname']
				else:
					return u'Undefined product'
	#end getAffectedProductFromProductId
	#
	#############################	
	def getAffectedProductFullNameFromProductId(self, sProductId):
		"""
		Return the product fullname store in self.dProducts, from Product ID 
		:param str sProductId: product id, ie. "10024" that corresponds to  "Microsoft Office for Mac 2011"
		:return: a string with the product fullname
		"""
		return self.getAffectedProductFromProductId(sProductId, 0)
	#end getAffectedProductFullNameFromProductId
	#
	#############################	
	def getAffectedProductFamillyFromProductId(self, sProductId):
		"""
		Return the product fullname store in self.dProducts, from Product ID 
		:param str sProductId: product id, ie. "10024" that corresponds to  "Microsoft Office for Mac 2011"
		:return: a string with the product fullname
		"""
		return self.getAffectedProductFromProductId(sProductId1, 1)
	#end getAffectedProductFamillyFromProductId
	#
	#############################	
	def getAffectedProductVendorFromProductId(self, sProductId):
		"""
		Return the product fullname store in self.dProducts, from Product ID 
		:param str sProductId: product id, ie. "10024" that corresponds to  "Microsoft Office for Mac 2011"
		:return: a string with the product fullname
		"""
		return self.getAffectedProductFromProductId(sProductId, 2)
	#end getAffectedProductVendorFromProductId
	#
	#############################	
	def getAcknowledgmentsFromVuln(self, oVuln):
		"""
		Get the list of Acknowledgments
		<vuln:Acknowledgments><vuln:Acknowledgment><vuln:Name>aaaaaaaaaaaaaaaaaaa</vuln:Name>
		
		:param oVuln: lxml object from witch to retrieve affected products and threats
		:return: list of names
		"""
		#
		# Acknowledgments
		sAcknowledgments = u''
		# 
		# Get current CVE
		sCve = self.getCveFromVulnerability(oVuln)
		#
		# Only one <vuln:Acknowledgments>
		sTag = u'vuln:Acknowledgments'
		oDescendant = oVuln.find(sTag, namespaces=self.oXml.nsmap)
		if oDescendant is None:
			print ' (i) Warn, XML missing tag:{%s} for vulnerability %s' % (sCve)
			return sAcknowledgments
		else:
			pass
		#
		# May have multiple <vuln:Acknowledgment
		sTag = u'vuln:Acknowledgment'
		lChilds = oDescendant.findall(sTag, namespaces=self.oXml.nsmap)
		if (len(lChilds)==0):
			print ' (i) Warn, XML no Acknowledgment for vulnerability %s' % (sCve)
		else:
			for oChild in lChilds:
				#Get sub element Name
				sTag = u'vuln:Name'
				oName = oChild.find(sTag, namespaces=self.oXml.nsmap)
				# Clean up
				sLocalAck = oName.text.strip()
				sLocalAck = sLocalAck.replace(u"\r", u'').replace(u"\n", u' ')
				sAcknowledgments+= u'%s, ' % (sLocalAck)#(oName.text.strip())
		#
		# remove last ', '
		if (len(sAcknowledgments)>2):
			return sAcknowledgments[0:-2]
		else:
			return sAcknowledgments
	#end getAcknowledgmentsFromVuln
	#
	#############################	
	def isIeAndEdgeAffected(self, dAffectedProductsAndThreats):
		"""
		Check if IE and EDGE are affected, meaning are present in a dict
		that describe the affected products
		
		:param dict dAffectedProductsAndThreats: dictionnary of affected products
		:return: a tuple of boolean, first is true if IE is affected, second if for edge
		"""
		bIsIeAffected = False
		bIsEdgeAffected = False
		#	
		# Check affected products
		for sAffectedProductId in dAffectedProductsAndThreats:
			if (sAffectedProductId==u'0'):
				# It's my dirty of storing iSeverityGrade, sorry ;-)
				pass
			else:
				sFamilly = self.dProducts[sAffectedProductId][u'famillyname'].lower().strip()
				sFullname = self.dProducts[sAffectedProductId][u'fullname'].lower().strip()
				#
				# Check browser is affected
				if (sFamilly == u'browser'):
					# Check if IE is affected
					if (sFullname.find(self.dHCBulletinsName[u'HARD-CODED-IE'].lower())!=-1):
						bIsIeAffected = True
					else:
						pass
					#
					# check if EDGE is affected, could be both
					if (sFullname.find(self.dHCBulletinsName[u'HARD-CODED-EDGE'].lower())!=-1):
						bIsEdgeAffected = True
					else:
						pass
				else:
					# Not a browser
					pass
		return (bIsIeAffected, bIsEdgeAffected)
	#end isIeAndEdgeAffected
	#
	#############################	
	def getBulletinNameFromTitle(self, sTitle):
		"""
		The major trick of this code : find the bulletin name from a hard coded list
		
		:return: bulletin title as a string
		"""
		for dBulletin in self.lBulletinsNames:
			for sStart in dBulletin[u'startwith']:
				if (sTitle[0:len(sStart)].upper()==sStart.upper()):
					return dBulletin[u'name']
		return u''
	#end getBulletinNameFromTitle
	#
	#############################	
	def buildProductsFromBulletin(self):
		"""
		Build the product list from the bulletin
		It's a dictionnary 'ProductId':{'vendorname':..., 'famillyname':..., 'fullname':...}
		"""
		#
		# Build products dictionnary with only "FullProductName"
		oProducts = self.oXml.find(u'prod:ProductTree', namespaces=self.oXml.nsmap)
		#
		# Get branch name
		for oBranch in oProducts.findall(u'prod:Branch', namespaces=self.oXml.nsmap):
			# Get Vendor Name
			if ((u'Type' not in oBranch.attrib) or (u'Name' not in oBranch.attrib)):
				# wrong XML, missing type or name
				print ' ! Wrong XML for prod:Branch, missing attributes Type or Name'
			elif (oBranch.attrib[u'Type']!=u'Vendor'):
				# type is not vendor !!?
				print ' ! Wrong XML, Type is not a Vendor, it is:{%s}' % oBranch.attrib[u'Type']
			else:
				sVendorName = oBranch.attrib[u'Name']
				for oSubBranch in oBranch.findall(u'prod:Branch', namespaces=self.oXml.nsmap):
					if ((u'Type' not in oSubBranch.attrib) or (u'Name' not in oSubBranch.attrib)):
						# wrong XML, missing type or name
						print ' ! Wrong XML for prod:Branch>prod:Branch, missing attributes Type or Name'
					elif (oSubBranch.attrib[u'Type']!=u'Product Family'):
						# type is not Product Family !!?
						print ' ! Type is not a Product Family:{%s}' % oSubBranch.attrib
					else:
						sFamillyName = oSubBranch.attrib[u'Name']
						# List all fullproductname
						for oProduct in oSubBranch.findall(u'prod:FullProductName', namespaces=self.oXml.nsmap):
							if (u'ProductID' not in oProduct.attrib):
								# wrong XML, missing type or name
								print ' ! Wrong XML for prod:FullProductName, missing attribute oProduct'
							else:
								sProductId = oProduct.attrib[u'ProductID']
								sFullName = oProduct.text
								self.dProducts[sProductId] = {'vendorname':sVendorName,
																				 'famillyname':sFamillyName,
																				 	'fullname':sFullName}
	#end buildProductsFromBulletin
	#
	#############################
	def getProductsCount(self):
		return len(self.dProducts)
	#end getProductsCount
	#
	#############################
	def addCveToMsBulletins(self, sBulletinName, sCve, sCveTitle, dAffectedProductsAndThreats, Acknowledgments, oVuln):
		"""
		Simply add elements to the shared dictionnary of bulletins : self.dMSBulletins :
		self.dMSBulletins : {
		
		
		# { bulletin-name-from-lBulletinsTitles : {
		#																	 CVE-xxxx-xxxxx : {
		#																								'cve': cve code,
		#																								'title': title,
		#																								'productsandthreats' : dic of elements,
		#																								'ovuln': lxml object (pointer)
		#																										}
		#																					},
		#																	 CVE-xxxx-xxxxx : {
		#																								...
		#																					}
		#		next-bulletin-name-from-lBulletinsTitles : {
		#																	 CVE-xxxx-xxxxx : {
		#																								...
		#																					}
		
		:param str sBulletinName: bulletin name and index in the dict self.dMSBulletins
		:param str sCve: cve id (cve-yyyy-xxxxx)
		:param str sCveTitle: cve title
		:param dict dAffectedProductsAndThreats: dictionnary of affected products and threats
		:param str Acknowledgments: names
		:param oVuln: vulnerability as an lxml object
		"""
		#
		#print u'   + Adding CVE: %s, BulletinName: %s' % (sCve, sBulletinName)
		#print = u'                   Title: %s' % (sCveTitle)
		#
		# Handle when self.dMSBulletins[sBulletinTitle] do not already exists, to avoid exception
		# when addressing [title][cve] if not title does not exists
		if sBulletinName not in self.dMSBulletins:
			self.dMSBulletins[sBulletinName] = {}
		else:
			pass	
		#	
		# Add CVE in Bulletins
		if sCve in self.dMSBulletins[sBulletinName]:
			# CVE already exists, strange !!!
			print u' CVE:%s already exists in MSBulletins dictionnary !!?' % (sCve)
		else:
			self.dMSBulletins[sBulletinName][sCve] = { u'cve':sCve, u'title':sCveTitle, u'productsandthreats':dAffectedProductsAndThreats, u'ack': Acknowledgments, u'ovuln':oVuln }
	#end addCveToMsBulletins
	#
	#############################		
	def buildMsBulletins(self):
		"""
		Build a dictionnary of all bulletin from lxml object self.oXml stored in self.dMSBulletins
		self.dMSBulletins: {
				bulletin-name-from-lBulletinsTitles : {
							 CVE-xxxx-xxxxx : {
												'cve': cve code,
												'title': title,
												'productsandthreats' : dic of elements,
												'ovuln': lxml object (pointer)
								},
							 CVE-xxxx-xxxxx : {
														...
								},
								...
				next-bulletin-name-from-lBulletinsTitles : {
							 CVE-xxxx-xxxxx : {
											...
								},
								...

		"""
		
			
		#
		# Check if the bulletin is out of band
		# The information can be found in 3 places :
		# - in the dUpdateConfig :  u'ID': u'xxx-OOB'
		# - in the update : <cvrf:DocumentNotes><cvrf:Note Title="Release Notes" Audience="Public" Type="Details" Ordinal="1"><p> [...] out of band [...]</p>
		# - NOT HANDLED HERE-> in the vuln/cve : <vuln:Vulnerability Ordinal="1"><vuln:Title>[...] OOB [...] </vuln:Title>
		self.dUpdateConfig[u'isoob'] = False
		if (self.dUpdateConfig[u'ID'].lower().find('oob')!=-1):
			self.dUpdateConfig[u'isoob'] = True
		else:
			sTag = u'cvrf:DocumentNotes'
			oDocNotes = self.oXml.find(sTag, namespaces=self.oXml.nsmap)
			if (oDocNotes!=None):
				# Multiple note ?
				sTag = u'cvrf:Note'
				lNotes = oDocNotes.findall(sTag, namespaces=self.oXml.nsmap)
				if (len(lNotes)!=0):
					for oNote in lNotes:
						if (oNote.text.lower().find('oob')!=-1):
							self.dUpdateConfig[u'isoob'] = True
							break
		#		
		# Foreach CVE, get infos and bulletin name that can be tghe same for multiple cve
		for oVuln in self.getVulnerabilities():
			# Get common informations
			sCve = self.getCveFromVulnerability(oVuln).strip()
			#print u'      CVE  :{%s}' % (sCve)
			sCveTitle = self.getTitleFromVulnerability(oVuln).strip()
			#print u'      Title:{%s}' % (sCveTitle)
			sCveAcknowledgments = self.getAcknowledgmentsFromVuln(oVuln).strip()
			#print u' Acknowledgments:{%s}' % (sCveAcknowledgments)
			sBulletinName =  self.getBulletinNameFromTitle(sCveTitle).strip()
			#print u'BulletinName:{%s}' % (sBulletinName)
			dAffectedProductsAndThreats = self.getAffectedProductsFromVuln(oVuln)
			(bIsIeAffected, bIsEdgeAffected) = self.isIeAndEdgeAffected(dAffectedProductsAndThreats)
			"""
			if (sCve == u'CVE-2016-0187'):
				# Not in any bulletin
				print u'      CVE  :{%s}' % (sCve)
				print u'      Title:{%s}' % (sCveTitle)
				print u'      BulletinName:{%s}' % (sBulletinName)
				print u'      Note:{%s}' % (self.getNoteFromVulnerability(oVuln))
				sys.exit()
			if (sCve == u'CVE-2016-0189'):
				# Not in any bulletin
				print u'      CVE  :{%s}' % (sCve)
				print u'      Title:{%s}' % (sCveTitle)
				print u'      BulletinName:{%s}' % (sBulletinName)
				print u'      Note:{%s}' % (self.getNoteFromVulnerability(oVuln))
				sys.exit()
			"""
			#
			# Ok, here we have some small - fucking big - problems that require a case by case processing:
			#  - sometimes Microsoft rank CVE in IE bulletin, and sometimes not
			#  - sometimes Flash vulns are named CVE and sometimes ADV
			#  - sometimes bulletin are composed only by vulns already put in a previous bulletin (CVE-2016-0187 and -0189 in ms16-051 and ms16-053)
			#  - some vulns are common to IE and EDGE, and can be found in both bulletin or other
			#  - missing CVE-2016-7189 CVE-2016-7190 CVE-2016-7194 in MS Rest API
			#
			#
			# Patch, on CVE Name that miss the string 'CVE', is this a joke Microsoft ???
			if ( sCve == u'2016-9890'):
				sCve = u'CVE-2016-9890'
			else:
				pass
			#
			# Not in any MS Bulletin !!?
			if (sCve == u'CVE-2016-3380'):
				# Not in any bulletin
				print u'   * CVE not in any bulletin'
				print u'      CVE  :{%s}' % (sCve)
				print u'      Title:{%s}' % (sCveTitle)
				print u'      BulletinName:{%s}' % (sBulletinName)
				print u'      Note:{%s}' % (self.getNoteFromVulnerability(oVuln))
				print u'     Ignoring...'
			#
			elif (sCve == u'CVE-2016-3237'):
				# In october xml, but referenced in MS16-101 from  august du to update
				print u'   * CVE already in a previous bulletin, new publication'
				print u'      CVE  :{%s}' % (sCve)
				print u'      Title:{%s}' % (sCveTitle)
				print u'      BulletinName:{%s}' % (sBulletinName)
				print u'      Note:{%s}' % (self.getNoteFromVulnerability(oVuln))
				print u'     Ignoring...'
			#
			# Unkown title
			elif ( (sCve[0:3].upper()!=u'ADV') and (sBulletinName==u'') ):
				# Unkown title... must be added manually to the Json file
				print u'   ! Can not find a Bulletin Name from the Json local dictionary. Add manually the Title bellow in the local JSON file.'
				print u'      CVE  :{%s}' % (sCve)
				print u'      Title:{%s}' % (sCveTitle)
				print u'      BulletinName:{%s}' % (sBulletinName)
				print u'      Note:{%s}' % (self.getNoteFromVulnerability(oVuln))
				#
				# Affected products
				dBulletinAffected = {}
				for sProductId in dAffectedProductsAndThreats:
					if (sProductId==u'0'):
						# It's my dirty of storing iSeverityGrade, sorry again ;-D
						pass
					else:
						sProduct = self.getAffectedProductFullNameFromProductId(sProductId)
						if (sProduct not in dBulletinAffected):
							dBulletinAffected[sProduct] = 1
						else:
							dBulletinAffected[sProduct] = dBulletinAffected[sProduct] + 1
				lBulletinAffectedSorted = sorted(dBulletinAffected)
				print u'      Affected:'
				for sProduct in lBulletinAffectedSorted:
					print u'               %s' % (sProduct)
				print u'     Abording...'
				sys.exit()
			#
			# Windows Defender signature update
			#elif ( (sCve[0:3].upper()==u'ADV') and
			#			( (sBulletinName.find(self.dHCBulletinsName[u'HARD-CODED-FLASH'])==-1) or
			#			  (sCveTitle.find(self.dHCBulletinsName[u'HARD-CODED-FLASH'])==-1) ) ):
			elif ( (sCve[0:3].upper()==u'ADV') and (sBulletinName.find(self.dHCBulletinsName[u'HARD-CODED-FLASH'])==-1) ):
				# Seems to be a Defender signature update, dont' care of that shit !
				print u'   * Windows Defenser signature update, not a bulletin'
				print u'      CVE  :{%s}' % (sCve)
				print u'      Title:{%s}' % (sCveTitle)
				print u'     BulletinName:{%s}' % (sBulletinName)
				print u'      Note:{%s}' % (self.getNoteFromVulnerability(oVuln))
				print u'     Ignoring...'
			#
			# Flash named ADV
			#elif ( (sCve[0:3].upper()==u'ADV') and
			#			( (sBulletinName.find(self.dHCBulletinsName[u'HARD-CODED-FLASH'])!=-1) and
			#			  (sCveTitle.find(self.dHCBulletinsName[u'HARD-CODED-FLASH'])!=-1) ) ):
			elif ( (sCve[0:3].upper()==u'ADV') and (sBulletinName.find(self.dHCBulletinsName[u'HARD-CODED-FLASH'])!=-1) ):
				# It's Flash, keep it
				#print u'   * Adobe Flash'
				#print u'      CVE  :{%s}' % (sCve)
				#print u'      Title:{%s}' % (sCveTitle)
				#print u'     BulletinName:{%s}' % (sBulletinName)
				#print u'      Note:{%s}' % (self.getNoteFromVulnerability(oVuln))
				#
				if ( sCve[0:3].upper()==u'ADV'):
					# Sometime, for Flash, CVE are in Note
					sNote = self.getNoteFromVulnerability(oVuln)
					#
					# Remove HTML tags for easy split and processing ;-)
					sNote = re.sub('<[^>]*>', '', sNote)
					#
					# retrieve CVE
					for sNote in sNote.split(u'CVE'):
						if (sNote[0]==u'-'):
							# seems good 'cause CVE has been removed by the split
							lCveFromNote = sNote.split(',')
							# Keep only [0] cause even if there is no ',', we get a list with one element
							sCve = u'CVE%s' % (lCveFromNote[0].strip())
							# Add it
							self.addCveToMsBulletins(sBulletinName, sCve, sCveTitle, dAffectedProductsAndThreats, sCveAcknowledgments, oVuln)
				else:
					self.addCveToMsBulletins(sBulletinName, sCve, sCveTitle, dAffectedProductsAndThreats, sCveAcknowledgments, oVuln)
					print u'     Ignoring...'
			else:
			
				#
				# Simple Patch
				lCvePatchs = [
											[u'CVE-2016-0070', u'Windows Registry'],
 											[u'CVE-2016-0073', u'Windows Registry'],
											[u'CVE-2016-0075', u'Windows Registry'],
											[u'CVE-2016-0079', u'Windows Registry'],
											[u'CVE-2016-0138', self.getBulletinNameFromTitle(u'Microsoft Exchange')],
											[u'CVE-2016-0152', self.getBulletinNameFromTitle(u'Windows IIS')], # MS16-058 named "Security Update for Windows IIS" but in MSRC API it's "Windows DLL Loading Remote Code Execution Vulnerability"
											[u'CVE-2016-0176', self.getBulletinNameFromTitle(u'Win32k')], # merged to MS16-062 whereas its directx usually it's a dedicated bulletin
											[u'CVE-2016-0180', sBulletinName + u' (mmsbga patch)'],
											[u'CVE-2016-0186', self.dHCBulletinsName[u'HARD-CODED-EDGE']], # MS16-052 (Edge) but in MSRC API, Edge is'nt affected :'(
											[u'CVE-2016-0191', self.dHCBulletinsName[u'HARD-CODED-EDGE']], # MS16-052 (Edge) but in MSRC API, Edge is'nt affected :'(
											[u'CVE-2016-0193', self.dHCBulletinsName[u'HARD-CODED-EDGE']], # MS16-052 (Edge) but in MSRC API, Edge is'nt affected :'(
											[u'CVE-2016-0197', self.getBulletinNameFromTitle(u'Win32k')], # merged to MS16-062 whereas its directx usually it's a dedicated bulletin
											[u'CVE-2016-3199', self.dHCBulletinsName[u'HARD-CODED-EDGE']],
											[u'CVE-2016-3202', self.dHCBulletinsName[u'HARD-CODED-EDGE']],
											[u'CVE-2016-3202', self.dHCBulletinsName[u'HARD-CODED-IE']],
											[u'CVE-2016-3210', self.dHCBulletinsName[u'HARD-CODED-IE']],
											[u'CVE-2016-3213', self.dHCBulletinsName[u'HARD-CODED-IE']],
											[u'CVE-2016-3213', self.getBulletinNameFromTitle(u'WPAD Elevation of Privilege Vulnerability')],
											[u'CVE-2016-3214', self.dHCBulletinsName[u'HARD-CODED-EDGE']],
											[u'CVE-2016-3216', u'Microsoft Graphics Component (mmsbga)'],
											[u'CVE-2016-3219', u'Microsoft Graphics Component (mmsbga)'],
											[u'CVE-2016-3220', u'Microsoft Graphics Component (mmsbga)'],
											[u'CVE-2016-3222', self.dHCBulletinsName[u'HARD-CODED-EDGE']], # double
											[u'CVE-2016-3232', self.getBulletinNameFromTitle(u'Win32k')],
											[u'CVE-2016-3248', self.dHCBulletinsName[u'HARD-CODED-EDGE']],
											[u'CVE-2016-3248', self.dHCBulletinsName[u'HARD-CODED-IE']],
											[u'CVE-2016-3259', self.dHCBulletinsName[u'HARD-CODED-EDGE']],
											[u'CVE-2016-3259', self.dHCBulletinsName[u'HARD-CODED-IE']],
											[u'CVE-2016-3260', self.dHCBulletinsName[u'HARD-CODED-EDGE']],
											[u'CVE-2016-3260', self.dHCBulletinsName[u'HARD-CODED-IE']],
											[u'CVE-2016-3265', self.dHCBulletinsName[u'HARD-CODED-EDGE']],
											[u'CVE-2016-3269', self.dHCBulletinsName[u'HARD-CODED-EDGE']],
											[u'CVE-2016-3270', self.getBulletinNameFromTitle(u'Microsoft Graphics Component')],
											[u'CVE-2016-3271', self.dHCBulletinsName[u'HARD-CODED-EDGE']],
											[u'CVE-2016-3276', self.dHCBulletinsName[u'HARD-CODED-EDGE']],
											[u'CVE-2016-3276', self.dHCBulletinsName[u'HARD-CODED-IE']],
											[u'CVE-2016-3296', self.dHCBulletinsName[u'HARD-CODED-EDGE']],
											[u'CVE-2016-3298', self.dHCBulletinsName[u'HARD-CODED-IE']], # in IE bulletin but also in it's own
											[u'CVE-2016-3298', self.getBulletinNameFromTitle(u'Microsoft Internet Messaging API')], # in IE bulletin but also in it's own
											[u'CVE-2016-3318', self.getBulletinNameFromTitle(u'Microsoft Office')],
											[u'CVE-2016-3325', self.dHCBulletinsName[u'HARD-CODED-EDGE']],
											[u'CVE-2016-3325', self.dHCBulletinsName[u'HARD-CODED-IE']],
											[u'CVE-2016-3326', self.dHCBulletinsName[u'HARD-CODED-EDGE']],
											[u'CVE-2016-3326', self.dHCBulletinsName[u'HARD-CODED-IE']],
											[u'CVE-2016-3348', self.getBulletinNameFromTitle(u'Microsoft Graphics Component')],
											[u'CVE-2016-3349', self.getBulletinNameFromTitle(u'Microsoft Graphics Component')],
											[u'CVE-2016-3350', self.dHCBulletinsName[u'HARD-CODED-EDGE']],
											[u'CVE-2016-3377', self.dHCBulletinsName[u'HARD-CODED-EDGE']],
											[u'CVE-2016-3382', self.dHCBulletinsName[u'HARD-CODED-EDGE']],
											[u'CVE-2016-3382', self.dHCBulletinsName[u'HARD-CODED-IE']],
											[u'CVE-2016-3385', self.dHCBulletinsName[u'HARD-CODED-IE']],
											[u'CVE-2016-3386', self.dHCBulletinsName[u'HARD-CODED-EDGE']],
											[u'CVE-2016-3389', self.dHCBulletinsName[u'HARD-CODED-EDGE']],
											[u'CVE-2016-3390', self.dHCBulletinsName[u'HARD-CODED-EDGE']],
											[u'CVE-2016-3390', self.dHCBulletinsName[u'HARD-CODED-IE']],
											[u'CVE-2016-7202', self.dHCBulletinsName[u'HARD-CODED-EDGE']], # only in edge and ie, not in Scripting Engine this time !!?
											[u'CVE-2016-7202', self.dHCBulletinsName[u'HARD-CODED-IE']],
											[u'CVE-2016-7287', self.dHCBulletinsName[u'HARD-CODED-EDGE']], # only in edge and ie, not in Scripting Engine this time !!?
											[u'CVE-2016-7287', self.dHCBulletinsName[u'HARD-CODED-IE']],
											[u'CVE-2016-7281', self.dHCBulletinsName[u'HARD-CODED-EDGE']], # only in edge and ie, not in Scripting Engine this time !!?
											[u'CVE-2016-7281', self.dHCBulletinsName[u'HARD-CODED-IE']],
											[u'CVE-2016-7243', self.dHCBulletinsName[u'HARD-CODED-EDGE']], # only in edge, not in Scripting Engine this time !!?
											[u'CVE-2016-7201', self.dHCBulletinsName[u'HARD-CODED-EDGE']], # only in edge, not in Scripting Engine this time !!?
											[u'CVE-2016-7203', self.dHCBulletinsName[u'HARD-CODED-EDGE']], # only in edge, not in Scripting Engine this time !!?
											[u'CVE-2016-7240', self.dHCBulletinsName[u'HARD-CODED-EDGE']], # only in edge, not in Scripting Engine this time !!?
											[u'CVE-2016-7208', self.dHCBulletinsName[u'HARD-CODED-EDGE']], # only in edge, not in Scripting Engine this time !!?
											[u'CVE-2016-7200', self.dHCBulletinsName[u'HARD-CODED-EDGE']], # only in edge, not in Scripting Engine this time !!?
											[u'CVE-2016-7242', self.dHCBulletinsName[u'HARD-CODED-EDGE']], # only in edge, not in Scripting Engine this time !!?
											[u'CVE-2016-7296', self.dHCBulletinsName[u'HARD-CODED-EDGE']], # only in edge, not in Scripting Engine this time !!?
											[u'CVE-2016-7297', self.dHCBulletinsName[u'HARD-CODED-EDGE']], # only in edge, not in Scripting Engine this time !!?
											[u'CVE-2016-7286', self.dHCBulletinsName[u'HARD-CODED-EDGE']], # only in edge, not in Scripting Engine this time !!?
											[u'CVE-2016-7288', self.dHCBulletinsName[u'HARD-CODED-EDGE']], # only in edge, not in Scripting Engine this time !!?
         							[u'CVE-2016-7257', self.getBulletinNameFromTitle(u'Microsoft Office')], # Office and also GDI, it's a first time !
         							[u'CVE-2016-7257', self.getBulletinNameFromTitle(u'Windows Graphics')], # Office and also GDI, it's a first time !
											[u'CVE-2016-7259', u'Microsoft Graphics Component (mmsbga)'], # by automation merge with CVE-2016-7292 and CVE-2016-7219 but MS make a dedicated bulletin MS16-151
											[u'CVE-2016-7260', u'Microsoft Graphics Component (mmsbga)'], # by automation merge with CVE-2016-7292 and CVE-2016-7219 but MS make a dedicated bulletin MS16-151
											
											[u'CVE-2017-0016', self.getBulletinNameFromTitle(u'Windows Denial')], #  named "SMBv2/SMBv3 Null Dereference DoS" not in MS17-10 but un MS17-12 !!?
											#CVE-2017-0102 => noyau
											[u'CVE-2017-0107', self.getBulletinNameFromTitle(u'Microsoft Office')], # XSS in sharepoint but MS put that in Office bulletin MS17-014
											
											[u'CVE-2017-0050', u'Windows Kernel (mmsbga)'], # kernel but has its own bulletin !!?
											[u'CVE-2017-0101', u'Windows Kernel (mmsbga)'], # kernel but has its own bulletin !!?
											[u'CVE-2017-0102', u'Windows Kernel (mmsbga)'], # kernel but has its own bulletin !!?
											[u'CVE-2017-0103', u'Windows Kernel (mmsbga)'], # kernel but has its own bulletin !!?


											[u'CVE-2017-0007', self.getBulletinNameFromTitle(u'Windows Elevation')], #  Device Guard but merged with other windows cve in bulletin MS17-012
											#CVE-2017-0101 => noyau 
											#CVE-2017-0050 => noyau
											# gerer
											# CVE-2016-7855 Adobe Flash OOB bulletin supplementaire MS16-128
											# boucle si plusieurs adobe oob
										
										]
				#
				bPatched = False
				for lCvePatch in lCvePatchs:
					if (sCve == lCvePatch[0]):
						# Patch
						self.addCveToMsBulletins(lCvePatch[1], sCve, sCveTitle, dAffectedProductsAndThreats, sCveAcknowledgments, oVuln)
						bPatched = True
				
				if sCve == u'CVE-2016-7855':
					print " ----- flash note ---- with OOB "
					print self.getNoteFromVulnerability(oVuln)
					print ''
					
					

					
					"""
					traiter vuln URL
					revision history
					
					<vuln:RevisionHistory><vuln:Revision><cvrf:Number>2.0</cvrf:Number>
																							 <cvrf:Date>2016-12-13T08:00:00</cvrf:Date>
																							 <cvrf:Description>
															 <vuln:Revision>
					"""
				#
				# Complex patch
				if bPatched == False:
					# After 2017, all "Scripting Engine" are part of IE/EDGE bulletin and no more a dedicated bulletin
					if ( sBulletinName == u'Scripting Engine (JScript and/or VBScript)' and (self.getBulletinRealYear()>=2017) ):
						# Add to IE bulletin
						if bIsIeAffected == True:
							sLocalBulletinName = self.dHCBulletinsName[u'HARD-CODED-IE']
							self.addCveToMsBulletins(sLocalBulletinName, sCve, sCveTitle, dAffectedProductsAndThreats, sCveAcknowledgments, oVuln)
						#
						# Add to EDGE bulletin
						if bIsEdgeAffected == True:
							sLocalBulletinName = self.dHCBulletinsName[u'HARD-CODED-EDGE']
							self.addCveToMsBulletins(sLocalBulletinName, sCve, sCveTitle, dAffectedProductsAndThreats, sCveAcknowledgments, oVuln)
						#
						# Ie and Edge are affected
						if bIsIeAffected == False and bIsEdgeAffected == False:
							"""
							print u'      Ie and Edge are affected'
							print u'      CVE  :{%s}' % (sCve)
							print u'      Title:{%s}' % (sCveTitle)
							print u'      BulletinName:{%s}' % (sBulletinName)
							print u'      Note:{%s}' % (self.getNoteFromVulnerability(oVuln))
							"""
							for sProductId in dAffectedProductsAndThreats:
								if (sProductId==u'0'):
									# It's my dirty of storing iSeverityGrade, sorry again ;-D
									pass
								else:
									print self.getAffectedProductFullNameFromProductId(sProductId)
							#
							# Add the CVE also to "Scripting Engine" Bulletin Name (the legacy bulletins were like that)
							self.addCveToMsBulletins(sBulletinName, sCve, sCveTitle, dAffectedProductsAndThreats, sCveAcknowledgments, oVuln)
						else:
							pass
					#
					# Patch, Common vuln for IE and EDGE
					elif ( sBulletinName == self.dHCBulletinsName[u'HARD-CODED-MIXEDGEIE'] ):
						# Add to IE bulletin
						if bIsIeAffected == True:
							sLocalBulletinName = self.dHCBulletinsName[u'HARD-CODED-IE']
							self.addCveToMsBulletins(sLocalBulletinName, sCve, sCveTitle, dAffectedProductsAndThreats, sCveAcknowledgments, oVuln)
						#
						# Add to EDGE bulletin
						if bIsEdgeAffected == True:
							sLocalBulletinName = self.dHCBulletinsName[u'HARD-CODED-EDGE']
							self.addCveToMsBulletins(sLocalBulletinName, sCve, sCveTitle, dAffectedProductsAndThreats, sCveAcknowledgments, oVuln)
					#
					# Patch, Stage case : IE/EDGE impacted but a specific bulletin is also created 
					elif ( (sBulletinName != self.dHCBulletinsName[u'HARD-CODED-IE']) and (sBulletinName != self.dHCBulletinsName[u'HARD-CODED-EDGE'])
					      and
								( (bIsIeAffected == True) or (bIsEdgeAffected == True) ) ):
						# Add to IE bulletin
						if bIsIeAffected == True:
							sLocalBulletinName = self.dHCBulletinsName[u'HARD-CODED-IE']
							self.addCveToMsBulletins(sLocalBulletinName, sCve, sCveTitle, dAffectedProductsAndThreats, sCveAcknowledgments, oVuln)
						#
						# Add to EDGE bulletin
						if bIsEdgeAffected == True:
							sLocalBulletinName = self.dHCBulletinsName[u'HARD-CODED-EDGE']
							self.addCveToMsBulletins(sLocalBulletinName, sCve, sCveTitle, dAffectedProductsAndThreats, sCveAcknowledgments, oVuln)
						#
						# Add also specific bulletin
						self.addCveToMsBulletins(sBulletinName, sCve, sCveTitle, dAffectedProductsAndThreats, sCveAcknowledgments, oVuln)
					#
					# Normal case ?	
					else:
						# Wow, it's a normal vuln, without fucking exotic case, it's a fucking miracle !
						self.addCveToMsBulletins(sBulletinName, sCve, sCveTitle, dAffectedProductsAndThreats, sCveAcknowledgments, oVuln)
				else:
					pass
		#
		# Consolidate severity for each Bulletin
		for sBulletinName in self.dMSBulletins:
			#
			# Bulletin severity grade
			iSeverityGrade = 0
			#
			# Get grade by summing each CVE severity
			for sCve in self.dMSBulletins[sBulletinName]:
				if (u'productsandthreats' in self.dMSBulletins[sBulletinName][sCve]):
					if (u'0' in self.dMSBulletins[sBulletinName][sCve][u'productsandthreats']):
						iCveGrade = self.dMSBulletins[sBulletinName][sCve][u'productsandthreats'][u'0'][u'severity']
						iSeverityGrade += iCveGrade
					else:
						# don't care
						pass
				else:
						# don't care
					pass
			# end - for sCve
			#
			# Save the severity in another list
			self.lMSBulletinsSortedBySeverity.append({u'bulletinname':sBulletinName,
																			u'severity':iSeverityGrade})
		#end - for sBulletinName
		#
		# Sort by Severity grade, stored at self.dMSBulletins[sBulletinName][u'severity']
		self.lMSBulletinsSortedBySeverity = sorted(self.lMSBulletinsSortedBySeverity, key=lambda k: k[u'severity'], reverse=True)
	#end buildMsBulletins
	#
	#############################	
	def removeMsBulletin(self, sBulletinName):
		"""
		Remove a bulletin by is name in the global array of bulletins
		
		:param sBulletinName: name of the bulletin aka dict index, as a string
		"""
		# Remove from self.dMSBulletins
		if sBulletinName in self.dMSBulletins:
			del self.dMSBulletins[sBulletinName]
		else:
			pass
		#
		# remove from self.lMSBulletinsSortedBySeverity
		for iIndex, dBulletin in enumerate(self.lMSBulletinsSortedBySeverity):
			if (sBulletinName == dBulletin[u'bulletinname']):
				del self.lMSBulletinsSortedBySeverity[iIndex]
				break
			else:
				pass
	#end removeMsBulletin
	#
		#############################			
	def getMSBulletinReference(self, sDate):
		"""
		Here is the magic: auto calculate a MS Bulletin reference, depending
		on fixed value in self.dMsBulletinRealReferences and the bulletin real release date
		Reference is MS12-345
		
		:param sDate: bulletin release date ISO 8601, as a string
		"""
		#
		# ISO 8601 to datetime.datetime
		oDate = self.iso8601ToDatetime(sDate)
		#
		# Check the year has changed since the previous call to getMSBulletinReference()
		if (self.iBulletinReferenceCurrentYear==0):
			# first launch ?
			self.iBulletinReferenceCurrentYear = oDate.year
			self.iBulletinReferenceCurrentRef = 0
		elif (self.iBulletinReferenceCurrentYear == oDate.year):
			# Same year
			self.iBulletinReferenceCurrentYear = oDate.year
		else:
			# New year
			self.iBulletinReferenceCurrentYear = oDate.year
			self.iBulletinReferenceCurrentRef = 1
		#
		# First call
		# Search the highest floor for month in dMsBulletinRealReferences by simply
		# multiply year by 100, sort of left shift ;-)
		if (self.iBulletinReferenceCurrentRef == 0):
			iCurrentReleaseDate = oDate.year*100 + oDate.month
			#
			for dRealRef in self.dMsBulletinRealReferences:
				if (iCurrentReleaseDate>=dRealRef[u'date']):
					# last ref incremented to get the next bulletin ref
					self.iBulletinReferenceCurrentRef = dRealRef[u'ref'] + 1
				else:
					break
			#
			# Check
			if (self.iBulletinReferenceCurrentRef==0):
				# Bulletin seems too old...
				print ' [!] Error, this bulletin is too old od date is wrong:{%s}' % (sDate)
				sys.exit()
			else:
				pass
		#
		################################
		# Patch patch patch everywhere
		################################
		# Patch for MS16-043 that does not exists
		if ((oDate.year==2016) and (self.iBulletinReferenceCurrentRef==43)):
			self.iBulletinReferenceCurrentRef = 44
		#
		# Patch for MS16-063 that should have been in the update of may and has been delayed to june
		elif ((oDate.year==2016) and (oDate.month==5) and (self.iBulletinReferenceCurrentRef==63)):
			# ignore 63 and go to 64
			self.iBulletinReferenceCurrentRef = 64
		elif ((oDate.year==2016) and (oDate.month==6) and (self.iBulletinReferenceCurrentRef==68)):
			# start first bulletin as 63
			self.iBulletinReferenceCurrentRef = 63
		elif ((oDate.year==2016) and (oDate.month==6) and (self.iBulletinReferenceCurrentRef==64)):
			# second bulletin after 63 is 68
			self.iBulletinReferenceCurrentRef = 68
		#
		# Path for MS16-142 that with automation is 129 but Microsoft choose otherwise
		elif ((oDate.year==2016) and (oDate.month==11) and (self.iBulletinReferenceCurrentRef==129)):
			# Check if the patch as already been applied
			if (u'MS16-129' in self.dMSBulletinReferences):
				# ok, already applied, we don't do anything
				pass
			else:
				# patch the IE bulletin
				self.iBulletinReferenceCurrentRef = 142
		# Patch of the patch, correction for MS16-129 that's become 143 with previous patch :-/
		elif ((oDate.year==2016) and (oDate.month==11) and (self.iBulletinReferenceCurrentRef==143)):
			if (u'MS16-129' not in self.dMSBulletinReferences):
				# Patch for my own patch to recover a normal situation
				self.iBulletinReferenceCurrentRef = 129
		# Patch of the patch, correction for MS16-143 that's become 142 with previous patch :-/
		elif ((oDate.year==2016) and (oDate.month==12) and (self.iBulletinReferenceCurrentRef==142)):
			self.iBulletinReferenceCurrentRef = 143
		#
		# Patch for MS16-143 that does not exists
		if ((oDate.year==2016) and (self.iBulletinReferenceCurrentRef==143)):
			self.iBulletinReferenceCurrentRef = 144
		
		#
		# Create the bulletin reference
		sLocalRef = u'%s%s-%03d' %(self.sBulletinReferencePrefix, str(oDate.year)[2:4], self.iBulletinReferenceCurrentRef)
		#	
		# Add it to the dictionnary
		self.dMSBulletinReferences[sLocalRef] = True
		#
		# Juste increment the reference
		self.iBulletinReferenceCurrentRef+=1
		#
		return (sLocalRef,self.iBulletinReferenceCurrentRef-1)
	#end getMSBulletinReference
	#
	#############################	
	def getBulletinIE(self):
		for sBulletinName in self.dMSBulletins:
			if sBulletinName == self.dHCBulletinsName[u'HARD-CODED-IE']:
				return sBulletinName
		return None
	#end getBulletinIE
	#
	#############################		
	def getBulletinEdge(self):
		for sBulletinName in self.dMSBulletins:
			if sBulletinName == self.dHCBulletinsName[u'HARD-CODED-EDGE']:
				return sBulletinName
		return None
	#end getBulletinEdge
	#
	#############################
	def getBulletinFlash(self):
		for sBulletinName in self.dMSBulletins:
			if sBulletinName == self.dHCBulletinsName[u'HARD-CODED-FLASH']:
				return sBulletinName
		return None
	#end getBulletinFlash
	#
	#############################	
	def getBulletinSortedExceptAdobe(self):
		lMSBulletinsExceptAdobe = []
		for dBulletins in self.lMSBulletinsSortedBySeverity:
			if dBulletins[u'bulletinname'] != self.dHCBulletinsName[u'HARD-CODED-FLASH']:
				lMSBulletinsExceptAdobe.append(dBulletins[u'bulletinname'])
		return lMSBulletinsExceptAdobe
	#end getBulletinSortedExceptAdobe
	#
	#############################	
	def showBulletinOssirWay(self, sOutputFile, sBulletinName):
		"""
		Show the MS Bulletin like in the OSSIR's "revue d'actualite"
		"""
		#
		# Generate MS Bulletin Reference
		(sMsBulletinReference, iMsBulletinReference) = self.getMSBulletinReference(self.getRealReleaseDate())
		#			
		# Count number of CVE
		iCveCount = len(self.dMSBulletins[sBulletinName])
		#
		# Affected : for each CVE, get affected
		dBulletinAffected = {}
		for sCve in self.dMSBulletins[sBulletinName]:
			for sProductId in self.dMSBulletins[sBulletinName][sCve][u'productsandthreats']:
				if (sProductId==u'0'):
					# It's my dirty of storing iSeverityGrade, sorry again ;-D
					pass
				else:
					sProduct = self.getAffectedProductFullNameFromProductId(sProductId)
					if (sProduct not in dBulletinAffected):
						dBulletinAffected[sProduct] = 1
					else:
						dBulletinAffected[sProduct] = dBulletinAffected[sProduct] + 1
		#
		# Check for "all supported"
		lAllSupported = [
				u'Windows 10',
				u'Windows 7',
				u'Windows 8.1',
				u'Windows RT 8.1',
				u'Windows Server 2008',
				u'Windows Server 2012',
				u'Windows Server 2012 R2',
				u'Windows Server 2016',
				u'Windows Vista'
			]
		iCounter = 0
		for sSupportedProduct in lAllSupported:
			bFound = False
			for sAffectedProduct in dBulletinAffected:
				iLen = len(sSupportedProduct)
				#print "compare [%s] et [%s] " % (sSupportedProduct,sAffectedProduct[0:iLen])
				if (sSupportedProduct.upper() == sAffectedProduct[0:iLen].strip().upper()):
					bFound = True
				else:
					pass
			if bFound == True:
				iCounter = iCounter+1
			else:
				pass		
		print str(iCounter) + '/' + str(len(lAllSupported))
		if (iCounter == len(lAllSupported)):
			dBulletinAffected = [u'All supported OS']

		#
		# Impact : for each CVE, get impact
		# Bulletin impact
		dBulletinImpacts = {}
		for sCve in self.dMSBulletins[sBulletinName]:
			# Impact for only this CVE
			dCveImpact = {}
			#
			for sAffected in self.dMSBulletins[sBulletinName][sCve][u'productsandthreats']:
				if (sAffected==u'0'):
					# It's my dirty of storing iSeverityGrade, sorry again ;-D
					pass
				else:
					sTag = u'impact'
					if sTag in self.dMSBulletins[sBulletinName][sCve][u'productsandthreats'][sAffected]:
						sImpact = self.dMSBulletins[sBulletinName][sCve][u'productsandthreats'][sAffected][sTag]
					else:
						sImpact = '?'
					#
					if (sImpact not in dCveImpact):
						dCveImpact[sImpact] = 1
					else:
						dCveImpact[sImpact] = dCveImpact[sImpact] + 1
			# end - for
			#
			iImpactCount = 0
			for sImpact in dCveImpact:
				if (iImpactCount>1):
					print u' (i) Warn, more than 1 impact :{%s}' % (str(dCveImpact))
					pass
				else:
					if (sImpact not in dBulletinImpacts):
						dBulletinImpacts[sImpact] = 1
					else:
						dBulletinImpacts[sImpact] = dBulletinImpacts[sImpact] + 1

		
		
		#
		# Exploited : for each CVE, check exploited
		dBulletinExploited = {u'disclosed':[], u'exploited':[]}
		for sCve in self.dMSBulletins[sBulletinName]:
			#
			if (u'0' in self.dMSBulletins[sBulletinName][sCve][u'productsandthreats']):
				if (u'disclosed' in self.dMSBulletins[sBulletinName][sCve][u'productsandthreats'][u'0']):
					if (self.dMSBulletins[sBulletinName][sCve][u'productsandthreats'][u'0'][u'disclosed'] != u'no'):
						dBulletinExploited[u'disclosed'].append(sCve)
				if (u'exploited' in self.dMSBulletins[sBulletinName][sCve][u'productsandthreats'][u'0']):
					if (self.dMSBulletins[sBulletinName][sCve][u'productsandthreats'][u'0'][u'exploited'] != u'no'):
						dBulletinExploited[u'exploited'].append(sCve)
						
		#
		# Acknowledgements : for each CVE, get acknowledgements and merge duplicate names
		dAck = {}
		for sCve in self.dMSBulletins[sBulletinName]:
			sAck = self.dMSBulletins[sBulletinName][sCve][u'ack']
			if (sAck==u''):
				sAck = u'?'
			#
			if (sAck not in dAck):
				# new one
				dAck[sAck] = sCve
			else:
				dAck[sAck] = u"%s, %s" % (dAck[sAck], sCve)

		# OSSIR Show
		sOssirOutput = u''
		sOssirOutput+= u"\r\n"
		if (u'isoob' in self.dUpdateConfig):
			if (self.dUpdateConfig[u'isoob'] == True):
				sOssirOutput+= u'***** Out of Band Bulletin - OOB *****'
				sOssirOutput+= u"\r\n"
		
		#sOssirOutput+= u'%s Vulnerabilite dans %s (%d CVE)' %(sMsBulletinReference, sBulletinName, iCveCount)
		if (iCveCount==1):
			sOssirOutput+= u'%s Vulnerability in %s (%d CVE)' %(sMsBulletinReference, sBulletinName, iCveCount)
		else:
			sOssirOutput+= u'%s Vulnerabilities in %s (%d CVE)' %(sMsBulletinReference, sBulletinName, iCveCount)
		sOssirOutput+= u"\r\n"
		
		sOssirOutput+= u'  Affected:'
		sOssirOutput+= u"\r\n"
		lBulletinAffectedSorted = sorted(dBulletinAffected)
		for sProduct in lBulletinAffectedSorted:
			sOssirOutput+= u'    %s' % (sProduct)
			sOssirOutput+= u"\r\n"			
		
		sOssirOutput+= u'  Exploit:'
		sOssirOutput+= u"\r\n"		
		for sImpact in dBulletinImpacts:
			sOssirOutput+= u'    %d x %s' % (dBulletinImpacts[sImpact], sImpact)
			sOssirOutput+= u"\r\n"

		if (len(dBulletinExploited[u'disclosed'])>0):
			sTmpOutput = u''
			for sTmpCve in dBulletinExploited[u'disclosed']:
				sTmpOutput+= sTmpCve + u', '
			sTmpOutput = sTmpOutput[0:-2]
			sOssirOutput+= u'  Published: %s' % (sTmpOutput)
			sOssirOutput+= u"\r\n"

		if (len(dBulletinExploited[u'exploited'])>0):
			sTmpOutput = u''
			for sTmpCve in dBulletinExploited[u'exploited']:
				sTmpOutput+= sTmpCve + u', '
			sTmpOutput = sTmpOutput[0:-2]
			sOssirOutput+= u'  Exploited: %s' % (sTmpOutput)
			sOssirOutput+= u"\r\n"
			
		sOssirOutput+= u'  Credits:'
		sOssirOutput+= u"\r\n"
		for sAck in dAck:
			# French patch
			sAckFrench = sAck
			sAckFrench = sAckFrench.replace(u' of the ', u' de ')
			sAckFrench = sAckFrench.replace(u' working with ', u' par ')
			sAckFrench = sAckFrench.replace(u' of ', u' de ')
			sOssirOutput+= u'    %s (%s)' % (sAckFrench, dAck[sAck])
			sOssirOutput+= u"\r\n"
		
		print '  > Write bulletin %s to %s' % (sMsBulletinReference, sOutputFile)
		with open(sOutputFile,'a+b') as oFile:
			oFile.write(sOssirOutput.encode('utf-8'))

		
#end class
#
##
###
# End
###
##
#