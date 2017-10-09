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
# Make MS Bulletin Great Again / MMSBGA
#############################
# Download MS security updates and rebuild MS Bulletin
#
# [ History ]
# * 2017-06
#  o creation
#
#############################
#
##
###
###########################################################
## Config
################################
#
# Proxy config
g_dProxyConfig = {
	u'enabled':False,#True,	# use proxy (True) or not (False)
	u'username':u'bob',			# username for proxy auth
	u'password':u'password',	# password for proxy auth
	u'proxy':u'http://1.2.3.4:8080',			# proxy url with port, like http://1.2.3.4:8080
	u'authtype':u'digest',	# proxy auth type as a string: u'basic' or u'digest'
	u'sslca':u'test.crt'			# if ssl/tls decypher, ca file name containing the ca, as a string, like: u'myownca.crt'
}
#
#
# Here your Microsoft Security Update REST API Key
g_ApiKey = u'1234...abcd...1234'
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
import sys
#import lxml.etree
from lxml import etree
#import xml.etree.ElementTree
from obj_RequestsWrap import objRequestsWrap
from obj_MsUpdates import objMsUpdates
from obj_MsUpdate import objMsUpdate
#
##
###
################################################################
## Parameters
################################
# Version, name, author...
fVersion = 0.1
sScriptName = u'MMSBGA'
Author = u'Mynameisv_'
#
##
###
###########################################################
# Functions
#############################
#
#############################
def getValueFromParent(oParent, namespaces, sName, sTitle=u''):
	oChild = oParent.find(sName, namespaces=namespaces)
	if oChild is not None:
		if (sTitle==u''):
			# return .text
			if oChild.text is not None:
				return oChild.text.strip()
			else:
				return u''
		if u'Title' in oChild.attrib:
			if (oChild.attrib[u'Title'] == sTitle):
				return oChild.text.strip()
			else:
				return u''
		else:
			return u''
	else:
		return u''
#end getValueFromParent
#
#############################
def getTitleFromVuln(oVuln, namespaces):
	return getValueFromParent(oVuln, namespaces, u'vuln:Title')
#end getTitleFromVuln
#
#############################
def getNoteFromVuln(oVuln, namespaces):
	oChild = oVuln.find(u'vuln:Notes', namespaces=namespaces)
	if (oChild==None):
		return u''
	else:
		return getValueFromParent(oChild, namespaces, u'vuln:Note', u'Description')
#end getNoteFromVuln
#
#############################
def getDescriptionFromThreat(oThreat, namespaces):
	return getValueFromParent(oThreat, namespaces, u'vuln:Description')
#end getDescriptionFromThreat
#


#
##
###
###########################################################
# Main
#############################
def main():
	#
	global g_ApiKey
	#
	# Get all MS Updates
	print u''
	print u'================================'
	print u'[>] Get all available MS updates links'
	#
	oUpdates = objMsUpdates()
	#
	# Set api key
	oUpdates.setApiKey(g_ApiKey)
	#
	# Get updates from MS API and sort them
	lUpdates = oUpdates.get(g_dProxyConfig)
	#
	print u' + Found %d updates' % (len(lUpdates))
	del oUpdates
	#
	#lUpdates = [{u'CvrfUrl': u'https://api.msrc.microsoft.com/cvrf/2016-Apr?api-Version={2016-08-01}', u'Severity': None, u'DocumentTitle': u'April 2016 Security Updates', u'CurrentReleaseDate': u'2017-05-16T07:00:00Z', u'RealReleaseDate': '2016-04-01T01:00:00Z', u'Alias': u'2016-Apr', u'InitialReleaseDate': u'2017-05-16T07:00:00Z', u'ID': u'2016-Apr'}]
	#
	# Bulletin reference counter, start at 0 if we start at April 2016
	iBulletinReference = 0
	#
	# Last bulletin release year
	iYear = 0
	#
	# Proceed all updates
	for dUpdate in lUpdates:
		print u''
		print u'================================'
		print u'[>] Get MS update from Microsoft MSRC API...'
		#
		# Create update object from dictionnary retrieved previously
		oUpdate = objMsUpdate(dUpdate)

		#
		#
		print u'          Update ID:{%s}' % (oUpdate.getId())
		print u'       Release date:{%s}' % (oUpdate.getCurrentReleaseDate())
		print u'  Real release date:{%s} (mmsbga patch)' % (oUpdate.getRealReleaseDate())
		print u'              Alias:{%s}' % (oUpdate.getAlias())
		print u'              Title:{%s}' % (oUpdate.getDocumentTitle())
		print u'--------------------------------'
		print u''
		#
		# 
		print '  > Write month header to ossir.txt'
		sHeader = u"\r\n"
		sHeader+= u'================================'
		sHeader+= u"\r\n"
		sHeader+= u' Make MS Bulletin Great Again / MMSBGA'
		sHeader+= u"\r\n"
		sHeader+= u'--------------------------------'
		sHeader+= u"\r\n"
		sHeader+= u' Microsoft Security Bulletin for: %02d-%s' % (oUpdate.getBulletinRealMonth(), oUpdate.getBulletinRealYear())
		sHeader+= u"\r\n"
		sHeader+= u'          Update ID:{%s}' % (oUpdate.getId())
		sHeader+= u"\r\n"
		sHeader+= u'       Release date:{%s}' % (oUpdate.getCurrentReleaseDate())
		sHeader+= u"\r\n"
		sHeader+= u'  Real release date:{%s} (mmsbga patch)' % (oUpdate.getRealReleaseDate())
		sHeader+= u"\r\n"
		sHeader+= u'              Alias:{%s}' % (oUpdate.getAlias())
		sHeader+= u"\r\n"
		sHeader+= u'              Title:{%s}' % (oUpdate.getDocumentTitle())
		sHeader+= u"\r\n"
		sHeader+= u'--------------------------------'
		sHeader+= u"\r\n"
		with open('ossir.txt','a+b') as oFile:
			sContent = oFile.write(sHeader.encode('utf-8'))
		#
		# Set the Bulletin Reference Counter
		oUpdate.setBulletinsReferenceCount(iBulletinReference)
		#
		# Set api key
		oUpdate.setApiKey(g_ApiKey)
		#
		# Set last bulletin year
		oUpdate.setLastBulletinYear(iYear)
		#
		# Get update
		#oUpdate.get(g_dProxyConfig, oUpdate.getAlias()+u'.xml')
		oUpdate.get(g_dProxyConfig)
		#
		#
		# Build Product list
		print u'  > Build products from Bulletin'
		oUpdate.buildProductsFromBulletin()
		print u'   + Found %d products' % (oUpdate.getProductsCount())
		#
		# Build the MS Bulletins from this Update
		print u'  > Build MS Bulletins'
		oUpdate.buildMsBulletins()
		print u'   + Found %d CVE' % (oUpdate.getVulnerabilitiesCount())
		print u'   + Found %d Bulletins' % (oUpdate.getBulletinsCount())
		#
		print u'  > Rebuilding MS Bulletins, with a fixed order (IE, Edge, ..., Flash)'
		
		#for d in oUpdate.lMSBulletinsSortedBySeverity:
		#	print str(d)
			
			
		#
		################################
		# Internet Explorer
		sBulletinName = oUpdate.getBulletinIE()
		if sBulletinName == None:
			print u'   * That is very odd, there is no Internet Explorer bulletin this month !!'
		else:
			#
			oUpdate.showBulletinOssirWay(sBulletinName)
			#
			# Remove this bulletin
			oUpdate.removeMsBulletin(sBulletinName)
		#
		################################
		# Edge
		sBulletinName = oUpdate.getBulletinEdge()
		if sBulletinName == None:
			print u'   * That is very odd, there is no Edge bulletin this month !!'
		else:
			#
			oUpdate.showBulletinOssirWay(sBulletinName)
			#
			# Remove this bulletin
			oUpdate.removeMsBulletin(sBulletinName)
		#
		################################
		# Every bulletin, except Adobe
		for sBulletinName in oUpdate.getBulletinSortedExceptAdobe():
			oUpdate.showBulletinOssirWay(sBulletinName)
		#
		################################
		# Adobe Flash
		sBulletinName = oUpdate.getBulletinFlash()
		if sBulletinName == None:
			print u'   * That is very odd, there is no Flash bulletin this month !!'
		else:
			#
			oUpdate.showBulletinOssirWay(sBulletinName)
			#
			# Remove this bulletin
			oUpdate.removeMsBulletin(sBulletinName)
		#
		################################
		#
		# Keep the Bulletin Reference counter (MSyy-12345)
		iBulletinReference = oUpdate.getBulletinsReferenceCount()
		#
		# Get and keep bulletin release year
		iYear = oUpdate.getBulletinRealYear()
		#
		# Bulletin footer
		print '  > Write month footer to ossir.txt'
		sFooter = u"\r\n"
		with open('ossir.txt','a+b') as oFile:
			sContent = oFile.write(sFooter.encode('utf-8'))
# end main
#
##
###
################################
# Generic main call
################
if __name__ == '__main__':
	main()
else:
	main()
#
##
###
# End
###
##
#
