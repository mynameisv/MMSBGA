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
#from lxml import etree
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
# Config file
g_sJsonConfigFile = u'mmsbga.conf.json'
#
# Output file
g_sOutputFile = u'output.txt'
#
# Proxy config
g_dProxyConfig = {}
#
# Here your Microsoft Security Update REST API Key
g_ApiKey = u''		
#
##
###
###########################################################
# Functions
#############################
#
#############################
def loadConf():
	"""
	Load configuration : proxy and msrc api key
	"""
	global g_dProxyConfig, g_ApiKey
	#
	# load file content
	with open(g_sJsonConfigFile,'rb') as oFile:
		sJsonContent = oFile.read()
	#
	dJsonContent = json.loads(sJsonContent)
	if (type(dJsonContent)!=dict):
		print u' ! Error, Json configuration file is wrong: not a dictionnary.'
		sys.exit(1)
	else:
		sSection = u'proxy'
		if (sSection in dJsonContent):
			# use proxy (True) or not (False)
			sTag = u'enabled'
			if (sTag in dJsonContent[sSection]):
				if (dJsonContent[sSection][sTag].upper() == 'TRUE'):
					g_dProxyConfig[sTag] = True
				else:
					g_dProxyConfig[sTag] = False
			else:
				g_dProxyConfig[sTag] = False
			# username for proxy auth
			sTag = u'username'
			if (sTag in dJsonContent[sSection]):
				g_dProxyConfig[sTag] = dJsonContent[sSection][sTag]
			else:
				g_dProxyConfig[sTag] = u''
			# password for proxy auth
			sTag = u'password'
			if (sTag in dJsonContent[sSection]):
				g_dProxyConfig[sTag] = dJsonContent[sSection][sTag]
			else:
				g_dProxyConfig[sTag] = u''
			# proxy url with port, like http://1.2.3.4:8080
			sTag = u'proxy'
			if (sTag in dJsonContent[sSection]):
				g_dProxyConfig[sTag] = dJsonContent[sSection][sTag].strip()
			else:
				g_dProxyConfig[sTag] = u''
			# proxy auth type as a string: u'basic' or u'digest'
			sTag = u'authtype'
			if (sTag in dJsonContent[sSection]):
				g_dProxyConfig[sTag] = dJsonContent[sSection][sTag].strip()
			else:
				g_dProxyConfig[sTag] = u'digest'
			# if ssl/tls decypher, ca file name containing the ca, as a string, like: u'myownca.crt'
			sTag = u'sslca'
			if (sTag in dJsonContent[sSection]):
				g_dProxyConfig[sTag] = dJsonContent[sSection][sTag].strip()
			else:
				g_dProxyConfig[sTag] = u''
		#
		sSection = u'api-key'
		if (sSection in dJsonContent):
			# api key
			g_ApiKey = dJsonContent[sSection].strip()
#
#
##
###
###########################################################
# Main
#############################
def main():
	#
	global g_dProxyConfig, g_ApiKey
	#
	print u''
	print u'%s %.2f / %s' % (sScriptName, fVersion, Author)
	print u''
	print u'================================'
	print u'[>] Loading configuration'
	loadConf()
	print u' + Done.'
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
		print '  > Write month header to %s' % (g_sOutputFile)
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
		with open(g_sOutputFile,'a+b') as oFile:
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
			oUpdate.showBulletinOssirWay(g_sOutputFile, sBulletinName)
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
			oUpdate.showBulletinOssirWay(g_sOutputFile, sBulletinName)
			#
			# Remove this bulletin
			oUpdate.removeMsBulletin(sBulletinName)
		#
		################################
		# Every bulletin, except Adobe
		for sBulletinName in oUpdate.getBulletinSortedExceptAdobe():
			oUpdate.showBulletinOssirWay(g_sOutputFile, sBulletinName)
		#
		################################
		# Adobe Flash
		sBulletinName = oUpdate.getBulletinFlash()
		if sBulletinName == None:
			print u'   * That is very odd, there is no Flash bulletin this month !!'
		else:
			#
			oUpdate.showBulletinOssirWay(g_sOutputFile, sBulletinName)
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
		print '  > Write month footer to %s' %(g_sOutputFile)
		sFooter = u"\r\n"
		with open(g_sOutputFile,'a+b') as oFile:
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
