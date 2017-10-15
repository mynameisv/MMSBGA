License
-------

DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE 

Version 3, August 2017
                    
Everyone is permitted to copy and distribute verbatim or modified 

copies of this license document, and changing it is allowed as long 

as the name is changed. 

DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE 
           
TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION 

1. You just DO WHAT THE FUCK YOU WANT TO.

2. As the "THE BEER-WARE LICENSE", if we meet some day, and you

 think this stuff is worth it, you can buy me a beer in return.


MMSBGA
------
```
 _____ _____ _____ _____ _____ _____ 
|     |     |   __| __  |   __|  _  |
| | | | | | |__   | __ -|  |  |     |
|_|_|_|_|_|_|_____|_____|_____|__|__|
                          
Make MS Bulletin Great Again
```

Why rebuild MS Bulletins !!?
-----------
Humans need to name things to use them. I'm human and MS Bulletin are things commonly used.
After the end of official MS Bulletin, we only get fucking unreadable XML with hundreds of CVEs and no way to simply get simple name like MS bulletin were.
Remember MS14-068, MS12-020 and MS17-010, yeah, but do you remember CVE-2017-0143 or CVE-2014-6324 ?
So here is a dev to automate MS Bulletin rebuild.

With autmation, all is not perfect, MS17-010 becomes MS17-009, but that ok 'cause old bulletins have already a reference. The work to rebuild the past was a way to check that my code was ok.

For now, the output is specific to a group a security enthusiasts people.


Patchssssssssss
-----------------
MS Bulletins has been clearly build manually, there is so much inconsistency !
I was force to make more than 100 patchs, mainly in obj_MsUpdate.py:buildMsBulletins() and obj_MsUpdate.py:getMSBulletinReference() :
 * CVE in REST API but in any MS Bulletin
 * CVE in a month A from the REST API, but in the month B in MS Bulletin
 * Lots of Jscript CVE sometimes in Jscript Bulletin AND Edge/IE Bulletin, and sometimes not
 * Missing string in CVE name (CVE-2016-9890 is referenced as '2016-9890')
 * ...


Usage
-----------------
1/ Create a Microsoft Security Response Center (MSRC) Portal account 
https://portal.msrc.microsoft.com/en-us/developer
2/ Sign-in
3/ Go to developer's tab or here : https://portal.msrc.microsoft.com/en-us/developer
4/ Generate (or Regenerate) and show your API Key
5/ Edit mmsbga.py and set g_ApiKey (near line 52)
6/ If needed, configure the proxy (near line 40)
6/ Run the script : python mmsbga.py





Todo
-----------------
Todo : 
 * Use python 3
 * Propose another output form
 * Add real english and french output
 * Put parameters in a .conf file and add command line switches
 * Use the release history to update bulletins
 * Create a way to check every hour and update a kind of database to have web pages like the old bulletin, and a main page that present the bulletin updates (aka rebuild old MS web site ^_^)
 * Clean the code
 * Select the month you want without rebuilding the previous month
 * Stop using fixed values/strings/... in the code



Unsolved problems
-----------------
MS16-119 includes CVE-2016-7189, CVE-2016-7190 and CVE-2016-7194 : https://technet.microsoft.com/en-us/library/security/ms16-119.aspx
But in Microsoft REST API, there are not provided !!?

Everytime, Flash bulletin is the last of the month except in decembre 2016, .Net (MS16-155) is after Flash (MS16-154)
Fuck Fuck Fuck !!!

MS16-144 includes CVE-2016-7202 : https://technet.microsoft.com/fr-fr/library/security/ms16-144.aspx
But in Microsoft REST API, it is not provided !!?



Last word ?
-----------

````
         ///\\\  ( Have Fun )
        / ^  ^ \ /
      __\  __  /__
     / _ `----' _ \
     \__\   _   |__\
      (..) _| _ (..)
       |____(___|     Mynameisv_ 2017
_ __ _ (____)____) _ _________________________________ _'
````