http-vuln-exchange.nse
======================

This script, initially created by Kevin Beaumont (a.k.a @GossiTheDog) tries to determine the patch status of Exchange servers against the CVEs used by Hafnium (a.k.a. ProxyLogin a.k.a. - CVE-2021-26855, CVE-2021-26857, CVE-2021-26858 and CVE-2021-27065) by looking at the version number found on the /owa URI.

Last updated on 19-3-2021

Version/patch information based on: 
* https://techcommunity.microsoft.com/t5/exchange-team-blog/released-march-2021-exchange-server-security-updates/ba-p/2175901
* https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-microsoft-exchange-server-2019-2016-and-2013-march-2-2021-kb5000871-9800a6bb-0a21-4ee7-b9da-fa85b3e1d23b
* https://docs.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates?view=exchserver-2019