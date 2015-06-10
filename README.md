# analyze_web
Scrap against webpage to gather URL and verified against VirusTotal

I use this script to scrape website for all URL and submitting them to virustotal for records

There is a catch though as I am using a public API key which only allows me to verify against virustotal 4 times per minute

Please insert your own virustotal API key in order for the script to work

Usage - ./analyze_web.rb [user-agent] [url]

USER-AGENT:

ie - 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)'

ff - 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:29.0) Gecko/20120101 Firefox/29.0'

chrome - 'Mozilla/5.0 (Windows NT 4.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36'

Example - ./analyze_web.rb ie company.com

Example - ./analyze_web.rb ff company.com

Example - ./analyze_web.rb chrome company.com
