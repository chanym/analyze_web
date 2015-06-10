#!/usr/bin/ruby
puts "\n** URL scraper found in website and check against Virustotal **\n\n"

if ARGV.length != 2 || !(ARGV[0].to_s =~ /\bie\b|\bff\b|\bchrome\b/) 
	puts "Usage - ./analyze_web.rb [user-agent] [url]"
	puts "\nUSER-AGENT:\n"
	puts "ie - 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)'"
	puts "ff - 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:29.0) Gecko/20120101 Firefox/29.0'"
	puts "chrome - 'Mozilla/5.0 (Windows NT 4.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36'"
	puts "\nExample - ./analyze_web.rb ie company.com"
	puts "Example - ./analyze_web.rb ff company.com"
	puts "Example - ./analyze_web.rb chrome company.com"
	exit
end

require 'rubygems'
require 'uirusu'

#You can specify your own user agent by adding to the hash below and change according in line 10 condition
ua = {'ie' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)',
			'ff' => 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:29.0) Gecko/20120101 Firefox/29.0',
			'chrome' => 'Mozilla/5.0 (Windows NT 4.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36'} 

APT_KEY = "" #insert your virustotal API key here

uagent = ua[ARGV[0]]
url = ARGV[1]
all_sites = []

def get_data(uagent, url)
	total = []
	all_url = []
	page = `curl -s -A "#{uagent}" "#{url}"`
	page.force_encoding("iso-8859-1").split.each do |x|
 		total << x.split('href="')[1].to_s.split('"')[0] if x =~ /href="/
 		total << x.split("href='")[1].to_s.split("'")[0] if x =~ /href='/
 		total << x.split('src="')[1].to_s.split('"')[0] if x =~ /src="/
 		total << x.split("src='")[1].to_s.split("'")[0] if x =~ /src='/
 	end 

	total.uniq!
	total.each {|x| all_url << x if x =~ /^http|^https/}
	all_url
end

def query_virustotal(total_url)
	count = 0
	puts "Total url to be query against virustotal : #{total_url.length}"
 	puts "Estimate time will be #{(total_url.length / 4.to_f).ceil} minutes as I am using non premium API key..."
 	print "*******\n"
   
 	total_url.each do |z|
 		result_array = []
 		if count < 4
 			results = Uirusu::VTUrl.query_report(APT_KEY, z)
 			result = Uirusu::VTResult.new(z, results)
 			result_array = result.to_stdout.split("\n")
 			puts result_array[0]
 			result_array.each {|a| puts a if a =~ /mal(ware|icious) site/}
 			count += 1
 		else
 			sleep 60
 			count = 0
 			redo
 		end
	end
end

count = 0

total_url = get_data(uagent, url)

if total_url.length == 0
	puts "There are no url to be queried... perhaps the site is not available"
	exit
else
	query_virustotal(total_url)
end
