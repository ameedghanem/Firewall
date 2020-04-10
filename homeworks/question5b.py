import xml.etree.ElementTree as ET
import requests
import lxml.html
import sys


def q5b(url:str):
	try:
		res = requests.get(url)
	except:
		sys.exit("Couldn't open the given url")
	doc = lxml.html.fromstring(res.content)
	print("<---------------------------->\npart a\n<---------------------------->")
	for attr in doc.xpath("//img[@alt!='']/@src"): # (a)
		print(attr)
	print("<---------------------------->\npart b\n<---------------------------->")
	for link in doc.xpath("//a[contains(@href, 'co.uk') and ( contains(@href, 'http://www') or contains(@href, 'https://www') )]/@href"): # (b)
		print(link)
	print("<---------------------------->\npart c\n<---------------------------->")
	for row in doc.xpath("//table[position()=1]/tbody[position()=1]/tr[position()=2]//text()"): # (c)
		print(row)
	print("<---------------------------->\npart d\n<---------------------------->")
	for word in doc.xpath("//b//text()"): # (d)
		print(word)


if __name__ == '__main__':
	if len(sys.argv) != 2:
		sys.exit(f'USAGE: python {sys.argv[0]} <url>')
	q5b(sys.argv[1])