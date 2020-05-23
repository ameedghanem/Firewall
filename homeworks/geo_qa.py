import requests 
import lxml.html
import rdflib
import nltk, sys

wiki_prefix = "http://en.wikipedia.org"
united_natinos_url = "https://en.wikipedia.org/wiki/List_of_countries_by_population_(United_Nations)"
"""
president = infobox.xpath("//president//text()")[0].replace(" ", "_")
prime minister = infobox.xpath("//prime minister//text()")[0].replace(" ", "_")
population = infobox.xpath("//population//text()")[0].replace(" ", "_")
area = infobox.xpath("//area//text()")[0].replace(" ", "_")
government = infobox.xpath("//government//text()")[0].replace(" ", "_")
capital = infobox.xpath("//capital//text()")[0].replace(" ", "_")
"""
countries_map = {}# a dictionary which will map a country to a list of its relevant elemtns (presidnet, capital, etc..)

#########################
# Information Extraction
#########################


def get_cherecter_info(url):
	"""
	Accepts a url of some president.
	Returns his name and his date of birth
	"""
	res = requests.get(url)
	doc = lxml.html.fromstring(res.content)
	infobox = doc.xpath("//table[contains(@class, 'infobox')]")[0].replace(" ", "_")

	# extract the charecter name
	#name = infobox.xpath("//table//div[@class='fn')]/text()")[0].replace(" ", "_")

	# extract the date of birth
	b = infobox.xpath("//table//th[contains(text(), 'Born')]")[0].replace(" ", "_")
	if b != []:
		bdate = xpath("./../td//span[@class='bday']//text()")[0].replace(" ", "_")

	return bdate



def get_countries_info(url):
	"""
	Accepts a url of all countries in the world.
	It creates an onology for those countries.
	"""
	res = requests.get(url) 
	doc = lxml.html.fromstring(res.content)
	
	table = doc.xpath("//table[contains(@id, 'main')]")[0]
	countries = table.xpath("//td//span/a[@title]/@href")

	president = prime_minister = population = area = government = capital = ""
	pt_bdate = pm_bdate = ""

	with open("ontology.nt", 'a+') as writer:
		for c in countries:
			page = requests.get(wiki_prefix + c)
			page_doc = lxml.html.fromstring(page.content)
			infobox = page_doc.xpath("//table[contains(@class, 'infobox')]")[0]

			cname = infobox.xpath("//div[@class='fn org country-name']/text()")[0].replace(" ", "_")

			president_h = infobox.xpath("//th//div/a[contains(@title, 'President of')]")
			if president_h != []:
				print(president_h)
				president = president_h[0].xpath("././../td//a/text()")[0]
				president_link = president_h[0].xpath("./../td//a/@href")[0]
				print(president_link)
				pt_bdate = get_charecter_info(wiki_prefix + president_link)

			print(president, cname)
			prime_minister_h = infobox.xpath("//table//th[contains(text(), 'Prime Minister')]")
			if president_h != []:
				prime_minister = prime_minister_h[0].xpath("./../td/text()")[0]
				prime_minister_link = prime_minister_h[0].xpath("./../td//a/@href")[0]
				pm_bdate = get_charecter_info(wiki_prefix + prime_minster_link)


			population_h = infobox.xpath("//table//th[contains(text(), 'Population')]")
			if population_h != []:
				population = population_h[0].xpath("./../td/text()")[0]


			area_h = infobox.xpath("//table//th[contains(text(), 'Area')]")
			if area_h != []:
				area = area_h[0].xpath("./../td/text()")[0]


			government_h = infobox.xpath("//table//th[contains(text(), 'Government')]")
			if government_h != []:
				government = government_h[0].xpath("./../td/text()")[0]


			capital_h = infobox.xpath("//table//th[contains(text(), 'Capital')]")
			if capital_h != []:
				capital = "a"#capital_h[0].xpath("./../td/text()")[0]


			writer.write("<http://example.org/{0}> <http://example.org/president> <http://example.org/{1}> .\n".format(president, cname))
			writer.write("<http://example.org/{0}> <http://example.org/prime_minister> <http://example.org/{1}> .\n".format(prime_minister, cname))
			writer.write("<http://example.org/{0}> <http://example.org/population> <http://example.org/{1}> .\n".format(population, cname))
			writer.write("<http://example.org/{0}> <http://example.org/area> <http://example.org/{1}> .\n".format(area, cname))
			writer.write("<http://example.org/{0}> <http://example.org/government> <http://example.org/{1}> .\n".format(government, cname))
			writer.write("<http://example.org/{0}> <http://example.org/capital> <http://example.org/{1}> .\n".format(capital, cname))
			writer.write("<http://example.org/{0}> <http://example.org/born> <http://example.org/{1}> .\n".format(president, pt_bdate))
			writer.write("<http://example.org/{0}> <http://example.org/born> <http://example.org/{1}> . \n".format(prime_minister, pm_bdate))






###############################
# Natural Language Processing
###############################

def parse_question(question):
	"""
	Accepts a question in the english language
	Returns a sparql query properly
	"""
	pass



def get_asnwer(query):
	"""
	Accepts a sparql query
	Returns the query's answer according to the ontology we've created before
	"""
	pass



###############
# M  A  I  N
###############

def run(argv):
	cmd = argv[1]
	if cmd == 'create' and argv[2].endswith(".nt"):
		get_countries_info(united_natinos_url)
	elif cmd == 'question':
		query = parse_question(argv[2])
		get_answer(query)
	else:
		print("Invalid Command")
		return


"""
if __name__ == '__main__':
	if len(sys.argv) != 3:
		print("Usage: {} <command> <argument>".format(sys.argv[0]))
	run(sys.argv)
"""

get_countries_info(united_natinos_url)