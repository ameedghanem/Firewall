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
countries_map = {}# a dictionary which will map a country to a list of its relevant elemtns (president, capital, etc..)

#########################
# Information Extraction
#########################


def get_charecter_info(url):
	"""
	Accepts a url of some president.
	Returns his name and his date of birth
	"""
	res = requests.get(url)
	if res.status_code != 200:
		return ""
	doc = lxml.html.fromstring(res.content)
	infobox = doc.xpath("//table[contains(@class, 'infobox')]")[0]

	# extract the charecter name
	#name = infobox.xpath("//table//div[@class='fn')]/text()")[0].replace(" ", "_")

	# extract the date of birth
	bdate = ""
	b = infobox.xpath("//table//th[contains(text(), 'Born')]")
	if b != []:
		lst = b[0].xpath("./../td//span[@class='bday']//text()")
		if lst != []:
			if '\n' in lst:
				lst.remove('\n')
			#print(lst)
			bdate = lst[0].replace(" ", "_")
	if bdate == "":
		b = infobox.xpath("//table//th[contains(text(), 'Born')]")
		if b != []:
			lst = b[0].xpath("./../td/text()[1]")
			if lst != []:
				bdate = lst[0].replace(" ", "_")
	if sum([1 for ch in bdate if 0 <= ord(ch)-ord('0') <= 9]) < 1:
		bdate = ""
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
			# some of these fields are empty in some of the countries. Thus, we need to initialize them in each iteration
			president = prime_minister = population = area = government = capital = ""
			pt_bdate = pm_bdate = ""

			page = requests.get(wiki_prefix + c)
			page_doc = lxml.html.fromstring(page.content)
			infobox = page_doc.xpath("//table[contains(@class, 'infobox')]")[0]

			cname = ""
			cname_lst = infobox.xpath("//th/div[(contains(@class, 'fn org') and position()=1)]//text()")
			if cname_lst == []:
				cname_lst = infobox.xpath("//th/div/div[contains(@class, 'fn org')]/div/div/span[1]/text()")
			if '\n' in cname_lst:
				cname_lst.remove('\n')
			for word in cname_lst:
				if '[' in word:
					continue
				cname += word.replace(" ", "_")

			president_h = infobox.xpath("//th//div/a[text()='President']")
			if president_h != []:
				president = president_h[0].xpath("../../../td//a/text()")[0].replace(" ", "_")
				president_link = president_h[0].xpath("../../../td//a/@href")[0]
				pt_bdate = get_charecter_info(wiki_prefix + president_link)


			prime_minister_h = infobox.xpath("//tr//div/a[text()='Prime Minister']")
			if prime_minister_h != []:
				lst = prime_minister_h[0].xpath("../../../td//a/text()")
				if '\n' in lst:
					lst.remove('\n')
				prime_minister = lst[0].replace(" ", "_")
				prime_minister_link = prime_minister_h[0].xpath("../../../td//a/@href")[0]
				pm_bdate = get_charecter_info(wiki_prefix + prime_minister_link)


			population_h = infobox.xpath("//table//th//a[text()='Population']")
			if population_h != []:
				estimate = population_h[0].xpath("../../..//text()[contains(., 'estimate') or contains(., 'census') or contains(., 'Estimate')]/..")[0]
				lst = estimate.xpath("../..//td[1]//text()")
				if '\n' in lst:
					lst.remove('\n')
				population = lst[0].replace(" ", "")


			area_h = infobox.xpath("//table//th/a[contains(text(), 'Area')]")
			if area_h != []:
				total = area_h[0].xpath("../../../tr/th[1]/div[(contains(text(), 'Land') or contains(text(), 'Total')) and position()=1]")[0]
				area = total.xpath("../../td[1]/text()")[0]
				if '$' in area:
					total = area_h[0].xpath("../../../tr//div[contains(./a/text(), 'Land')]")[0]
					area = total.xpath("../../td[1]/text()")[0]
				area = ' '.join(area.split())
				if ' ' in area:
					ind = area.index(' ')
					area = area[:ind] + "_km2"
				elif not area.endswith("km2"):
					area = area + "_km2"


			government_h = infobox.xpath("//table//th//text()[contains(., 'Government')]/..")
			if government_h != []:
				government_words = government_h[0].xpath("../..//td/a/text()")
				for word in government_words:
					government += (word.replace(" ", "_") + "_")
				government = government[:-1]


			capital_h = infobox.xpath("//table//th[contains(text(), 'Capital')]")
			if capital_h != []:
				capital_lst = capital_h[0].xpath("./../td//text()")
				if '\n' in capital_lst:
					capital_lst.remove('\n')
				capital = capital_lst[0].replace(" ", "_")

			#print(cname, president, pt_bdate, capital, government, population, area, prime_minister)
			print(cname, capital, area)
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