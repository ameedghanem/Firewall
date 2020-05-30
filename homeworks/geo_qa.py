import requests 
import lxml.html
import rdflib
import urllib
import nltk, sys

wiki_prefix = "http://en.wikipedia.org"
example_prefix = "http://example.org/"
united_natinos_url = "https://en.wikipedia.org/wiki/List_of_countries_by_population_(United_Nations)"

president_r = rdflib.URIRef("http://example.org/president")
prime_minister_r = rdflib.URIRef("http://example.org/prime_minister")
population_r = rdflib.URIRef("http://example.org/population")
area_r = rdflib.URIRef("http://example.org/area")
capital_r = rdflib.URIRef("http://example.org/capital")
born_r = rdflib.URIRef("http://example.org/born")
government_r = rdflib.URIRef("http://example.org/government")

cname_index = 6
total_presidents = set()

#########################
# Information Extraction
#########################


def update_ontology(ontology, cname, capital, president, pt_bdate, prime_minister, pm_bdate, government, population, area):
	"""
	Adds all relevnt data about the given country!
	"""
	if capital != "":
		ontology.add((rdflib.URIRef(example_prefix+cname), capital_r, rdflib.URIRef(example_prefix+capital)))
	if president != "":
		ontology.add((rdflib.URIRef(example_prefix+cname), president_r, rdflib.URIRef(example_prefix+president)))
	if prime_minister != "":
		ontology.add((rdflib.URIRef(example_prefix+cname), prime_minister_r, rdflib.URIRef(example_prefix+prime_minister)))
	if pt_bdate != "":
		if president not in total_presidents:
			total_presidents.add(president)
			ontology.add((rdflib.URIRef(example_prefix+president), born_r, rdflib.URIRef(example_prefix+pt_bdate)))
	if pm_bdate != "":
		ontology.add((rdflib.URIRef(example_prefix+prime_minister), born_r, rdflib.URIRef(example_prefix+pm_bdate)))
	if government != "":
		ontology.add((rdflib.URIRef(example_prefix+cname), government_r, rdflib.URIRef(example_prefix+government)))
	if population != "":
		ontology.add((rdflib.URIRef(example_prefix+cname), population_r, rdflib.URIRef(example_prefix+population)))
	if area != "":
		ontology.add((rdflib.URIRef(example_prefix+cname), area_r, rdflib.URIRef(example_prefix+area)))
	total_presidents.add(president)


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



def get_countries_info(url, ontology_path):
	"""
	Accepts a url of all countries in the world.
	It creates an onology for those countries.
	"""
	a,b = 0,0
	dd =[]
	countries_ontology = rdflib.Graph()
	res = requests.get(url) 
	doc = lxml.html.fromstring(res.content)
	
	table = doc.xpath("//table[contains(@id, 'main')]")[0]
	countries = table.xpath("//td//span[1]/a[@title]/@href")

	president = prime_minister = population = area = government = capital = ""
	pt_bdate = pm_bdate = ""

	for c in countries:
		# some of these fields are empty in some of the countries. Thus, we need to initialize them in each iteration
		president = prime_minister = population = area = government = capital = ""
		pt_bdate = pm_bdate = ""

		page = requests.get(wiki_prefix + c)
		page_doc = lxml.html.fromstring(page.content)
		infobox = page_doc.xpath("//table[contains(@class, 'infobox')]")[0]

		cname = c[cname_index:]
		cname = urllib.parse.unquote(cname)

		president_h = infobox.xpath("//th//div/a[text()='President']")
		if president_h != []:
			president = president_h[0].xpath("../../../td//a/text()")[0].replace(" ", "_")
			president_link = president_h[0].xpath("../../../td//a/@href")[0]
			pt_bdate = get_charecter_info(wiki_prefix + president_link)


		prime_minister_h = infobox.xpath("//tr//div/a[contains(text(), 'Prime Minister')]")
		if prime_minister_h != []:
			lst = prime_minister_h[0].xpath("../../../td//a/text()")
			if '\n' in lst:
				lst.remove('\n')
			prime_minister = lst[0].replace(" ", "_")
			prime_minister_link = prime_minister_h[0].xpath("../../../td//a/@href")[0]
			pm_bdate = get_charecter_info(wiki_prefix + prime_minister_link)


		population_h = infobox.xpath("//table//th//a[text()='Population']")
		#print(infobox.xpath("//table//th//a[text()='Population']/text()"), cname)
		if population_h != []:
			estimate = population_h[0].xpath("../../..//text()[contains(., 'estimate') or contains(., 'census') or contains(., 'Estimate')]/..")[0]
			lst = estimate.xpath("../..//td[1]//text()")
			if '\n' in lst:
				lst.remove('\n')
			p = lst[0].replace(" ", "")
			if '(' in p:
				p = p[:p.index('(')]
			if p.endswith('\n'):
				 p = p[:-1]
			population = p
			population = "".join(population.split())
		else:
			population_h = infobox.xpath("//table//tr/th/text()[contains(., 'Population')]/..")
			estimate = population_h[0].xpath("../../tr//div[contains(text(), 'estimate')]/../../td/text()")
			if estimate != []:
				population = estimate[0].replace(" ", "")
			else:
				t = population_h[0].xpath("../../tr//th[contains(text(), 'Total')]/../td/text()")#[0].replace(" ", "")#/../../text()")[0].replace(" ", "")
				if t != []:
					population = t[0].replace(" ", "")
				else:
					population = population_h[0].xpath("../../tr//th/div[contains(text(), 'census') or contains(text(), 'Census')]/../../td/text()")[0].replace(" ", "")


		area_h = infobox.xpath("//table//th/a[contains(text(), 'Area')]")
		if area_h == []:
			area_h = infobox.xpath("//table//th//text()[contains(., 'Area')]/..")
			total = area_h[0].xpath("../../tr/th[1]/div[contains(text(), 'Total')]")
			if total != []:
				area = total[0].xpath("../../td[1]/text()")[0]
			else:
				total = area_h[0].xpath("../../tr/th[1]//text()[contains(., 'Total')]/..")[0]
				area = total.xpath("../td[1]/text()")[0]#it was "../../td[1]/text()" but not working, i changedbut network has failed
		else:
			total = area_h[0].xpath("../../../tr/th[1]/div[(contains(text(), 'Land') or contains(text(), 'Total') or contains(text(), 'Including') or contains(text(), 'proper')) and position()=1]")[0]
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


		government_h = infobox.xpath("//table//tr/th//text()[contains(., 'Government')]/..")
		if government_h != []:
			government_words = government_h[0].xpath("./../../td//a/text()")
			if government_words == []:
				government_words = government_h[0].xpath(".//../td//a/text()")
			for word in government_words:
				if '[' in word:
					continue
				government += (word.replace(" ", "_") + "_")
			government = government[:-1]


		capital_h = infobox.xpath("//table//th[contains(text(), 'Capital')]")
		if capital_h != []:
			capital_lst = capital_h[0].xpath("./../td//text()")
			if '\n' in capital_lst:
				capital_lst.remove('\n')
			if ' ' in capital_lst:
				capital_lst.remove(' ')
			capital = capital_lst[0].replace(" ", "_")
			if 'None' in capital_lst[0].replace(" ", ""):
				capital = ""

		update_ontology(
			countries_ontology,
			cname, capital,
			president, pt_bdate,
			prime_minister, pm_bdate,
			government,
			population,
			area
		)
		if 'republic' in government:
			a += 1
		elif 'monarchy' in government:
			b += 1
		else:
			dd.append(government_words)
		print(cname, government)
	print(a, b, len(dd))
	countries_ontology.serialize(ontology_path, format="nt")




###############################
# Natural Language Processing
###############################

def parse_question(question):
	"""
	Accepts a question in the english language
	Returns a sparql query properly
	"""
	query = ""
	tokens = nltk.word_tokenize(question)
	tags = tokens.pos_tag(tokens)




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
		get_countries_info(united_natinos_url, argv[2])
	elif cmd == 'question':
		query = parse_question(argv[2])
		answer = get_answer(query)
		print(answer)
	else:
		print("Invalid Command")
		return


"""
if __name__ == '__main__':
	if len(sys.argv) != 3:
		print("Usage: {} <command> <argument>".format(sys.argv[0]))
	run(sys.argv)
"""

get_countries_info(united_natinos_url, "ontology.nt")