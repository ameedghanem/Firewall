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

president_of = "President of "
prime_minister_of = "Prime minister of "

cname_index = 6
exampleOrg_index = 19
get_content = lambda entity: entity[0][exampleOrg_index:]
compose_uri = lambda s: example_prefix+s

total_presidents = set()
total_countries = set()

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
		if president not in total_presidents: # some presidents are actually presidents of more than one country!
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
	countries_ontology = rdflib.Graph()
	res = requests.get(url) 
	doc = lxml.html.fromstring(res.content)
	
	table = doc.xpath("//table[contains(@id, 'main')]")[0]
	countries = set(table.xpath(".//td[.//span/@class]//a[1][@title]/@href"))-{'/wiki/Kingdom_of_the_Netherlands'}#table.xpath("//td//span[1]/a[@title]/@href")

	president = prime_minister = population = area = government = capital = ""
	pt_bdate = pm_bdate = ""

	for c in countries:
		# some of these fields are empty in some of the countries. Thus, we need to initialize them in each iteration
		president = prime_minister = population = area = government = capital = ""
		pt_bdate = pm_bdate = ""

		page = requests.get(wiki_prefix + c)
		page_doc = lxml.html.fromstring(page.content)
		infobox = page_doc.xpath("//table[contains(@class, 'infobox')]")#[0]
		if infobox == []:
			continue
		infobox = infobox[0]

		cname = c[cname_index:]
		cname = urllib.parse.unquote(cname)
		#if cname in total_countries:
		#	continue

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


		"""population_h = infobox.xpath("//table//th//a[text()='Population']")
		if population_h != []:
			estimate = population_h[0].xpath("../../..//th//text()[contains(., 'estimate') or contains(., 'census') or contains(., 'Estimate')]/..")[0]
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
			if '%' in population:
				population = infobox.xpath("//table//tr[./th//a/text()='Population'][1]/following-sibling::tr[1]/th[contains(.//div/text(), 'estimate') or contains(.//div/text(), 'census') or contains(.//div/text(), 'Estimate')]/../td//text()")[0]
		else:
			population_h = infobox.xpath("//table//tr/th/text()[contains(., 'Population')]/..")
			estimate = population_h[0].xpath("../../tr//div[contains(text(), 'estimate')]/../../td/text()")
			if estimate != []:
				population = estimate[0].replace(" ", "")
			else:
				t = population_h[0].xpath("./../../tr//th[contains(text(), 'Total')]/../td/text()")
				if t != []:
					population = t[0].replace(" ", "")
					population = infobox.xpath("//table//tr[contains(./th/text()[1], 'Population')]/following-sibling::tr[1]/td[1]//text()")[0]
				else:
					population = population_h[0].xpath("../../tr//th/div[contains(text(), 'census') or contains(text(), 'Census')]/../../td/text()")[0].replace(" ", "")
		"""
		"""population = infobox.xpath("//table//tr[./th//text()='Population'][1]/following-sibling::tr[1]/th[contains(.//div//text(), 'estimate') or contains(.//div/text(), 'census') or contains(.//div/text(), 'Census') or contains(.//div/text(), 'Estimate') or contains(.//div/text(), 'Total')]/../td//text()")[0]
		population = ''.join(population.split(' '))
		if population.endswith('\n'):
			population = population[:-1]
		if '(' in population:
			population = population[:population.index('(')]"""

		"""population_h = infobox.xpath("//table//tr[./th//text()='Population'][1]/following-sibling::tr[1]/th[1]")
		print(infobox.xpath("//table//tr[.//th//text()='Population'][1]//th//text()"))#/following-sibling::tr[1]/th[1]//text()"))
		#print(population_h[0].xpath("./../td//text()"))
		population = population_h[0].xpath("./../td//text()")"""
		population = infobox.xpath(".//tr[./th//text()='Population'][1]/following-sibling::tr[1]/td[1]//text()")
		if population == []:
			continue
		#print(cname, infobox.xpath(".//tr/th/a[contains(text(), 'Population')]/text()"))#".//tr[./th/a/text()='Population']/th/a/text()"))
		if '\n' in population:
			population.remove('\n')
		if 'km' in population[0]:
			population = infobox.xpath(".//tr[./th//text()='Population'][1]/td[1]//text()")
		population = ''.join(population[0].split())
		if population.endswith('\n'):
			population = population[:-1]
		if '(' in population:
			population = population[:population.index('(')]


		area_h = infobox.xpath("//table//th/a[contains(text(), 'Area')]")
		if area_h == []:
			area_h = infobox.xpath("//table//th//text()[contains(., 'Area')]/..")
			total = area_h[0].xpath("../../tr/th[1]/div[contains(text(), 'Total')]")
			if total != []:
				#print(total[0].xpath("../../td[1]/text()"))
				area = total[0].xpath("../../td[1]/text()")[0]
			else:
				total = area_h[0].xpath("../../tr/th[1]//text()[contains(., 'Total')]/..")[0]
				#print(total.xpath("../td[1]/text()"))
				area = total.xpath("../td[1]/text()")[0]#it was "../../td[1]/text()" but not working, i changedbut network has failed
		else:
			total = area_h[0].xpath("../../../tr/th[1]/div[(contains(text(), 'Land') or contains(text(), 'Total') or contains(text(), 'Including') or contains(text(), 'proper')) and position()=1]")[0]
			#print(179, total.xpath("../../td[1]/text()"))
			area = total.xpath("../../td[1]/text()")[0]
			if '$' in area:
				total = area_h[0].xpath("../../../tr//div[contains(./a/text(), 'Land')]")[0]
				#print(total.xpath("../../td[1]/text()"))
				area = total.xpath("../../td[1]/text()")[0]
		area = ' '.join(area.split())
		if ' ' in area:
			ind = area.index(' ')
			area = area[:ind] + "_km2"
		elif not area.endswith("km2"):
			area = area + "_km2"


		government_h = infobox.xpath("//table//tr/th[.//text()='Government']//text()/..")
		if government_h != []:
			government_words = government_h[0].xpath("./../../td//text()")
			if government_words == []:
				government_words = government_h[0].xpath(".//../td//text()")
			for word in government_words:
				if 'de facto' in word:
					government_words.remove('\n')
					government_words = government_words[:government_words.index(word)]
					break
			invalid_words = ['[', ':', '\n', ' ']
			government_words = [word for word in government_words if word not in invalid_words and 'de jure' not in word and 'de facto' not in word]
			for word in government_words:
				if '[' in word:
					continue
				if word.endswith(' '):
					word = word.replace(' ', '')
				government += (word.replace(' ', '_') + "_")
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

		#total_countries.add(cname)	
		update_ontology(
			countries_ontology,
			cname, capital,
			president, pt_bdate,
			prime_minister, pm_bdate,
			government,
			population,
			area
		)
		if 'republic' not in government and 'monarchy' not in government:
			print(cname)
		#print(cname, government)

	countries_ontology.serialize(ontology_path, format="nt")

#3 TODO: check if all ares in kn not miles, and 2nd, check if population doesnt have a km in the string


###############################
# Natural Language Processing
###############################

def extract_entity(question, word1, word2):
	"""
	extracts the emtity whcih is actually the substring between the two given words
	"""
	ind1 = question.lower().index(word1.lower()) + len(word1)
	ind2 = question.lower().index(word2.lower())
	return question[ind1:ind2]



def parse_question(question):
	"""
	parses the question returns the relevant entity and relation
	"""
	entity = relation = ""
	if 'born' in question.lower(): # the pattern of when was <entitiy> born
		entity = extract_entity(question, 'when ', 'was')
		relation = 'born'
	elif 'who' in question.lower():
		if 'president' in question.lower() or 'prime minister' in question.lower():
			relation = extract_entity(question, 'is the ', ' of ')
			entity = extract_entity(question, ' of ', '?')
		else:
			relation = 'president_prime_minister'
			entity = question[7:]
	else:
		relation = extract_entity(question, 'is the ', ' of ')
		entity = extract_entity(question, ' of ', '?')
	if entity == "" or relation == "":
		return None
	entity, relation = entity.replace(" ", "_"), relation.(" ", "_")
	if entity.endswith('_'):
		entity = entity[:-1]
	if relation.endswith('_'):
		relation = relation[:-1]
	return entity, relation



def get_sparql_query(entity, relation):
	"""
	accepts an entity and a relation and bulids a proper sparql query
	"""
	query = None
	if relation != 'president_prime_minister':
		query = "select ?c where { {1} {2} ?c } ".format(entity, relation)
	else:
		query = "select ?p, ?c where { ?p <http://example.org/president> ?c or ?p <http://example.ord/prime_minister> ?c}"
	return query



def evaluate_query(query):
	"""
	Accepts a sparql query
	Returns the query's answer according to the ontology we've created before
	"""
	geo_ontology = rdflib.Graph()
	geo_ontology.parse("ontology.nt", format="nt")
	lst = list(geo_ontology.query(query))
	answer = [get_content(ans).replace("_", " ") for ans in lst]
	return answer




def print_answer(answer, identity):
	"""
	printing the answer of properly
	"""
	if identity:
		print(president_of if identity=='president' else prime_minister_of)
		if len(answer) == 1:
			print(answer[0])
		else:
			for ans in answer:
				print(ans, ', ')
		return
	else:
		print(answer[0])



def answer_the_question(question):
	"""
	accepts aquestion in natural language (ENG)
	prints the proper answer
	"""
	entity, relation = parse_question(question)
	query = get_sparql_query(entity, relation)
	answer = evaluate_query(query)
	answer = '_'.join(answer) if len(answer) > 1 else answer[0]
	if 'who is' not in question.lower():
		print(answer)
	else:
		if relation == 'prime_minister':
			print("Prime minister of %s" % answer)
		elif relation == 'president':
			print("President of %s" % answer)
		else:
			print("")




###############
# M  A  I  N
###############

def run_qa(argv):
	cmd = argv[1]
	if cmd == 'create' and argv[2].endswith(".nt"):
		get_countries_info(united_natinos_url, argv[2])
	elif cmd == 'question':
		answer_the_question(argv[2])
		print(answer)
	else:
		print("Invalid Command")
		return


if __name__ == '__main__':
	run_qa(sys.argv)


get_countries_info(united_natinos_url, "ontology.nt")