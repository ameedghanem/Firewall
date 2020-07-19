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
total_prime_ministers = set()

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
		if president not in total_presidents: # some presidents are actually presidents of more than one country!
			total_presidents.add(president)
			ontology.add((rdflib.URIRef(example_prefix+cname), president_r, rdflib.URIRef(example_prefix+president)))
	if prime_minister != "":
		if prime_minister not in total_prime_ministers: # some presidents are actually presidents of more than one country!
			total_prime_ministers.add(prime_minister)
			ontology.add((rdflib.URIRef(example_prefix+cname), prime_minister_r, rdflib.URIRef(example_prefix+prime_minister)))
	if pt_bdate != "":
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



def isNumber(s):
	"""
	Returns True iff s represents a vaaid value of area 
	"""
	for i in s:
		if (not (i.isdigit())) and i!=',' and i!='.' :
			return False

	return True



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
			if lst != []:
				prime_minister = lst[0].replace(" ", "_")
				prime_minister_link = prime_minister_h[0].xpath("../../../td//a/@href")[0]
				pm_bdate = get_charecter_info(wiki_prefix + prime_minister_link)


		population = infobox.xpath(".//tr[./th//text()='Population'][1]/following-sibling::tr[1]/td[1]//text()")
		if population == []:
			continue
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
			print ('area_h is empty')
			area_h = infobox.xpath("//table//th//text()[contains(., 'Area')]/..")
			total = area_h[0].xpath("../../tr/th[1]/div[contains(text(), 'Total')]")
			if total != []:
				area = total[0].xpath("../../td[1]/text()")[0]
			else:
				print ('total is empty')
				if(c== '/wiki/Channel_Islands'):
					total = infobox.xpath("//th[.//text()='Area']/../td//text()")
					area=total[0]
				else:
					total = area_h[0].xpath("../../tr/th[1]//text()[contains(., 'Total')]/..")[0]
					area = total.xpath("../td[1]/text()")[0]
		else:
			total = area_h[0].xpath("../../../tr/th[1]/div[(contains(text(), 'Land') or contains(text(), 'Total') or contains(text(), 'Including') or contains(text(), 'proper')) and position()=1]")[0]
			area = total.xpath("../../td[1]/text()")[0]
			if '$' in area:
				total = area_h[0].xpath("../../../tr//div[contains(./a/text(), 'Land')]")[0]
				area = total.xpath("../../td[1]/text()")[0]
		area = area.split()
		if 'km' in area:
			ind = area.index('km') - 1
			theNewArea = ''
			for i in area[ind]:
				if i.isdigit() or i==',' or i==".":
					theNewArea = theNewArea + i
			area = theNewArea + "_km2"
		elif (len(area)==1 and isNumber(area[0])):
			area = area[0] + "_km2"


		government_h = infobox.xpath("//table//tr/th[.//text()='Government']//text()/..")
		if government_h != []:
			government_words = government_h[0].xpath("./../../td//text()")
			if government_words == []:
				government_words = government_h[0].xpath(".//../td//text()")
			for word in government_words:
				if 'de facto' in word.lower():
					government_words.remove('\n')
					government_words = government_words[:government_words.index(word)]
					break
			invalid_words = ['[', ':', '\n', ' ']
			government_words = [word for word in government_words if word not in invalid_words and 'de jure' not in word and 'de facto' not in word]
			for word in government_words:
				if '[' in word:
					continue
				if '(' in word:
					break
				if word.endswith(' '):
					word = word.replace(' ', '')
				government += (word.replace(' ', '_') + "_")
			government = government[:-1]
			if ' ' in government:
				government = government.replace(' ', '')
			if '__' in government:
				government = government.replace("__", '_')
			if government.startswith('_'):
				government = government[1:]
			if 'undera' in government:
				government = government.replace("undera", "under_a")


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
		#if cname == 'United_States':
		print(cname)#, government)

	countries_ontology.serialize(ontology_path, format="nt")

#3 TODO: check if all ares in kn not miles, and 2nd, check if population doesnt have a km in the string


###############################
# Natural Language Processing
###############################

def extract_entity(question, word1, word2):
	"""
	extracts the entity whcih is actually the substring between the two given words
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
		entity = extract_entity(question, 'of ', ' born')
		r = extract_entity(question, 'the ', ' of ')
		relation = 'born' + '_%s' % (r)
	elif 'who' in question.lower():
		if 'president' in question.lower() or 'prime minister' in question.lower():
			relation = extract_entity(question, 'is the ', ' of ')
			entity = extract_entity(question, ' of ', '?')
		else:
			relation = 'president_prime_minister'
			entity = question[7:-1]
	else:
		relation = extract_entity(question, 'is the ', ' of ')
		entity = extract_entity(question, ' of ', '?')
	if entity == "" or relation == "":
		return None
	entity, relation = entity.replace(" ", "_"), relation.replace(" ", "_")
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
	if relation != 'president_prime_minister' and 'born_' not in relation:
		query = ["select ?f where { <http://example.org/%s> <http://example.org/%s> ?f } " % (entity, relation)]
	elif relation.startswith('born'):
		relation = relation.split('_', 1)[1]
		query = ["select ?bdate where { <http://example.org/%s> <http://example.org/%s> ?p. ?p <http://example.org/born> ?bdate }" % (entity, relation)]
	else:
		q1 = "select ?c where { ?c <http://example.org/president> <http://example.org/%s> }" % entity
		q2 = "select ?c where { ?c <http://example.org/prime_minister> <http://example.org/%s> }" % entity
		query = [q1, q2]
	return query



def evaluate_query(query):
	"""
	Accepts a sparql query
	Returns the query's answer according to the ontology we've created before
	"""
	lst = []
	answer = ""
	geo_ontology = rdflib.Graph()
	geo_ontology.parse("ontology.nt", format="nt")
	if query:
		if len(query) > 1:
			res1 = geo_ontology.query(query[0])
			if res1:
				lst = list(res1) + ['president']
			res2 = geo_ontology.query(query[1])
			if res2 and not res1:
				lst = list(res2) + ['prime_minister']
		else:
			lst = list(geo_ontology.query(query[0]))
	if lst:
		answer = [get_content(ans).replace("_", " ") for ans in lst if type(ans) != str] + [t for t in lst if type(t) == str]
	return answer



def answer_the_question(question):
	"""
	accepts aquestion in natural language (ENG)
	prints the proper answer
	"""
	entity, relation = parse_question(question)
	query = get_sparql_query(entity, relation)
	answer = evaluate_query(query)
	if answer:
		if 'who is' not in question.lower():
			answer = ', '.join(answer) if len(answer) > 1 else answer[0]
			print(answer)
		else:
			if relation == 'prime_minister' or relation == 'president':
				answer = ', '.join(answer) if len(answer) > 1 else answer[0]
				print(answer)
			elif relation == 'president_prime_minister':
				print("%s of %s" % (answer[1].title().replace('_', ' '), answer[0]))
			else:
				sys.exit()


def run_quesries():
	"""
	We've bulit this function in order to evaluate the quesries that we were asked to, in part a of the assignment
	"""
	get_string = lambda entity:	entity[0][19:].replace('_', ' ') if 'http' in entity[0] else entity[0]
	q1 = "select distinct ?pCount (COUNT(?p) as ?pCount) WHERE { ?p <http://example.org/government> ?g . FILTER (regex(lcase(str(?g)), 'monarchy'))}" # monarchy government
	q2 = "select distinct ?pCount (COUNT(?p) as ?pCount) WHERE { ?p <http://example.org/government> ?g . FILTER (regex(lcase(str(?g)), 'republic'))}" # republic government
	q3 = "select distinct ?pCount (COUNT(?p) as ?pCount) WHERE { ?p <http://example.org/prime_minister> ?c . }" # prime minister count
	q4 = "select distinct ?pCount (COUNT(?a) as ?pCount) WHERE { ?p <http://example.org/area> ?a . }" # countries count
	queries = [q1, q2, q3, q4]

	g = rdflib.Graph()
	g.parse("ontology.nt", format="nt")
	t = [list(g.query(q))[0] for q in queries]
	for r in t:
		print(get_string(r))



###############
# M  A  I  N
###############

def run_qa(argv):
	cmd = argv[1]
	if cmd == 'create' and argv[2].endswith(".nt"):
		get_countries_info(united_natinos_url, argv[2])
	elif cmd == 'question':
		answer_the_question(argv[2])
	else:
		print("Invalid Command")
		return


if __name__ == '__main__':
	run_quesries() # this was for runnign the 4 queries that we have been asked to run in part A
	#run_qa(sys.argv)
