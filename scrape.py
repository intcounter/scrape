# This program checks webpages or RSS feeds for changes or for the occurrence
# / non-occurence of certain search terms and then runs processes / sends email
# notifications whenever appropriate changes are observed. Includes a class
# for handling encryption so that email passwords are never stored in plain
# text.
import glob, random, time, urllib2, subprocess, hashlib, os, struct, smtplib
import string, feedparser, getpass, winsound
from Crypto.Cipher import AES


class INIFile:
	# This class processes an .ini file into a dictionary of keys and values.
	def __init__(self,filePath):
		# The following field will contain the dictionary that we seek:
		self.config = {}
		configFile = open(filePath,'r')
		info = configFile.readlines()
		for i in info:
			colon = i.find(':')
			# Only lines containing a colon are processed:
			if (colon >= 0):
				key = i[:i.find(':')]
				data = i[i.find(':')+2:len(i)-1]
				if (key in self.config):
					self.config[key] += [data]
				else:
					self.config[key] = [data]
		configFile.close()

class Control:
	# The control object orchestrates a group of agents, each of which
	# periodically scrapes a website or rss feed.
	def __init__(self,config):
		self.toAddress = config['toAddress'][0] # Notifications sent here
		self.userAgent = config['userAgent'][0] # Useragent for http ident.
		fullName = config['fullName'][0]
		fromAddress = config['fromAddress'][0]
		server = config['smtpServer'][0]
		port = int(config['smtpPort'][0])
		emailFilename = config['emailFilename'][0]
		# The passwd feild contains a passkey for unlocking the email password
		# encrypted within the file corresponding to emailFilename:
		if ('passwd' in config):
			passwd = config['passwd'][0]
		else:
			passwd = getpass.getpass("Please enter your email passkey (no echo): ")
		# The self.writer field is a tool for composing and sending emails:
		self.writer = EmailAuthor(fullName,fromAddress,emailFilename,passwd,
		                          server,port)
		self.agents = [] # A list of the agents that will be scraping
		files = glob.glob(config['configDir'][0] + '*')
		for f in files:
			iniAgent = INIFile(f)
			if (iniAgent.config['type'][0] == 'HTML'):
				self.agents += [HTMLAgent(iniAgent.config)]
			elif (iniAgent.config['type'][0] == 'RSS'):
				self.agents += [RSSAgent(iniAgent.config)]
		self.sortAgents()
	# The sortAgents method sorts the list of agents by time to next scraping:
	def sortAgents(self):
		self.agents.sort(key=lambda x: x.currWait, reverse=True)
	# The nextAgent method activates the next agent for scraping and action:
	def nextAgent(self):
		a = self.agents.pop()
		Control.timePrint("Waiting for " + str(a.currWait)
		                  + " seconds. Next up is " + a.name)
		time.sleep(a.currWait)
		Control.timePrint(a.name + " is now scraping.")
		a.scrape(self.userAgent)
		if (a.scrapeSuccess):
			a.retrynum = 0
			for action in a.actions:
				if (action.complete == False or a.neverComplete):
				    action.act(a.currContent,a.prevContent,a.name,self.writer,
				               self.toAddress)
		else:
			a.retrynum += 1
			Control.timePrint(a.name +  " will retry its scrape "
			                  + str(a.retries - a.retrynum + 1) + " time(s)")
		self.decTime(a.currWait)
		complete = a.actionsComplete()
		withinRetries = (a.retrynum <= a.retries)
		if (not complete and withinRetries):
			a.currWait = a.newPause()
			self.agents += [a]
			self.sortAgents()
	# After an agent acts, decTime decreases the wait time for other agents:
	def decTime(self,pause):
		for a in self.agents:
			a.currWait -= pause
	# The timePrint static method is for printing information with a timestamp:
	@staticmethod
	def timePrint(strng):
		timestamp = time.strftime("%m/%d/%y [%I:%M:%S %p]: ")
		print timestamp + strng

class Agent:
	# An agent is an object for scraping webpages, rss feeds, etc. It keeps
	# track of time between scrapes, actions to perform, etc.
	def __init__(self,config):
		self.name = config['name'][0] # A name to identify the agent
		self.location = config['location'][0] # Location to scrape
		self.retries = int(config['retries'][0]) # Max number of retries
		self.retrynum = 0 # Number indicating the current retry agent is on
		self.avgWait = int(config['avgWait'][0]) # Average wait time for scrape
		self.currWait = self.newPause() # Current wait time until next scrape
		# The self.neverComplete bool indicates whether this agent never
		# completes (meaning it goes forever), or if it can end:
		self.neverComplete = (config['neverComplete'][0].lower() == 'true')
		self.currContent = "" # Content from the most recent scraping
		self.prevContent = "" # Content from the last scraping
		self.scrapeSuccess = False # Bool: did the most recent scrape succeed?
		self.actions = [] # A list of the actions to perform on each scraping
		for i in range(len(config['search'])):
			self.actions += [Action(config['search'][i],config['style'][i],
			                 config['process'][i],config['email'][i])]
	# The actual scraping method. This method is overloaded in subclasses
	# to allow for different styles of scraping (for HTML, RSS, etc.):
	def scrape(self,userString):
		return ()
	# This method uses a pseudorandom generator to create a gaussian random
	# wait time. This is so that scrapings seem random to a server:
	def newPause(self):
		if self.retrynum == 0:
			factor = 1
		else:
			factor = 1.36
		avg = self.avgWait*factor
		dev = int(round(self.avgWait*factor*0.23))
		randwait = int(round(random.gauss(avg,dev)))
		return min(max(randwait,avg-3*dev,1),avg+3*dev)
	# This method checks whether an agent has completed all of its
	# associated actions:
	def actionsComplete(self):
		complete = True
		for a in self.actions:
			complete = complete and a.complete
		if self.neverComplete:
			complete = False
		return complete

class HTMLAgent(Agent):
	# The HTMLAgent is an agent for scraping html webpages.
	def scrape(self,userString):
		header = {'User-Agent':userString}
		request = urllib2.Request(self.location,None,header)
		try:
			response = urllib2.urlopen(request)
			self.prevContent = self.currContent
			self.currContent = response.read()
			self.scrapeSuccess = True
		except Exception as e:
			winsound.PlaySound('SystemAsterisk', winsound.SND_ALIAS)
			self.scrapeSuccess = False
			Control.timePrint("An error occurred. Type: " + str(type(e))
			                  + "; Message: " + str(e))

class RSSAgent(Agent):
	# The RSSAgent is an agent for scraping rss feeds.
	def scrape(self,userString):
		try:
			response = feedparser.parse(self.location)
			self.prevContent = self.currContent
			titleU = response['items'][0]['title']
			title = titleU.encode('ascii','ignore')
			bodyTextU = response['items'][0]['content'][0]['value']
			bodyText = bodyTextU.encode('ascii','ignore')
			self.currContent = title + " " + bodyText
			self.scrapeSuccess = True
		except Exception as e:
			winsound.PlaySound('SystemAsterisk', winsound.SND_ALIAS)
			self.scrapeSuccess = False
			Control.timePrint("An error occurred. Type: " + str(type(e))
			                  + "; Message: " + str(e))

class Action:
	# An action is an object that takes care of a particular task to be
	# performed once a site has been scraped. It can search for a substring,
	# for a substring's absence, or for whether or not changes have occurred.
	def __init__(self,search,style,process,email):
		self.search = search # the search string to seek / avoid
		# self.style indicates the type of search, with three options:
		#   - 'SEEK' : the action succeeds when the search string is found
		#   - 'AVOID' : the action succeeds when the search string is absent
		#   - 'DIFF' : the action succeeds when the contents have changed
		self.style = style
		self.process = process # the process to run when action succeeds
		self.email = (email.lower() == 'true') # email notification on success?
		self.complete = False # has this action completed?
	# The act method carries out the action, including processes/emails/logs:
	def act(self,currContent,prevContent,agentName,emailWriter,toAddy):
		found = (currContent.find(self.search) > -1)
		new = (currContent != prevContent)
		seekHit = new and found and self.style == 'SEEK'
		avoidHit = new and not found and self.style == 'AVOID'
		diffHit = new and self.style == 'DIFF'
		if (seekHit or avoidHit or diffHit):
			si = subprocess.STARTUPINFO()
			si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
			si.wShowWindow = subprocess.SW_HIDE
			subprocess.Popen(self.process, startupinfo=si)
			self.complete = True
			Control.timePrint("A pattern has been matched for " + agentName
			                  + ", having search term: " + self.search)
			Control.timePrint("Content: " + currContent[:47])
			if (self.email):
				subj = "A pattern match occurred for the agent: " + agentName
				body = ("A pattern match has occurred, as initiated by agent "
				        + agentName + ". Specifically a pattern match was"
				        + "found looking for " + self.search + " in an "
				        + self.style + " search style. Good luck!")
				emailWriter.sendMail(toAddy,subj,body)
			try:
				logname = string.replace(agentName,' ','-').lower() + ".log"
				logfile = open(logname,'w')
				logfile.write(currContent)
				logfile.close()
				Control.timePrint("Current content has been written to the"
				                  + " log file.")
			except Exception as e:
				winsound.PlaySound('SystemAsterisk', winsound.SND_ALIAS)
				Control.timePrint("There was an error writing the current"
					              + " content to a log. Type: " + str(type(e))
					              + "; Message: " + str(e))

class AEStool:
	# AEStool creates a factory for encrypting and decrypting files
	def __init__(self,rounds=397,saltSize=32,keySize=32,blockSize=16):
		self.rounds = rounds # the number of rounds to hash the key
		self.saltSize = saltSize # the size of the salt for key hashing
		self.keySize = keySize # the size of the key
		self.blockSize = blockSize # the block size for encrpytion
	# Given a keypass named passwd and a random salt, keygen generates a key
	# of size self.keySize
	def keygen(self, passwd, salt):
		key = passwd
		for i in range(0,self.rounds):
			key = hashlib.sha256(key + salt).digest()
		key = key[:self.keySize]
		return key
	# encrypt takes the keypass and some plainText and encrypts it via AES.
	def encrypt(self, passwd, plainText):
		frontPadLength = random.randint(3,14)
		paddedText = " "*frontPadLength + ":" + plainText
		messageSize = long(len(paddedText))
		backPadLength = 16 - (messageSize % 16)
		paddedText = paddedText + " "*backPadLength
		salt = os.urandom(self.saltSize)
		key = self.keygen(passwd,salt)
		iv = os.urandom(self.blockSize)
		cipherType = AES.new(key,AES.MODE_CBC,iv)
		ciphertext = cipherType.encrypt(paddedText)
		ciphertext = ciphertext + struct.pack('Q', messageSize) + iv + salt
		return ciphertext
	# decrypt takes the keypass and some ciphertext and decrypts it via AES.
	def decrypt(self, passwd, ciphertext):
		startSize = (len(ciphertext) - struct.calcsize('Q') - self.blockSize
		             - self.saltSize)
		startIV = startSize + struct.calcsize('Q')
		startSalt = startIV + self.blockSize
		rawData = ciphertext[:startSize]
		messageSize = struct.unpack('Q',ciphertext[startSize:startIV])[0]
		iv = ciphertext[startIV:startSalt]
		salt = ciphertext[startSalt:]
		key = self.keygen(passwd,salt)
		cipherType = AES.new(key,AES.MODE_CBC,iv)
		paddedText = cipherType.decrypt(rawData)
		startMessage = paddedText.find(":")
		plainText = paddedText[startMessage+1:messageSize]
		return plainText

class EmailAuthor:
	# The EmailAuthor object is a factory for sending emails. It's initialized
	# with origin information, the location of an encrypted email password,
	# a keypass to unlock it, server and port info, etc.
	def __init__(self,fromName,fromAddy,passfile,passwd,server,port):
		self.fromAddy = fromAddy # email address for From line
		self.fromLine = "From: " + fromName + " <" + fromAddy + ">\n"
		self.passfile = passfile # filename for encrypted email password
		self.passwd = passwd # keypass for unlocking the email password
		self.server = server # smtp server
		self.port = port # smtp server port
	# sendMail sends an email to a given address with a given subject/message
	def sendMail(self,toAddy,subject,messageBody):
		message = self.fromLine
		message = message + "To: <" + toAddy + ">\n"
		message = message + "Subject: " + subject + "\n\n" + messageBody
		aesObj = AEStool()
		try:
			login = self.fromAddy
			cipherfile = open(self.passfile,'rb')
			ciphertext = cipherfile.read()
			cipherfile.close()
			password = aesObj.decrypt(self.passwd,ciphertext)
			smtpObj = smtplib.SMTP(self.server, self.port)
			smtpObj.ehlo()
			smtpObj.starttls()
			smtpObj.login(login,password)
			smtpObj.sendmail(self.fromAddy,[toAddy],message)
			smtpObj.quit()
			Control.timePrint("Notification sent to: " + toAddy)
		except Exception as e:
			winsound.PlaySound('SystemAsterisk', winsound.SND_ALIAS)
			Control.timePrint("There was an error in the email notification."
			                  + " Type: " + str(type(e)) + "; Message: "
			                  + str(e))

if __name__ == '__main__':
	ini = INIFile('./scrape.ini')
	pwfilename = ini.config['emailFilename'][0]
	if (glob.glob(pwfilename) == []):
		print "NOTE: You have not yet configured your email password file."
		aes = AEStool()
		key = getpass.getpass("Enter a passkey to lock your email password (no echo): ")
		plaintext = getpass.getpass("Enter your email password for encryption (no echo): ")
		pwfile = open(pwfilename,'wb')
		pwfile.write(aes.encrypt(key,plaintext))
		pwfile.close()
	c = Control(ini.config)
	while(c.agents != []):
		c.nextAgent()
	Control.timePrint("All agents have completed. Exiting program.")