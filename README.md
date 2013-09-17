scrape
======

scrape is an application for scraping web sites and rss feeds, performing actions and/or notifications
whenever search actions succeed


BACKGROUND:

scrape consists of three primary components:

  ./scrape.py - The script orchestrating the page scraping. scrape.py oversees a collection of scraping
      agents (one per site that you would like to monitor). The scraping agents access pages at random
      intervals and perform searches (actions) on the results. When an action succeeds (a certain term
      is found to be present, absent, etc.), scrape.py can spawn an appropriate process and/or send a
      notification email. The behavior of each agent is managed in an initialization file.

  ./scrape.ini - An initialization file for the scraping program itself, containing settings for email
      notifications and for specifying the location of the agent files. See scrape.ini for more details
      on the program's settings.

  ./agents/* - A collection of initialization files for the scraping agents. See the sample agent
      initialization file for more details on scraping agents' settings.


GETTING STARTED:

Before running scrape.py, be sure to edit scrape.ini and to edit / create agent files appropriate to
the task that you would like to accomplish. The example agent file (gaming.ini) creates an agent that
scrapes Amazon.com every 250 seconds (on average) and checks to see if the PS4 is in stock. If it is,
the agent attempts to run vlc.exe to play a notification sound, and then attempts to send an email
notification.

The first time that you run scrape.py, you will be prompted to set up a passkey with which to encrypt
your email password. Your email password will then be encrypted on the hard drive and decrypted
whenever email notifications need to be sent.

After setting up the encrypted password file (or upon running the scrape.py script in the future), you
will be asked for your passkey once again. This will be used to unlock the email password the next time
the scraper attempts to send an email.

So get configured, send your agents out into the wilderness and enjoy!
