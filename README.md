# sucho-data-rescue-scrape
Python Jupyter Notebook for Scraping and Internet Archive Preservation

This has some slapped together (very kludged) Python scripts for crawling and scraping Websites to automatically discover links
and links to image files so these links can be submitted for archiving with the Internet Archive's Wayback machine.

This is very much a work in progress as I'm still a novice with Jupyter Notebooks, and I'm totally new to the world of Web crawlers
and Web archiving.

## NOTE
  1) This requires that you have an Internet Archive account with Amazon S3 like credentials. You'll need to obtain an `INTERNET_ARCHIVE_ACCESS_KEY` and a `INTERNET_ARCHIVE_SECRET_KEY`. Copy the `secrets_change.json` file and save as `secrets.json` and paste in your Internet Archive credentials into the appropriate place in the `secrets.json` file and save.
  2) TODO add stuff I'm forgetting


## NOTE
I run this using a Windows 11 machine using an Ubuntu 20 subsystem on Linux. 
I found it easier to install various Python packages in Linux world rather than on Windows directly. 
However to start Jupyter Notebooks in the Linux subsystem, I needed a special invocation as follows:
```
jupyter notebook --ip=127.0.0.1 --port=8888
