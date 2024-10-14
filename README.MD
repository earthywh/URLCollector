<h1 align="center">
  <img src="https://raw.githubusercontent.com/earthywh/URLCollector/refs/heads/main/37660b5a-db22-47ec-94aa-3680324ebb7b.jpg" alt="URLCollector" width="200px">
  <br>
</h1>

URLCollector collects URLS using GAU and Katana for a list of domains and stores them in a folder for further analysis for Bug Bounty Hunters and Security testers. It also collects all JS files and stores them in folder. 
It also runs jsluice on collected JS files and outputs secrets. 

Below Tools are required to be installed in system as pre-requisites.
1. Katana
2. GAU
3. Subfinder
4. JSLuice

<b>Usage </b>


<code>python3 urlscollect.py domains.txt</code>


The Output files are stored in a folder where urlscollect.py is saved. The folder name is the data + time when the tool is run 
