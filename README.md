# Github-Hunter
This tool is for sensitive information searching on Github.
## Requirements
Python 3.x <br>
## OS Support
Linux,MacOS,Windows<br>
## Installation
1.`git clone https://github.com/Hell0W0rld0/Github-Hunter.git`<br>
Notice:Github Hunter only supports Python3.x, if you are using Python2.x,do some tests before use it<br>
2.`cd Github-Hunter`<br>
3.`pip install virtualenv`<br>
4.`virtualenv --python=/usr/local/bin/python3 env`<br>
5.`source venv/bin/activate`<br>
6.`pip install -r requirements`<br>
## Settings
Befor use it,you must change parameters in `info.ini.example`,then change filename(just delete `.example`)
### Example
`[KEYWORD]`<br>
`keyword = your main keyword here`<br>
<br>
`[EMAIL]`<br>
`host = Email server`<br>
`user = Email User`<br>
`password = Email password`<br>
<br>
`[SENDER]`<br>
`sender = The email sender`<br>
<br>
`[RECEIVER]`<br>
`receiver1 = Email receiver No.1`<br>
`receiver2 = Email receiver No.2`<br>
<br>
`[Github]`<br>
`user = Github Username`<br>
`password = Github Password`<br>
<br>
`[PAYLOADS]`<br>
`p1 = Payload 1`<br>
`p2 = Payload 2`<br>
`p3 = Payload 3`<br>
`p4 = Payload 4`<br>
`p5 = Payload 5`<br>
`p6 = Payload 6`<br>
### Keyword and Payloads
The keyword is main keyword,such as your company name,email,etc.<br>
The payloads searching is based on main keyword's results.You can customize your payloads,the more you add, the more sensitive information it will find.
## Run
`python GithubHunter.py`<br>
You will receive a .csv file and emails when application complete.<br>
CSV file includes repositories' url、user、upload data、filename which are best match of main keyword.<br>
The emails will be send contain urls which certainly include sensitive information.
