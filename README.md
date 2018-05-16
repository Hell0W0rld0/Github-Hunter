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
`[KEYWORD]`
`keyword = your main keyword here`

`[EMAIL]`
`host = Email server`
`user = Email User`
`password = Email password`

`[SENDER]`
`sender = The email sender`

`[RECEIVER]`
`receiver1 = Email receiver No.1`
`receiver2 = Email receiver No.2`

`[Github]`
`user = Github Username`
`password = Github Password`

`[PAYLOADS]`
`p1 = Payload 1`
`p2 = Payload 2`
`p3 = Payload 3`
`p4 = Payload 4`
`p5 = Payload 5`
`p6 = Payload 6`<br>
### Keyword and Payloads
The keyword is main keyword,such as your company name,email,etc.<br>
The payloads will be used to search sensitive informtion on results when main keyword searching finished.The Github Hunter will search main keyword on Github then use payloads to locate projects' urls which include sensitive information,it will send email to receivers at last.
