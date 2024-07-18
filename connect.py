
#-*- coding: utf-8 -*-
import time
import telnetlib

class Sw_telnet:
    def __init__(self,host,timeout,login,password,sw_command):
        self.host = host
        self.timeout = int(timeout)
        self.login = login
        self.password = password
        self.sw_command = sw_command
        self.output = ''
        self.__sw()
        
    def to_bytes(self,line):
        return f"{line}\r\n".encode("utf-8")

    def __sw(self):
        with telnetlib.Telnet(self.host) as tn:    
          
            tn.write(self.to_bytes(self.login))
            tn.write(self.to_bytes(self.password))
          
            for command in self.sw_command:
                tn.write(self.to_bytes(command))
                time.sleep(self.timeout)
            self.output = tn.read_very_eager().decode("utf-8")
            time.sleep(self.timeout)
            tn.close()

    def get_result(self):
        return self.output      
          