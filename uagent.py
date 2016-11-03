import os, sys
import shutil
import socket
import ConfigParser
import subprocess


class UAgentConfig:
    def __init__(self, cfg):
        self.analyzer_path = 'analyzer.py'
        self.conf_path = cfg
        self.ip = None
        self.port = None


    def BuildConfig(self, section, conf_dict):
        '''
            reconfigure analysis.conf 
        '''
        """
        # check
        if not os.path.exists(self.conf_path):
            print ('[-] error, not found config file!')
            return False
        """
        # parser
        config = ConfigParser.ConfigParser(allow_no_value=True)
        config.add_section(section)

        """
        # read conf
        config.read(self.conf_path)
        for section in config.sections():
            for name, raw_value in config.items(section):
                if name.strip() == 'ip':
                    self.ip = raw_value.strip()
                elif name.strip() == 'port':
                    self.port = raw_value.strip()
                else:
                    setattr(self, name.strip(), raw_value.strip())
        """

        # set key and value
        for key in conf_dict:
            if key.strip() == 'ip':
                self.ip = conf_dict[key]
            elif key.strip() == 'port':
                self.port = conf_dict[key]
            else:
                setattr(self, key, conf_dict[key])
            config.set(section, key, conf_dict[key])

        # output conf file
        config.write(open(self.conf_path, 'w'))

        print ('[+] build config is ok.')
        return True


    def ShowPipeLog(self):
        '''
            print analysis log
        '''
        if not self.ip and not self.port:
            print ('[-] parser log error.')
            return False

        ip_port = (self.ip, int(self.port))
        sk = socket.socket()
        sk.bind(ip_port)
        sk.listen(2)
        
        try:
            print 'server waiting %s:%s...'%(self.ip, self.port)
            conn,addr = sk.accept()
            while True:
                conn.recv(4096)
            conn.close()
        except KeyboardInterrupt as e:
            print ('[+] show log is complete')
        except Exception as e:
            print e

        return True


    def run(self, sample, section, conf_dict):
        '''
            start
        '''
        print ('[+] parser config')
        if not self.BuildConfig(section, conf_dict):
            print "[-] build error."
            return

        analyzer = os.path.join(os.getcwd(), self.analyzer_path)
        if not os.path.exists(analyzer):
            print "[-] analyzer is not found! "

        target = os.path.join(os.environ["TEMP"], self.file_name)
        shutil.copyfile(sample, target)

        # start analyzer.py
        proc = subprocess.Popen([sys.executable, analyzer],
                        cwd=os.path.dirname(analyzer))
        
        print ('[+] start show log')
        self.ShowPipeLog()


if __name__ == '__main__':
    print ('[+] start uagent:')

    if len(sys.argv) < 2:
        print 'userpage:'
        print '    uagent.py  filepath'
    elif not os.path.exists(sys.argv[1]):
        print 'parameter error: file is not exist!'
    else:
        # analysis program
        sample = sys.argv[1]

        # default config
        parameter = {'category':'file',         # task type
                     'target':'',               # it's file ,this is null, else url
                     'clock':'20161031T10:29:48',# set system time
                     'file_type':'PE32 executable (GUI) Intel 80386, for MS Windows',
                     'file_name':os.path.basename(sample),
                     'package':'',              # null
                     'options':'route=none,procmemdump=yes,apk_entry=:',
                     'port':2201,               # host port
                     'terminate_processes':False,
                     'enforce_timeout':False,
                     'timeout':120,             # analysis timeout
                     'ip': '127.0.0.1',         # host ip
                     'pe_exports':'',           
                     'id':1}                    # task id

        UAgentConfig("analysis.conf").run(sample, "analysis", parameter)
