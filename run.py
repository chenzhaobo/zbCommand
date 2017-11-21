#!/usr/bin/python
#!encoding: utf-8

import os
import sys
import stat
import pexpect
import logging
def _setup_logging():
    """ Initialize logger. """
    # create logger with 'spam_application'
    logger = logging.getLogger('zbCommand')
    logger.setLevel(logging.DEBUG)
    # create file handler which logs even debug messages
    fh = logging.FileHandler('zbCommand.log')
    fh.setLevel(logging.DEBUG)
    # create console handler with a higher log level
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    # create formatter and add it to the handlers
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    # add the handlers to the logger
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger

log =  _setup_logging()
# 读取文件配置, 获取服务器IP\名称\用户名\密码

class Server_config(object):
    '''
    读取csv文件  文件格式 host_name, ip, login_user, passwd
    '''
    def __init__(self, config_file):
        self._config_file =  config_file
        self.data =  []
        self.read_file()


    def read_file(self):
        with open(self._config_file, 'r') as rf:
            for i in rf.readlines():
                self.data.append(i.strip().split(','))


class Server(object):
    def __init__(self, _server = []):
        self._servers =  _server
        self.__server_index =  0

    def servers(self):
        for server in self._servers:
            self.next_server()
            yield self

    def next_server(self):
        self.__do()
        self.__server_index += 1

    def __do(self):
        s =  self._servers[self.__server_index]
        self.host_name =  s[0]
        self.IP = s[1]
        self.login_user = s[2]
        self.passwd = s[3]


# 将本地文件上传到服务器 ---scp命令
class Scp(object):

    def __init__(self, server, local_file):
        self.des_login_name =  server.login_user
        self.des_ip = server.IP
        self.des_passwd =  server.passwd
        self.des_path =  r'/root/'
        self.local_file = local_file

        self.x()


    def x(self):
        command = "scp {local_file} {severA}@{ip}:{des_path}".format(
            local_file = self.local_file, severA = self.des_login_name,
            ip = self.des_ip, des_path = self.des_path)
        log.info('scp command:' + command)
        child = pexpect.spawn(command)
        try:
            child.expect("password:")
            child.sendline(self.des_passwd)
        except Exception as e:
            log.error('expect passwd error, try not use passwd!')
            #log.error('error:{}'.format(e))
        finally:
            child.interact()



# 服务器执行命令
class SSH(object):

    def __init__(self, server):

        self.des_login_user = server.login_user
        self.des_ip =  server.IP
        self.des_passwd =  server.passwd
        self.cmd =  ''


    def excute_cmd(self, cmd):
        command = 'ssh {user}@{ip} "{cmd}"'.format (user = self.des_login_user,
                                                    ip = self.des_ip, cmd = cmd)
        #command = 'ssh {user}@{ip} '.format (user = self.des_login_user,ip = self.des_ip, )
        ssh = pexpect.spawn(command)
        try:
            i = ssh.expect(['password:', 'continue connecting (yes/no)?'], timeout=5)
            print('--------------------', i)
            if i == 0 :
                ssh.sendline(passwd)
            elif i == 1:
                ssh.sendline('yes\n')
                ssh.expect('password: ')
                ssh.sendline(passwd)


        except pexpect.EOF as e:
            log.error( "ssh connect EOF \n{}\n\n".format(e))
        except pexpect.TIMEOUT as e:
            log.error( "ssh connect TIMEOUT \n{}\n\n".format(e))
        except Exception as e:
            log.error( "ssh connect Unknown error\n {}\n\n".format(e))

        self.ssh = ssh

        return ssh.before

    def date(self):

        return self.excute_cmd('date')


    def cat(self,path ):

        return self.excute_cmd('cat {}'.format(path))



    def close(self):
        self.ssh.close()



if __name__ == '__main__' :
    config_file =  'config.csv'
    data =  Server_config(config_file).data
    server =  Server(data)
    local_file = r'/home/czb/kill.py'  # 绝对路径
    for i in server.servers():
        print(i.host_name)
        Scp(i, local_file)
        ssh = SSH(i)

        log.info('---------- :{}'.format(ssh.date()))
        log.info('-----------:{}'.format(ssh.cat('/root/kill.py')))
        ssh.close()
        exit()
