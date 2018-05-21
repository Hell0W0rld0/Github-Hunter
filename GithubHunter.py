# -*- coding: utf-8 -*-

import requests
from lxml import etree
import csv
from tqdm import tqdm
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.header import Header
from email.utils import parseaddr,formataddr
from email import encoders
import configparser
from time import sleep

'''
工具名:GithubHunter
作者：Allen_Zhang
主要用途：本工具主要是查询Github中可能泄露的代码，用户名，密码，数据库信息，网络结构信息等
实现方法：通过登陆Github后，搜索关键词，然后呈现数据
'''

def login_github(username,password):#登陆Github
    #初始化参数
    login_url = 'https://github.com/login'
    session_url = 'https://github.com/session'
    try:
        #获取session
        s = requests.session()
        resp = s.get(login_url).text
        dom_tree = etree.HTML(resp)
        key = dom_tree.xpath('//input[@name="authenticity_token"]/@value')
        user_data = {
            'commit': 'Sign in',
            'utf8': '✓',
            'authenticity_token': key,
            'login': username,
            'password': password
        }
        #发送数据并登陆
        s.post(session_url,data=user_data)
        s.get('https://github.com/settings/profile')
        return s
    except:
        print('产生异常，请检查网络设置及用户名和密码')

def hunter(gUser,gPass,keyword,payloads):#根据关键词获取想要查询的内容

    print('''\033[1;34;0m     #####                                  #     #                                   
    #     # # ##### #    # #    # #####     #     # #    # #    # ##### ###### #####  
    #       #   #   #    # #    # #    #    #     # #    # ##   #   #   #      #    # 
    #  #### #   #   ###### #    # #####     ####### #    # # #  #   #   #####  #    # 
    #     # #   #   #    # #    # #    #    #     # #    # #  # #   #   #      #####  
    #     # #   #   #    # #    # #    #    #     # #    # #   ##   #   #      #   #  
     #####  #   #   #    #  ####  #####     #     #  ####  #    #   #   ###### #    # \r\n\r\n\033[0m''')

    global sensitive_list
    global tUrls
    sensitive_list = []
    tUrls = []
    try:
        #创建表格文件
        csv_file = open('leak.csv','w',encoding='utf-8',newline='')
        writer = csv.writer(csv_file)
        writer.writerow(['URL','Username','Upload Time','Filename'])

        #代码搜索
        s = login_github(gUser,gPass)
        print('登陆成功，正在检索泄露信息.......')
        sleep(1)
        for page in tqdm(range(1,6)):
            search_code = 'https://github.com/search?p='+ str(page) + '&q=' + keyword + '&type=Code'
            resp = s.get(search_code)
            results_code = resp.text
            dom_tree_code = etree.HTML(results_code)
            Urls = dom_tree_code.xpath('//div[@class="d-inline-block col-10"]/a[2]/@href')
            users = dom_tree_code.xpath('//a[@class="text-bold"]/text()')
            datetime = dom_tree_code.xpath('//relative-time/text()')
            filename = dom_tree_code.xpath('//div[@class="d-inline-block col-10"]/a[2]/text()')
            for i in range(len(Urls)):
                for Url in Urls:
                    Url = 'https://github.com'+ Url
                    tUrls.append(Url)
                writer.writerow([tUrls[i],users[i],datetime[i],filename[i]])
            for raw_url in Urls:
                url = 'https://raw.githubusercontent.com' + raw_url.replace('/blob', '')
                code = requests.get(url).text
                for payload in payloads:
                    if payload in code:
                        leak_url = '命中的Payload为：'+payload+'\r\n'+'https://github.com'+ raw_url + '\r\n\r\n' + '代码如下：\r\n' + code + '\r\n\r\n' 
                        sensitive_list.append(leak_url)

        csv_file.close()

        return sensitive_list

    except Exception as e:
        print(e)


def send_mail(host,username,password,sender,receivers):#自动发送邮件

    def _format_addr(s):
        name,addr = parseaddr(s)
        return formataddr((Header(name,'utf-8').encode(),addr))

    message = MIMEMultipart()
    message['From'] = _format_addr('小雨点安全监控<%s>' % sender)
    message['To'] = ','.join(receivers)
    subject = 'Github信息泄露报表'
    message['Subject'] = Header(subject,'utf-8').encode()

    message.attach(MIMEText('Dear all \r\n\r\n 经过检查，暂时未发现敏感的信息泄露。附件是可能存在Github代码泄露的仓库报表，请查收！','plain','utf-8'))

    with open('leak.csv','rb') as f:
        m = MIMEBase('excel','csv',filename='leak.csv')
        m.add_header('Content-Disposition','attachment',filename='leak.csv')
        m.add_header('Content-ID','<0>')
        m.add_header('X-Attachment-Id','0')
        m.set_payload(f.read())
        encoders.encode_base64(m)
        message.attach(m)

    try:
        server = smtplib.SMTP()
        server.connect(host,25)
        server.login(username,password)
        server.sendmail(sender,receivers,message.as_string())
        print("邮件发送成功！")
    except Exception as err:
        print(err)

    server.quit()

def send_warning(host,username,password,sender,receivers,content):

    def _format_addr(s):
        name,addr = parseaddr(s)
        return formataddr((Header(name,'utf-8').encode(),addr))

    msg = MIMEMultipart()
    msg['From'] = _format_addr('小雨点安全监控<%s>' % sender)
    msg['To'] = ','.join(receivers)
    Subject = 'Github敏感信息泄露通知'
    msg['Subject'] = Header(Subject,'utf-8').encode()
    msg.attach(MIMEText('Dear all \r\n\r\n请注意，怀疑Github上已经上传敏感信息！以下是可能存在敏感信息的仓库！\r\n\r\n'+content+'\r\n\r\n'))

    with open('leak.csv','rb') as f:
        m = MIMEBase('excel','csv',filename='leak.csv')
        m.add_header('Content-Disposition','attachment',filename='leak.csv')
        m.add_header('Content-ID','<0>')
        m.add_header('X-Attachment-Id','0')
        m.set_payload(f.read())
        encoders.encode_base64(m)
        msg.attach(m)
    try:
        server = smtplib.SMTP(host,25)
        server.login(username,password)
        server.sendmail(sender,receivers,msg.as_string())
        print('邮件发送成功！')
    except Exception as err:
        print(err)

    server.quit()





def main():
    config = configparser.ConfigParser()
    config.read('info.ini')
    g_User = config['Github']['user']
    g_Pass = config['Github']['password']
    host = config['EMAIL']['host']
    m_User = config['EMAIL']['user']
    m_Pass = config['EMAIL']['password']
    m_sender = config['SENDER']['sender']
    receivers = []
    for k in config['RECEIVER']:
        receivers.append(config['RECEIVER'][k])

    keyword = config['KEYWORD']['keyword']
    payloads = []
    for key in config['PAYLOADS']:
        payloads.append(config['PAYLOADS'][key])
    sensitive_list = hunter(g_User,g_Pass,keyword,payloads)
    if sensitive_list:
        print('\033[1;31;0m警告：找到敏感信息！\r\n\033[0m')
        print('开始发送告警邮件......')
        content = ''.join(sensitive_list)
        send_warning(host,m_User,m_Pass,m_sender,receivers,content)
    else:
        print('恭喜：未找到敏感信息！\r\n')
        print('所有检查已完成，已生成报表！\r\n')
        print('开始发送报表......\r\n')
        send_mail(host,m_User,m_Pass,m_sender,receivers)


if __name__ == '__main__':
    main()
