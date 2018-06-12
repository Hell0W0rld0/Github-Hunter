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
import os
import sys

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
    global comp_list
    global tUrls
    sensitive_list = []
    comp_list = []
    tUrls = []
    try:
        #创建报告文件
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
                        leak_url = '命中的Payload为：'+payload+'\r\n'+'https://github.com'+ raw_url + '\r\n\r\n\r\n' + '代码如下：\r\n'+ code + '\r\n\r\n'
                        comp_url = payload + ' ' + 'https://github.com' + raw_url + '\n'
                        sensitive_list.append(leak_url)
                        comp_list.append(comp_url)

        csv_file.close()

        return sensitive_list,comp_list

    except Exception as e:
        print(e)


def send_warning(host,username,password,sender,receivers,message,content):

    def _format_addr(s):
        name,addr = parseaddr(s)
        return formataddr((Header(name,'utf-8').encode(),addr))

    msg = MIMEMultipart()
    msg['From'] = _format_addr('Github安全监控<%s>' % sender)
    msg['To'] = ','.join(receivers)
    Subject = 'Github敏感信息泄露通知'
    msg['Subject'] = Header(Subject,'utf-8').encode()
    msg.attach(MIMEText(message + '\r\n\r\n' + content + '\r\n\r\n'))

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



if __name__ == '__main__':
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
    sensitive_list,comp_list = hunter(g_User, g_Pass, keyword, payloads)
    NewAdd = []
    da = []
    if sensitive_list:
        if os.path.exists('data.csv'):
            csv_reader = csv.reader(open('data.csv',encoding='utf-8'))
            try:
                for row in csv_reader:
                    for i in row:
                        da.append(i)
                if sensitive_list == da:
                    print('没有新增泄露信息！')

                elif len(da) > len(sensitive_list):
                    for x in sensitive_list:
                        if x in da:
                            NewAdd.append(x)

                elif len(da) < len(sensitive_list):
                    for y in da:
                        if y in sensitive_list:
                            NewAdd.append(y)
                if NewAdd:
                    print('\033[1;31;0m警告：找到新增的敏感信息！\r\n\033[0m')
                    print('开始发送告警邮件......\r\n')
                    NewLine = open('data.csv','a+',encoding='utf-8',newline='')
                    write_line = csv.writer(NewLine)
                    for l in NewAdd:
                        write_line.writerow([l])
                    NewLine.close()
                    message = 'Dear all \r\n\r\n警告！以下链接是新增的敏感信息，请查收！'
                    NewContent = ''.join(NewAdd)
                    send_warning(host, m_User, m_Pass, m_sender, receivers, message,NewContent)
                else:
                    print('恭喜：未找到新增的敏感信息！\r\n')
                    print('所有检查已完成，已生成报表！\r\n')
                    print('开始发送报表......\r\n')
                    message = 'Dear all \r\n\r\n 未发现新增的敏感信息，附件是可能存在信息泄露的报告，请查收！'
                    content = ''
                    send_warning(host, m_User, m_Pass, m_sender, receivers, message, content)

            except Exception as e:
                print('发生错误，程序即将退出！\r\n' + e)
                sys.exit(1)
        else:
            print('数据表格不存在，正在创建......\r\n')
            data_file = open('data.csv','w',encoding='utf-8',newline='')
            write_data = csv.writer(data_file)
            for line in comp_list:
                write_data.writerow([line])
            data_file.close()
            print('\033[1;31;0m警告：找到敏感信息！\r\n\033[0m')
            print('开始发送告警邮件......\r\n')
            message = 'Dear all \r\n\r\n以下是发现的可能存在信息泄露的仓库，请查收！'
            content = ''.join(sensitive_list)
            send_warning(host, m_User, m_Pass, m_sender, receivers, message,content)
    else:
        print('恭喜：未找到敏感信息！\r\n')
        print('所有检查已完成，已生成报表！\r\n')
        print('开始发送报表......\r\n')
        message = 'Dear all \r\n\r\n 恭喜！未找到敏感信息，附件是报告内容，请查收！'
        content = ''
        send_warning(host, m_User, m_Pass, m_sender, receivers, message, content)