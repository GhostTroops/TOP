#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import requests,json

n = 2023
xY = ["# Table of Contents"]
xOut = []

def log(s):
    global xOut
    xOut+=[s]

aA = []
cmpfun = lambda x:x["stargazers_count"]
for i in range(0,10):
    log("## " + str(n))
    r = requests.get('https://api.github.com/search/repositories?o=desc&q=CVE-'+str(n)+'-&s=updated&type=Repositories')
    a = json.loads(r.text)
    if "items" in a:
        a = a["items"]
        xY += ["* [" + str(n) + " year top total " + str(len(a)) + "](#"+ str(n) +")"]
        log("|star|updated_at|name|url|des|")
        log("|---|---|---|---|---|")
        #a.sort(key=cmpfun,reverse=True)
        aA += a
        # a = x1
        for x in a:
            try:
            # print(json.dumps(x))
            # if x:
                szDes = x["description"]
                if None == szDes:
                    szDes = ""
                log("|" +"|".join([str(x["stargazers_count"]),x["updated_at"],x["name"],x["html_url"],szDes])+"|")
            except Exception as e:
                pass
                # print(x)
            # break
        n = n - 1
if 1 < len(xY):
    print("\n".join(xY))
    print("\n".join(xOut))

class Info():
    def __init__(self,description,stargazers_count,name,html_url):
        self.description = description
        self.stargazers_count = stargazers_count
        self.name = name
        self.html_url = html_url
    def __hash__(self):
        return hash(self.name + self.html_url)
    def __eq__(self, other):
        return self.html_url == other.html_url and self.name == other.name

xY = []
# 也许这里去重会有问题
temp = []
for x in aA:
    temp.append(Info(x["description"],x["stargazers_count"],x["name"],x["html_url"]))
aA = list(set(temp))
cmpfun = lambda x:x.stargazers_count
# aA.sort(key=cmpfun,reverse=True)
xY += ["# Top"]
xY += ["|star|updated_at|name|url|des|"]
xY += ["|---|---|---|---|---|"]
for x in aA:
    try:
        szDes = x.description
        if None == szDes:
            szDes = ""
        xY += ["|" +"|".join([str(x.stargazers_count),x["updated_at"],x.name,x.html_url,szDes])+"|"]
    except Exception as e:
        pass
if 0 < len(aA):
    f11 = open("Top.md","wb")
    f11.write("\n".join(xY).encode('utf-8'))
    f11.close()
# ?q=user%3Ahktalent&type=Repositories')
