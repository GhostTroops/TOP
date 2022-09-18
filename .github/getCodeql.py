#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import requests,json

n = 2022
xOut = []

def log(s):
    global xOut
    xOut+=[s]

cmpfun = lambda x:x["stargazers_count"]
for i in range(0,10):
    log("## Codeql")
    r = requests.get('https://api.github.com/search/repositories?l=CodeQL&o=desc&q=codeql&s=stars&type=Repositories')
    a = json.loads(r.text)
    if "items" in a:
        a = a["items"]
        log("|star|name|url|des|")
        log("|---|---|---|---|")
        a.sort(key=cmpfun,reverse=True)
        # a = x1
        for x in a:
            try:
            # print(json.dumps(x))
            # if x:
                szDes = x["description"]
                if None == szDes:
                    szDes = ""
                log("|" +"|".join([str(x["stargazers_count"]),x["name"],x["html_url"],szDes])+"|")
            except Exception as e:
                print(e)
                pass
                # print(x)
            # break
    break
if 0 < len(xOut):
    f11 = open("Top_Codqql1.md","wb")
    f11.write("\n".join(xOut).encode('utf-8'))
    f11.close()
# ?q=user%3Ahktalent&type=Repositories')
