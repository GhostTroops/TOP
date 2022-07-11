cd $HOME/MyWork/TOP
py3 $HOME/MyWork/mybugbounty/getTop.py >end.md
cat he.md end.md ed.md >README.md
py3 $HOME/MyWork/mybugbounty/getCodeql.py
cat hecdql.md Top_Codqql.md ed.md >Top_Codeql.md
git commit -m "update $(date)" .;git push

