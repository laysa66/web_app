
import random
import codecs

output = codecs.open("question.sql", "w", "utf-8")
insert = "INSERT INTO question (id_user,question, answers, tags) VALUES(1,"
ans = "'[{''reponse'': ''R1'', ''correcte'': ''false''}, {''reponse'': ''R2'', ''correcte'': ''false''}, {''reponse'': ''R3'', ''correcte'': ''true''}, {''reponse'': ''R4'', ''correcte'': ''false''}]'"
tags = ["'Matrices'","'Python'","'C++'","'Java'","'C'","'Database'","'Réseaux'","'Système'","'Algorithmes'","'Programmation'","'Web'","'Logique'"]
sql_lines = []
for i in range(1, 100):
    #randint
    random_int = random.randint(1, len(tags)-1)
    print(random_int)
    #print in sql file 
    tags_q = "['" + "', '".join(random.sample(tags, random_int)) + "']"
    print(tags_q)
    sql_lines.append( insert+ "'Q" + str(i)+"'," + ans  + ", '" + tags_q + "');" + " \r" )

output.writelines(sql_lines)
output.close()
        
        