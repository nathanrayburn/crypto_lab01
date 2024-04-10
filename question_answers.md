1. Quel est l’avantage d’utiliser le test du χ2 plutôt que de comparer simplement la lettre la plus fréquente dans le texte chiffré par rapport aux statistiques du langage de base? 

Cela nous permet d'avoir une vision ensemble du trend global du text. On peut avoir deux langues qui utilise fréquement une lettre et là ça vaudrait plus rien.

---
2. Pourquoi est-ce que le test du χ2 ne fonctionne-t-il pas directement sur un texte chiffré à l’aide du chiffre de Vigenère?

Vu que le Vigenère utilise pas le même shift pour chaque lettre. Cela rend le chiffre de Vigenère nettement plus résistant à l'analyse des fréquences contrairement à Caesear. Pour la même lettre, il peut avoir plusieurs sortis.

---
3.  Que mesure l’indice de coïncidence?

L'indice de coïncidence calcule la probabilité que deux lettres choisies au hasard dans un texte soient les mêmes. Cette mesure permet d'évaluer dans quelle mesure le texte suit une distribution de lettres aléatoire ou correspond à une structure de langue naturelle. En analysant cette probabilité, et en segmentant le texte chiffré en sous-groupes basés sur différentes longueurs de clé supposées, on peut utiliser l'indice de coïncidence pour s'approcher de la longueur réelle de la clé Vigenère. Cela repose sur l'idée que pour la bonne longueur de clé, les sous-groupes refléteront une distribution des lettres plus similaire à celle d'une langue naturelle.

---
4.  Pourquoi est-ce que l’indice de coïncidence n’est-il pas modifié lorsque l’on applique le chiffre de César généralisé sur un texte? 

---   
5.  Est-il possible de coder un logiciel permettant de décrypter un document chiffré avec le chiffre de Vigenère et une clef ayant la même taille que le texte clair? Justifiez. 

---   
6.  Expliquez votre attaque sur la version améliorée du chiffre de Vigenère.

---    
1.  Trouvez une méthode statistique (proche de ce qu’on a vu dans ce labo) permettant de distinguer un texte en anglais d’un texte en français. Qu’en pensez-vous? Testez votre méthode.