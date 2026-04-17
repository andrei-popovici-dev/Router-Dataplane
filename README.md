POPOVICI Andrei-Razvan 324CC

1. Se incearca trimiterea unui pachet icmp de tip "Echo Request" de pe h0 pe h3, astfel incat sa trecem prin ambele routere. In screenshot se poate observa terminalul din stanga sus, al lui h0, unde se observa faptul ca pachetul se intoarce inapoi, cu ttl = 62 (pentru cele 2 hop-uri). De asemenea, in screenshot se pot observa si 2 ferestre wireshark, cea de sus reprezentand una dintre interfetele routerului 0, respectiv cea de jos interfata routerului 1. In ferestrele wireshark se poate observa corespondenta request-reply cu secventele aferente.

2. Pentru implementarea LPM-ului am ales o abordare folosind un trie datorita complexitatii temporale reduse. In implementare am creeat 3 functii de biblioteca:
- init-trie: creeaza trie-ul pe baza tabelei de rutare(se foloseste de functia add_node)
- add_node: parcurge arborele pana cand isi "epuizeaza" masca de retea(aceasta determinand nivelul in arbore al unei adrese) si populeaza ultimul nod in care ajunge
- LPM: cauta nodul cel mai adanc din trie care este populat

3. Se trimite o cerere de tip "ARP Broadcast"(folosind arping) de catre h0 la interfata expusa de router0 lui h0. In screenshot se poate observa terminalul din stanga sus, al lui h0, unde se observa faptul ca router0 raspunde cu un pachet arp reply catre h0. In fereastra wireshark se observa pachetul initial trimis de h0 de tip "Broadcast", care este primit de router0, iar acesta la randul sau trimite "ARP reply" catre h0.

4. Se trimit 2 tipuri de ping-uri: unul cu un TTL = 1, garantand astfel o eroare de tip "TTL Exceeded", si unul cu o adresa care nu exista in retea, garantand o eroare de tip "Destination Unreachable". In terminal-ul din stanga sus, al lui h0, se poate observa faptul ca router-ul interpreteaza corect erorile pachetelor, iar acesta transmite atat pachete de eroare "TTL Exceeded", cat si "Destination Unreachable", in functie de problema. In fereastra wireshark se pot observa pachetele si corespondentul lor. In partea de jos a ferestrei wireshark se poate observa si includerea headerului ip si a celor 8 bytes din pachet