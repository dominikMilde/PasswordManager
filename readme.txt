Opis sustava:
Povjerljivost i integritet podataka štićeni su glavnom zaporkom koja se mora upisati prilikom
svake naredbe komunikacije s tajnikom. Podržane operacije su:
init <glavna lozinka>
put <glavna lozinka> <adresa> <lozinka za adresu>
get <glavna lozinka> <adresa>

Koristim AEC_GCM mode jer na taj način mogu osigurati i povjerljivost i integritet.
Ključ se generira iz master ključa i salta (koji se mijenja svakim unosom/čitanjem) pomoću 
PBKDF2 funkcije za derivaciju ključa - 100 000 ponavljanja i algoritam SHA256.

Tijekom init naredbe, zapisujem kriptirani testni string.

Na početku bin datoteke je 16 bajtova salta nakon čega ide 16 bajtova nonce (IV) i nakon toga 16 bajtova tag koji nam je uz ciphertext dao AES_GCM.

Prilikom put i get naredbe se prvo generira ključ iz master lozinke i trenutno zapiranog salta u bin datoteci. Tim ključem i noncem i tagom iz 
trenutnog zapisa datoteke se dekriptira sadržaj bin datoteke. Ukoliko je master lozinka kriva ili je netko mijenjao bin datoteku, dekripcija neće uspjeti 
i obavijestit će se korisnik.

Na kraju put i get naredbe se generira novi salt. Njime se dokument kriptira - AESGCM nam daje nonce i tag koji zapisujemo na početak bin datoteke
kako bi nam koristio u sljedećem čitanju.

Upravo korištenje AESGCM i generiranje novih salta, taga i nonca nam osigurava sve sigurnosne zahtjeve navedene u vježbi. 
