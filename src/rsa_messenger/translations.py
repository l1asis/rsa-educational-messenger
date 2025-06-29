# translations.py
# Centralized translations for the RSA Messenger client

from typing import Any

TRANSLATIONS: dict[str, Any] = {
    "client": {
        "connect": {
            "en": {
                "title": "Client App | Connect Page",
                "welcome": "Welcome!",
                "info": "Here's some info and rules:",
                "rule1": "[1] - Please enter the local IP of the server and the server port specified by the organizer.",
                "rule2": "[2] - The name and username will be assigned to you automatically.",
                "rule3": "[3] - You can select your preferred country (affects the name).",
                "rule4": "[4] - You may have to wait until the organizer allows you to join.",
                "rule5": "[5] - Rude behaviour and harassment are prohibited. Be nice.",
                "country": "Country:",
                "server_ip": "Server-IP:",
                "server_port": "Server-Port:",
                "connect": "Connect",
            },
            "de": {
                "title": "Client App | Verbindungsseite",
                "welcome": "Willkommen!",
                "info": "Hier sind einige Infos und Regeln:",
                "rule1": "[1] - Bitte geben Sie die lokale IP und den Server-Port ein, wie vom Organisator angegeben.",
                "rule2": "[2] - Name und Benutzername werden automatisch zugewiesen.",
                "rule3": "[3] - Sie können Ihr bevorzugtes Land auswählen (beeinflusst den Namen).",
                "rule4": "[4] - Sie müssen möglicherweise warten, bis der Organisator Sie zulässt.",
                "rule5": "[5] - Unhöfliches Verhalten ist verboten. Seien Sie nett.",
                "country": "Land:",
                "server_ip": "Server-IP:",
                "server_port": "Server-Port:",
                "connect": "Verbinden",
            },
        },
        "waiting": {
            "en": {
                "title": "Client App | Waiting Page",
                "waiting_for_approval": "Waiting for approval...",
                "facts": [
                    "RSA was invented in 1977 by Ron Rivest, Adi Shamir, and Leonard Adleman.",
                    "It was one of the first practical public-key encryption methods.",
                    "As an asymmetric algorithm, RSA uses a public key for encryption and a private key for decryption.",
                    "Only the private key holder can decrypt messages encrypted with the corresponding public key.",
                    "RSA's security relies on the difficulty of factoring the product of two large primes.",
                    "Multiplying primes is easy; factoring their product is difficult.",
                    "RSA keys usually range from 1024 to 4096 bits; longer keys offer more security but slower performance.",
                    "RSA can generate digital signatures to verify a message's authenticity and integrity.",
                    "Prime numbers form the core of RSA encryption.",
                    "RSA is essential for secure online communication, like HTTPS, which ensures encrypted key exchanges.",
                    "Quantum algorithms, like Shor's, could potentially break RSA by factoring large numbers quickly.",
                    "RSA needs padding (e.g., PKCS#1) to prevent attacks and improve security through randomness.",
                    "RSA is commonly used to encrypt small pieces of data or symmetric keys, not large files.",
                    "It's slow for bulk data encryption, so it's often paired with faster algorithms like AES.",
                    "A compromised private key risks all data encrypted with the matching public key.",
                    "The largest known prime number has over 24 million digits: 2^(136,279,841) − 1, a Mersenne prime.",
                    "Euler's work on modular arithmetic and number theory is fundamental to the RSA encryption algorithm.",
                    "The modular inverse in RSA, used to calculate the private key, relies on Euler's theorem to ensure the correct decryption.",
                    "Euler's Totient Function (φ(n)) is used in RSA to calculate the private key. For two primes p and q, φ(n) = (p-1)(q-1).",
                    "Euler's Theorem states that for coprime integers a and n, a^(φ(n)) ≡ 1 (mod n).",
                ],
                "just_wait": "Just wait",
            },
            "de": {
                "title": "Client App | Warteseite",
                "waiting_for_approval": "Warten auf Genehmigung...",
                "facts": [
                    "RSA wurde 1977 von Ron Rivest, Adi Shamir und Leonard Adleman erfunden.",
                    "Es war eine der ersten praktischen Methoden der öffentlichen Schlüsselverschlüsselung.",
                    "RSA verwendet einen öffentlichen Schlüssel zur Verschlüsselung und einen privaten zur Entschlüsselung.",
                    "Nur der Inhaber des privaten Schlüssels kann Nachrichten entschlüsseln, die mit dem entsprechenden öffentlichen Schlüssel verschlüsselt wurden.",
                    "Die Sicherheit von RSA beruht auf der Schwierigkeit, das Produkt großer Primzahlen zu faktorisieren.",
                    "Primzahlen zu multiplizieren ist einfach, ihre Faktorisierung jedoch schwierig.",
                    "RSA-Schlüssel reichen von 1024 bis 4096 Bits; längere Schlüssel bieten mehr Sicherheit, aber langsamere Leistung.",
                    "RSA kann digitale Signaturen erzeugen, um die Authentizität und Integrität einer Nachricht zu überprüfen.",
                    "Primzahlen sind der Kern der RSA-Verschlüsselung.",
                    "RSA ist wichtig für sichere Online-Kommunikation wie HTTPS, das verschlüsselte Schlüsselaustausche gewährleistet.",
                    "Quantenalgorithmen wie Shor's könnten RSA durch schnelles Faktorisieren großer Zahlen brechen.",
                    "RSA benötigt Padding (z. B. PKCS#1), um Angriffe zu verhindern und die Sicherheit durch Zufälligkeit zu erhöhen.",
                    "RSA wird meist verwendet, um kleine Daten oder symmetrische Schlüssel zu verschlüsseln, nicht große Dateien.",
                    "Es ist langsam bei der Verschlüsselung großer Datenmengen, daher wird es oft mit schnelleren Algorithmen wie AES kombiniert.",
                    "Ein kompromittierter privater Schlüssel gefährdet alle Daten, die mit dem passenden öffentlichen Schlüssel verschlüsselt wurden.",
                    "Die größte bekannte Primzahl hat über 24 Millionen Stellen: 2^(136,279,841) − 1, eine Mersenne-Primzahl.",
                    "Eulers Arbeit zur modularen Arithmetik ist entscheidend für den RSA-Algorithmus.",
                    "Der modulare Inverse in RSA, der zur Berechnung des privaten Schlüssels verwendet wird, basiert auf Eulers Theorem.",
                    "Eulers Totientfunktion (φ(n)) wird in RSA zur Berechnung des privaten Schlüssels verwendet: φ(n) = (p-1)(q-1).",
                    "Eulers Theorem besagt, dass für teilerfremde ganze Zahlen a und n gilt: a^(φ(n)) ≡ 1 (mod n).",
                ],
                "just_wait": "Einfach warten",
            },
        },
        "rsa_key_generator": {
            "en": {
                "title": "Client App | RSA Key Generator",
                "error1": "Both p and q must be valid integers.",
                "error2": "Both p and q must be prime numbers. Non-prime numbers could lead to weak encryption keys.",
                "error3": "p and q must be distinct prime numbers. If not, given N (which by definition is public in RSA), it is trivial to find p=q=√N",
                "error4": "Both p and q must be greater than 1. Numbers less than or equal to 1 are not prime and cannot be used in cryptographic operations.",
                "error5": "The values of p and q are too close. Close primes could make factorization easier and weaken encryption.",
                "error6": "e and d cannot be equal. If e equals d, the private key can be derived from the public key, which breaks the encryption.",
            },
            "de": {
                "title": "Client App | RSA-Schlüsselgenerator",
                "error1": "Sowohl p als auch q müssen gültige ganze Zahlen sein.",
                "error2": "Sowohl p als auch q müssen Primzahlen sein. Nicht-Primzahlen könnten zu schwachen Verschlüsselungsschlüsseln führen.",
                "error3": "p und q müssen verschiedene Primzahlen sein. Wenn nicht, ist es trivial, p=q=√N zu finden, wenn N gegeben ist (was in RSA öffentlich ist).",
                "error4": "Sowohl p als auch q müssen größer als 1 sein. Zahlen kleiner oder gleich 1 sind keine Primzahlen und können nicht in kryptografischen Operationen verwendet werden.",
                "error5": "Die Werte von p und q sind zu nah beieinander. Nahe Primzahlen könnten die Faktorisierung erleichtern und die Verschlüsselung schwächen.",
                "error6": "e und d dürfen nicht gleich sein. Wenn e gleich d ist, kann der private Schlüssel aus dem öffentlichen Schlüssel abgeleitet werden, was die Verschlüsselung bricht.",
            }
        }
    },
    "server": {
        "en": {
            "title": "Server App | Control Panel",
            "current_online": "Current Online Users:",
            "search": "Search Users:",
            "status": {
                "awaits_approval": "Awaits Approval",
                "online": "Online",
                "offline": "Offline",
                "kicked": "Kicked",
                "banned": "Banned",
            },
            "buttons": {
                "approve": "Approve",
                "kick": "Kick",
                "ban": "Ban",
                "unban": "Unban",
                "info": "Info",
            },
            "logging": "Display Logs",
        },
        "de": {
            "title": "Server App | Kontrollpanel",
            "current_online": "Aktuell Online-Benutzer:",
            "search": "Benutzer suchen:",
            "status": {
                "awaits_approval": "Wartet auf Genehmigung",
                "online": "Online",
                "offline": "Offline",
                "kicked": "Gekickt",
                "banned": "Gesperrt",
            },
            "buttons": {
                "approve": "Genehmigen",
                "kick": "Kicken",
                "ban": "Sperren",
                "unban": "entsperren",
                "info": "Info",
            },
            "logging": "Protokolle anzeigen",
        },
    },
    "common": {
        "en": {
            "loading": "Loading...",
            "error": "Error",
            "success": "Success",
            "info": "Info",
            "warning": "Warning",
            "yes": "Yes",
            "no": "No",
            "ok": "OK",
            "cancel": "Cancel",
        },
        "de": {
            "loading": "Laden...",
            "error": "Fehler",
            "success": "Erfolg",
            "info": "Info",
            "warning": "Warnung",
            "yes": "Ja",
            "no": "Nein",
            "ok": "OK",
            "cancel": "Abbrechen",
        },
    }
}