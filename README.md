# ntag203RollingCodeAuth
An arduino sketch for authenticating ntag203/mifare ultralight tags with really random "rolling" codes instead of only using UID with an MFRC522 rfid reader.

One can use this as a door lock for example.

Simply connect the learn pin to ground and the scanned tag will be stored as an authenticated tag.

You can also connect a speaker to the speaker pin and you will get a low beep on access denied and a high beep on access granted.

#How it works:
##Learning:
* The arduino will write a random (using the best "real" random generator for arduino I could find) 4byte number to the tag and will save the UUID and this random number in EEPROM.
##Authenticating
* Read the tag
* Check if UUID in "database"
* Read the 4byte secret which previously was stored and compare it to the one stored for this UUID in the EEPROM
* Write a new random secret to the tag and only after a sucessfull write trigger access granted function

#Note!
This is not by any means secure! There is no encryption at all.
The only security is that the random value gets changed everytime the tag is used to authenticate.
* Thus an attacker who would copy your rfid key would need to emulate the uuid and copy the secret from the memory.
* The attacker would need to use the door before you do it the next time because the stolen code will only be valid until you use your tag again.
* You would notice the security-breach because your tag would not authenticate any more as the new key from the attackers authentication is now stored in the "database"

However I have seen countles Arduino projects use only the UUID for authentication which I think this solution here is far superior to. I especially like it because it works with the NFC Ring (http://nfcring.com/)

#Todo
* Better learning (support of onlearning specific tags)
* Rewrite ugly hacky code.
* Create a really secure version with more advanced smartcard.
