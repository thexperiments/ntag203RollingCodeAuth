//Rolling code Authentication for ntag203 (mifare ultralight)

//headers for MFRC522 lib
//see: https://github.com/miguelbalboa/rfid/
//code for reading and writing tags taken from the examples
#include <SPI.h>
#include <MFRC522.h>

//headers needed for best possible randomness
//see: https://gist.github.com/endolith/2568571
//all code for random generation taken from there
#include <stdint.h>
#include <avr/interrupt.h>
#include <avr/wdt.h>

//header for eeprom (because we need to safe the keys and ring pages)
#include <EEPROM.h>

//config of MRFC522 lib
#define SS_PIN 10
#define RST_PIN 9
MFRC522 mfrc522(SS_PIN, RST_PIN);        // Create MFRC522 instance.

//variables for the randomness
byte rnd_sample = 0;
boolean rnd_sample_waiting = false;
byte rnd_current_bit = 0;
byte rnd_result = 0;
byte rnd_current_byte = 0; //modifying to generate
byte rnd_result_bytes[4];  //4 random bytes as we are going to use one page key for now
boolean rnd_result_bytes_valid = false;

//some defines for memory operations
#define KEY_SIZE 4 //because we want to use only one page for now (4bytes)
#define UID_SIZE 7 //because ntag UID is 7 bytes
#define KEY_STAORAGE_OFFSET 0x7F //we offset the key storage to the middle of the memory for now
#define MAX_KNOWN_UIDS 10 //for reserving memory to read the uids from eeprom
#define UID_NOT_KNOWN 0xFF //when getting an index of a uid this indicates that it was not found

//defines for jumper learn mode
#define JP_LEARN_PIN 6
#define JP_LEARN_GND_PIN 5

//variables for authentication code
byte known_uid_count = 0; //because we need to know where to add a new one
MFRC522::Uid known_uids[MAX_KNOWN_UIDS]; //for storing known tag uids
byte pages_used[2] = {0x26,0x27};//we need to toggle between these to 
//make sure we dont ruin the old key when writing the new one

//////////////////////////////////////////////
///////////////////Random helpers/////////////
//////////////////////////////////////////////

//code from propably_random.ino see top of file for link

// Rotate bits to the left
// https://en.wikipedia.org/wiki/Circular_shift#Implementing_circular_shifts
byte rotl(const byte value, int shift) {
  if ((shift &= sizeof(value)*8 - 1) == 0)
    return value;
  return (value << shift) | (value >> (sizeof(value)*8 - shift));
}

// Setup of the watchdog timer.
void wdtSetup() {
  cli();
  MCUSR = 0;
  
  /* Start timed sequence */
  WDTCSR |= _BV(WDCE) | _BV(WDE);
 
  /* Put WDT into interrupt mode */
  /* Set shortest prescaler(time-out) value = 2048 cycles (~16 ms) */
  WDTCSR = _BV(WDIE);
 
  sei();
}
 
// Watchdog Timer Interrupt Service Routine
ISR(WDT_vect)
{
  rnd_sample = TCNT1L; // Ignore higher bits
  rnd_sample_waiting = true;
}

//////////////////////////////////////////////
///////////////////helpers////////////////////
//////////////////////////////////////////////

void serialPrintBytes (byte *bytes, int size){
  //print the bytes
  for (int i = 0; i<size; i++){
    Serial.print(bytes[i] < 0x10 ? " 0" : " ");
    Serial.print(bytes[i],HEX);
  }
  Serial.println();
}


//////////////////////////////////////////////
///////////////////RFID helpers///////////////
//////////////////////////////////////////////

byte getUidIndex(MFRC522::Uid *uid)
{
  byte found_uid_index = UID_NOT_KNOWN; //UID_NOT_KNOWN indicates that uid was not found
  for (int uid_index = 0; uid_index < (sizeof(known_uids)/sizeof(MFRC522::Uid)); uid_index++)
  {
    //loop through all known uids
    for (int uid_byte_index = 0; uid_byte_index < (*uid).size; uid_byte_index++)
    {
      //and loop through all bytes of these uids
      if (known_uids[uid_index].uidByte[uid_byte_index] != (*uid).uidByte[uid_byte_index])
      {
        //at least one byte does not match, proceed to checking next uid
        break;
      }
      else if (uid_byte_index == ((*uid).size - 1))
      {
        //last byte also was equal, we know this uid!
        found_uid_index = uid_index;
      }
    }
    if (found_uid_index != UID_NOT_KNOWN) break; //we have found the uid, no reason to look further
  }
  return(found_uid_index);
}

void readUidRecords(MFRC522::Uid uids[MAX_KNOWN_UIDS])
{
  //we first need to read the number of uids which are stored in memory
  //we have stored them right before the keys
  byte addr = KEY_STAORAGE_OFFSET - 1;
  byte uid_count = EEPROM.read(addr);
  
  addr = 0x00; //reset to start of memory
  //read the UIDs
  for (byte uid_index = 0; uid_index<uid_count; uid_index++)
  {
    //for each stored uid
    uids[uid_index].size = UID_SIZE; //store the size of the uuid to the struct used by the RFID lib
    for (byte byte_index = 0; byte_index < UID_SIZE; byte_index++)
    {
      //itarate over bytes and read them from eeprom
      uids[uid_index].uidByte[byte_index] = EEPROM.read(addr);
      addr++;
    }
    Serial.print("Loading UID ");
    Serial.print(uid_index, DEC);
    //Serial.print(": ");
    //serialPrintBytes(uids[uid_index].uidByte, UID_SIZE);
    Serial.println();
  }
  //safe the number of uids found
  known_uid_count = uid_count;
}


void writeKeyRecord(byte key_index, byte page, byte key[])
{
  //calculating the start address for the entries we need 1 byte for the page and the space for the key
  //we offset the memory area to the middle of the 255byte memory (half memory for keys, half for cards)
  byte addr = key_index * (1 + KEY_SIZE) + KEY_STAORAGE_OFFSET;
  //first write the page we have written the key to
  EEPROM.write(addr, page);
  addr++;
  for (byte i=0; i<KEY_SIZE; i++)
  {
    //then itarate over key bites and save them
    EEPROM.write(addr, key[i]);
    addr++;
  }
}

void writeUidRecord(byte uid_index, byte uid[])
{
  //calculating the start address for the entries we need 1 byte for the page and the space for the key
  byte addr = uid_index * (UID_SIZE);
  for (byte i=0; i<UID_SIZE; i++)
  {
    //then itarate over key bites and save them
    EEPROM.write(addr, uid[i]);
    addr++;
  }
  //if it is a new entry (currently only option)
  if (uid_index >= known_uid_count)
  {
    //we need to increase the known cards
    known_uid_count++;
    //we have stored it right before the keys
    byte addr = KEY_STAORAGE_OFFSET - 1;
    EEPROM.write(addr, known_uid_count);
  }
}

boolean authenticateKey(byte key_index, byte key[])
{
  boolean authenticated = false;
  //calculating adress of key, basically the same as for writing but offsetby one because we don't want to read the page
  byte addr = key_index * (1 + KEY_SIZE) + KEY_STAORAGE_OFFSET + 1;
  //we will directly compare the stored key for that card
  for (byte i=0; i<KEY_SIZE; i++)
  {
    //by itarateing over key bytes
    if(key[i] != EEPROM.read(addr))
    {
      authenticated = false;
      break; //keys don't match no further investigation
    }
    else if (i == KEY_SIZE -1)
    {
      //if we get here we have reached the last byte and comparison was successfull
      authenticated = true;
    }
    addr++;
    
  }
  return authenticated;
}

byte getPageForKey(byte key_index)
{
  //calculating adress of key, basically the same as for writing
  byte addr = key_index * (1 + KEY_SIZE) + KEY_STAORAGE_OFFSET;
  //we can directly return what we read from the eeprom
  return (EEPROM.read(addr));
}

boolean writePage(byte page, byte data[4])
{
  byte status;
  Serial.print("Writing new value to page ");
  Serial.print(page, HEX);
  status = mfrc522.MIFARE_Ultralight_Write(page, data, 4);
  Serial.print(": ");
  serialPrintBytes(data, 4);
  if (status != MFRC522::STATUS_OK) {
    Serial.print("MIFARE_Ultralight_Write() failed: ");
    Serial.println(mfrc522.GetStatusCodeName(status));
    return false;
  }
  else
  {
    Serial.println("Sucessfully written new value!");
  }
  return true;
}

boolean readPage(byte page, byte buffer[4])
{
  byte status;
  Serial.print("Reading page ");
  Serial.println(page, HEX);     
  byte buffer_tmp[18];
  byte size = sizeof(buffer_tmp);
  status = mfrc522.MIFARE_Read(page, buffer_tmp, &size);
  if (status != MFRC522::STATUS_OK) {
    Serial.print("MIFARE_Read() failed: ");
    Serial.println(mfrc522.GetStatusCodeName(status));
    return false;
  }
  else
  {
    Serial.print("value: ");
    buffer[0] = buffer_tmp[0];
    buffer[1] = buffer_tmp[1];
    buffer[2] = buffer_tmp[2];
    buffer[3] = buffer_tmp[3];
    serialPrintBytes(buffer, 4);
  }
  return true;
}

byte getNewKeyPage(byte key_index)
{
  //we need to verify that the new key gets written to a 
  //different page than the old one was stored to
  byte new_page = 0;
  if(getPageForKey(key_index) == pages_used[0])
  {
      new_page = pages_used[1];
  }
  else
  {
      new_page = pages_used[0];
  }
  return new_page;
}

//////////////////////////////////////////////
///////////////////Access/////////////////////
//////////////////////////////////////////////
void accessGranted()
{
  Serial.println("Access granted!");
}

void accessDenied()
{
  Serial.println("Access denied!");
}

//////////////////////////////////////////////
///////////////////Setup//////////////////////
//////////////////////////////////////////////

void setup() {
  Serial.begin(115200);      // Initialize serial communications with the PC
  SPI.begin();               // Init SPI bus
  mfrc522.PCD_Init();        // Init MFRC522 card
  wdtSetup();                //setup the watchdog for randomness generation
  
  //setup the two pins for learning jumper
  pinMode(JP_LEARN_PIN, INPUT_PULLUP); //input for the learning mode jumper
  pinMode(JP_LEARN_GND_PIN, OUTPUT); //virtual gnd for learn jumper
  
  //make JP_LEARN_GND_PIN low to work as virtual gnd for learning jumper
  digitalWrite(JP_LEARN_GND_PIN, LOW);
  
  //read list of known uids from eeprom
  readUidRecords(known_uids);
}


//////////////////////////////////////////////
///////////////////Mainloop///////////////////
//////////////////////////////////////////////

void loop() {
  //code for gathering random number
  if (rnd_sample_waiting) {
    rnd_sample_waiting = false;
    rnd_result_bytes_valid = false;
   
    rnd_result = rotl(rnd_result, 1); // Spread randomness around
    rnd_result ^= rnd_sample; // XOR preserves randomness
   
    rnd_current_bit++;
    if (rnd_current_bit > 7)
    {
      rnd_current_bit = 0;
      rnd_result_bytes[rnd_current_byte] = rnd_result;
      rnd_current_byte++;
      if (rnd_current_byte > 3)
      {
        rnd_current_byte = 0;
        Serial.print("New random key:");
        serialPrintBytes(rnd_result_bytes,4);
        // flag the current random bytes as valid
        rnd_result_bytes_valid = true;
        //disable the watchdog to halt random generation
        wdt_disable();
      }
    }
  }
  
  //code for RFID reading and writing
  byte status;
  // Look for new cards
  if ( ! mfrc522.PICC_IsNewCardPresent()) {
          return;
  }

  // Select one of the cards
  if ( ! mfrc522.PICC_ReadCardSerial()) {
          return;
  }
  // Now a card is selected. The UID and SAK is in mfrc522.uid.
  
  // Dump UID
  //Serial.print("Card UID:");
  //serialPrintBytes(mfrc522.uid.uidByte, mfrc522.uid.size);
  Serial.println();

  //only allow ultralight compatible tags
  byte piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
  if (piccType != MFRC522::PICC_TYPE_MIFARE_UL) {
    Serial.println("This only supports mifare ultralight compatible tags (ntag203).");
    // Dump PICC type
    Serial.print("PICC type: ");
    Serial.println(mfrc522.PICC_GetTypeName(piccType));
    return;
  }
  
  //look it up, try to get index of the current uid
  byte current_uid_index = getUidIndex(&mfrc522.uid);
  if (current_uid_index != UID_NOT_KNOWN)
  {
    Serial.println("Known UID detected, authenticating.");
    byte key_buffer[4];
    byte key_page = getPageForKey(current_uid_index);
    if (readPage(key_page, key_buffer))
    {
      //we have read the key sucessfully, now authenticate it
      if (authenticateKey(current_uid_index, key_buffer)||(!digitalRead(JP_LEARN_PIN)))
      {
        //we are now authenticated or in learning mode
        //get the new key page
        byte new_key_page = getNewKeyPage(current_uid_index);
        //try to write new key to ring
        if (writePage(new_key_page, rnd_result_bytes))
        {
          //writing was succesfull
          //store the just written page/key in eeprom
          writeKeyRecord(current_uid_index,new_key_page, rnd_result_bytes);
          Serial.println("New key sucessfully written to tag.");
          accessGranted();
        } 
        else
        {
          Serial.println("Error writing key. Authentication aborted, please retry.");
          accessDenied();
        }
      }
      else
      {
        accessDenied();
      }
    }
    else
    {
      Serial.println("Error reading key, please retry.");
      accessDenied();
    }
  }
  else
  {
    if (!digitalRead(JP_LEARN_PIN))
    {
      Serial.println("New UID detected, writing key.");
      //write the key
      byte new_index = known_uid_count;//adding value so current count will be new index
      if (writePage(pages_used[0], rnd_result_bytes))
      {
        //writing was succesfull
        //store the just written page/key in eeprom
        writeKeyRecord(new_index,pages_used[0], rnd_result_bytes);
        //add the uid to the known ones
        writeUidRecord(new_index, mfrc522.uid.uidByte);
        //list of known uids changed, update it
        readUidRecords(known_uids);
        //all done
        Serial.println("New UID sucessfully added and initialized.");
      } 
      else
      {
        Serial.println("Error writing key. Learning aborted, pleas retry.");
      }
    }
    else{
      Serial.println("This UID is not known, authentication failed.");
      accessDenied();
    }
  }
  
  status = mfrc522.PICC_HaltA();
  if (status != MFRC522::STATUS_OK) {
                  Serial.print("PICC_HaltA() failed: ");
                  Serial.println(mfrc522.GetStatusCodeName(status));
  }
  else
  {
    Serial.println("PICC halted sucessfully, please reenter field to write again");
  }
  //enable watchdog timer to start random generation
  wdtSetup();
}



