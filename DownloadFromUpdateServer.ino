/*************************************************** 
  This is an example for the Adafruit CC3000 Wifi Breakout & Shield

  Designed specifically to work with the Adafruit WiFi products:
  ----> https://www.adafruit.com/products/1469

  Adafruit invests time and resources providing this open source code, 
  please support Adafruit and open-source hardware by purchasing 
  products from Adafruit!

  Written by Limor Fried & Kevin Townsend for Adafruit Industries.  
  BSD license, all text above must be included in any redistribution
 ****************************************************/
 
 /*
This example does a test of the TCP client capability:
  * Initialization
  * Optional: SSID scan
  * AP connection
  * DHCP printout
  * DNS lookup
  * Optional: Ping
  * Connect to website and print out webpage contents
  * Disconnect
SmartConfig is still beta and kind of works but is not fully vetted!
It might not work on all networks!
*/
#include <WildFire.h>
#include <WildFire_CC3000.h>
#include <WildFire_SPIFlash.h>

#include <ccspi.h>
#include <SPI.h>
#include <TinyWatchdog.h>
#include <string.h>
#include "utility/debug.h"
#include "util/crc16.h"

WildFire wf;
WildFire_CC3000 cc3000;
WildFire_SPIFlash flash;
TinyWatchdog tinyWDT;

#define WLAN_SSID       "xxxxxxxxx"           // cannot be longer than 32 characters!
#define WLAN_PASS       "xxxxxxxxx"
// Security can be WLAN_SEC_UNSEC, WLAN_SEC_WEP, WLAN_SEC_WPA or WLAN_SEC_WPA2
#define WLAN_SECURITY   WLAN_SEC_WPA2

#define IDLE_TIMEOUT_MS  10000     // Amount of time to wait (in milliseconds) with no data 
                                   // received before closing the connection.  If you know the server
                                   // you're accessing is quick to respond, you can reduce this value.

// Where to download the update artifacts from
#define WEBSITE      "update.wickeddevice.com"

// the following defines are what goes in the SPI flash where to signal to the bootloader
#define LAST_4K_PAGE_ADDRESS      0x7F000     // the start address of the last 4k page
#define MAGIC_NUMBER              0x00ddba11  // this word at the end of SPI flash
                                              // is a signal to the bootloader to 
                                              // think about loading it
#define MAGIC_NUMBER_ADDRESS      0x7FFFC     // the last 4 bytes are the magic number
#define CRC16_CHECKSUM_ADDRESS    0x7FFFA     // the two bytes before the magic number
                                              // are the expected checksum of the file
#define FILESIZE_ADDRESS          0x7FFF6     // the four bytes before the checksum
                                              // are the stored file size
/**************************************************************************/
/*!
    @brief  Sets up the HW and the CC3000 module (called automatically
            on startup)
*/
/**************************************************************************/

uint32_t ip;
uint8_t mybuffer[512] = {0};
uint16_t downloadFile(char * filename, void (*responseBodyProcessor)(uint8_t, boolean));
unsigned long integrity_num_bytes_total = 0;
unsigned long integrity_crc16_checksum = 0;
void processIntegrityCheckBody(uint8_t dataByte, boolean end_of_stream);
void processUpdateHexBody(uint8_t dataByte, boolean end_of_stream);

// downloaded signature file values
unsigned long total_bytes_read = 0;
unsigned long body_bytes_read = 0;
uint16_t crc16_checksum = 0;
uint32_t flash_file_size = 0;
uint16_t flash_signature = 0;

void setup(void)
{
  wf.begin();
  tinyWDT.begin(500, 60000); 
  cc3000.enableTinyWatchdog(14, 500);
  Serial.begin(115200);

  Serial.print(F("SPI Flash Initialization..."));
  if (flash.initialize()){
    Serial.println(F("Complete."));    
  }
  else{
    Serial.println(F("Failed!"));  
  }  

  Serial.println(F("Hello, CC3000!\n"));   
  Serial.print("Free RAM: "); Serial.println(getFreeRam(), DEC);

  // retrieve the current signature parameters  
  flash_file_size = flash.readByte(FILESIZE_ADDRESS);
  flash_file_size <<= 8;
  flash_file_size |= flash.readByte(FILESIZE_ADDRESS+1);
  flash_file_size <<= 8;
  flash_file_size |= flash.readByte(FILESIZE_ADDRESS+2);  
  flash_file_size <<= 8;
  flash_file_size |= flash.readByte(FILESIZE_ADDRESS+3);  

  flash_signature = flash.readByte(CRC16_CHECKSUM_ADDRESS);
  flash_signature <<= 8;
  flash_signature |= flash.readByte(CRC16_CHECKSUM_ADDRESS+1);
  
  Serial.print("Current Signature: ");
  Serial.print(flash_file_size);
  Serial.print(" ");
  Serial.print(flash_signature);
  Serial.println();
  
  /* Initialise the module */
  Serial.println(F("\nInitializing..."));
  if (!cc3000.begin())
  {
    Serial.println(F("Couldn't begin()! Check your wiring?"));
    while(1);
  }
      
  // Optional SSID scan
  // listSSIDResults();
  
  Serial.print(F("\nAttempting to connect to ")); Serial.println(WLAN_SSID);
  if (!cc3000.connectToAP(WLAN_SSID, WLAN_PASS, WLAN_SECURITY)) {
    Serial.println(F("Failed!"));
    while(1);
  }
   
  Serial.println(F("Connected!"));
  
  /* Wait for DHCP to complete */
  Serial.println(F("Request DHCP"));
  while (!cc3000.checkDHCP())
  {
    delay(100); // ToDo: Insert a DHCP timeout!
  }  

  /* Display the IP address DNS, Gateway, etc. */  
  while (! displayConnectionDetails()) {
    delay(1000);
  }

  ip = 0;
  // Try looking up the website's IP address
  Serial.print(WEBSITE); Serial.print(F(" -> "));
  while (ip == 0) {
    if (! cc3000.getHostByName(WEBSITE, &ip)) {
      Serial.println(F("Couldn't resolve!"));
    }
    delay(500);
  }

  cc3000.printIPdotsRev(ip);
  
  // Optional: Do a ping test on the website  
  /*
  Serial.print(F("\n\rPinging ")); cc3000.printIPdotsRev(ip); Serial.print("...");  
  uint8_t replies = cc3000.ping(ip, 5);
  Serial.print(replies); Serial.println(F(" replies"));
  */

  // try and download the integrity check file up to three times
  uint16_t num_hdr_bytes = 0;
  for(uint8_t ii = 0; ii < 3; ii++){
    num_hdr_bytes = downloadFile("test.chk", processIntegrityCheckBody);   
    if(num_hdr_bytes > 0){
      break; 
    }
  }
  
  if(num_hdr_bytes > 0){
    // compare the just-retrieved signature file contents 
    // to the signature already stored in flash
    if((flash_file_size != integrity_num_bytes_total) || 
      (flash_signature != integrity_crc16_checksum)){
      flash.chipErase();
      
      // write these parameters to their rightful place in the SPI flash
      // for consumption by the bootloader
      
      while(flash.busy()){;}   
      flash.blockErase4K(LAST_4K_PAGE_ADDRESS);
      while(flash.busy()){;}  
      
      flash.writeByte(CRC16_CHECKSUM_ADDRESS + 0, (integrity_crc16_checksum >> 8) & 0xff);
      flash.writeByte(CRC16_CHECKSUM_ADDRESS + 1, (integrity_crc16_checksum >> 0) & 0xff);
      
      flash.writeByte(FILESIZE_ADDRESS + 0, (integrity_num_bytes_total >> 24) & 0xff);
      flash.writeByte(FILESIZE_ADDRESS + 1, (integrity_num_bytes_total >> 16) & 0xff);    
      flash.writeByte(FILESIZE_ADDRESS + 2, (integrity_num_bytes_total >> 8)  & 0xff);
      flash.writeByte(FILESIZE_ADDRESS + 3, (integrity_num_bytes_total >> 0)  & 0xff);            
      
      downloadFile("test.hex", processUpdateHexBody);    
      while(flash.busy()){;}   
      delay(500);
      //readOutFlashContents();
      
      // use tinywatchdog to force reset
      tinyWDT.force_reset();      
    }
    else{
      Serial.println("Signature matches, skipping HEX download.");
    }
  }
  else{
    Serial.println("Failed to download integrity check file, skipping Hex file download");
  }
  
  /* You need to make sure to clean up after yourself or the CC3000 can freak out */
  /* the next time your try to connect ... */
  Serial.println(F("\n\nDisconnecting"));
  cc3000.disconnect();
  
  pinMode(6, OUTPUT);
  digitalWrite(6, LOW);
}

void loop(void)
{
 static uint8_t led_state = 0; 
 delay(500);
 digitalWrite(6, led_state);
 led_state = 1 - led_state;
}

/**************************************************************************/
/*!
    @brief  Begins an SSID scan and prints out all the visible networks
*/
/**************************************************************************/

void listSSIDResults(void)
{
  uint32_t index;
  uint8_t valid, rssi, sec;
  char ssidname[33]; 

  if (!cc3000.startSSIDscan(&index)) {
    Serial.println(F("SSID scan failed!"));
    return;
  }

  Serial.print(F("Networks found: ")); Serial.println(index);
  Serial.println(F("================================================"));

  while (index) {
    index--;

    valid = cc3000.getNextSSID(&rssi, &sec, ssidname);
    
    Serial.print(F("SSID Name    : ")); Serial.print(ssidname);
    Serial.println();
    Serial.print(F("RSSI         : "));
    Serial.println(rssi);
    Serial.print(F("Security Mode: "));
    Serial.println(sec);
    Serial.println();
  }
  Serial.println(F("================================================"));

  cc3000.stopSSIDscan();
}

/**************************************************************************/
/*!
    @brief  Tries to read the IP address and other connection details
*/
/**************************************************************************/
bool displayConnectionDetails(void)
{
  uint32_t ipAddress, netmask, gateway, dhcpserv, dnsserv;
  
  if(!cc3000.getIPAddress(&ipAddress, &netmask, &gateway, &dhcpserv, &dnsserv))
  {
    Serial.println(F("Unable to retrieve the IP Address!\r\n"));
    return false;
  }
  else
  {
    Serial.print(F("\nIP Addr: ")); cc3000.printIPdotsRev(ipAddress);
    Serial.print(F("\nNetmask: ")); cc3000.printIPdotsRev(netmask);
    Serial.print(F("\nGateway: ")); cc3000.printIPdotsRev(gateway);
    Serial.print(F("\nDHCPsrv: ")); cc3000.printIPdotsRev(dhcpserv);
    Serial.print(F("\nDNSserv: ")); cc3000.printIPdotsRev(dnsserv);
    Serial.println();
    return true;
  }
}

// processs bytes as a state machine
// if you successfully process an address field, return it in addr, and return a positive status code 1
// if you decode a data byte, return it in data_byte and update addr to reflect the address of that byte, and return status code 2
// if you get a checksum error on a record return -1
// if you get an unknown record type on a record return -1
int8_t hex_file_process_char(char c, uint16_t * addr, uint8_t * decoded_data_byte){
  static uint8_t processing_state = 0;
  static uint8_t num_bytes_expected_in_current_record = 0;  
  static uint8_t current_offset_byte_address = 0;
  
  switch(processing_state){
    case 0:   // expecting colon
      break;
    default:  // unknown state
      break; 
  }
  
}

// returns the number of header bytes in the server response
// if the file was downloaded in one chunk, this means that
// mybuffer[ret] is the first byte of the response body
uint16_t downloadFile(char * filename, void (*responseBodyProcessor)(uint8_t, boolean)){
  uint16_t ret = 0;
  
  // re-initialize the globals
  total_bytes_read = 0; 
  body_bytes_read = 0;
  crc16_checksum = 0;
  
  /* Try connecting to the website.
     Note: HTTP/1.1 protocol is used to keep the server from closing the connection before all data is read.
  */
  tinyWDT.pet();
  WildFire_CC3000_Client www = cc3000.connectTCP(ip, 80);
  if (www.connected()) {
    www.fastrprint(F("GET /"));
    www.fastrprint(filename);
    www.fastrprint(F(" HTTP/1.1\r\n"));
    www.fastrprint(F("Host: ")); www.fastrprint(WEBSITE); www.fastrprint(F("\r\n"));
    www.fastrprint(F("\r\n"));
    www.println();
  } else {
    Serial.println(F("Connection failed"));    
    return 0;
  }

  Serial.println(F("-------------------------------------"));
  
  /* Read data until either the connection is closed, or the idle timeout is reached. */ 
  unsigned long lastRead = millis();
  unsigned long num_chunks = 0;
  unsigned long num_bytes_read = 0;
  unsigned long num_header_bytes = 0;
  unsigned long start_time = millis();
  
  #define PARSING_WAITING_FOR_CR       0
  #define PARSING_WAITING_FOR_CRNL     1
  #define PARSING_WAITING_FOR_CRNLCR   2
  #define PARSING_WAITING_FOR_CRNLCRNL 3  
  #define PARSING_FOUND_CRNLCRNL       4
  uint8_t parsing_state = PARSING_WAITING_FOR_CR;
  
  // get past the response headers    
  while (www.connected() && (millis() - lastRead < IDLE_TIMEOUT_MS)) {   
    while (www.available()) {
      //char c = www.read();
      tinyWDT.pet();
      num_bytes_read = www.read(mybuffer, 255);
      num_chunks++;
      for(uint8_t ii = 0 ; ii < num_bytes_read; ii++){
         if(parsing_state != PARSING_FOUND_CRNLCRNL){
           num_header_bytes++;
         }
         
         switch(parsing_state){
         case PARSING_WAITING_FOR_CR:
           if(mybuffer[ii] == '\r'){
             parsing_state = PARSING_WAITING_FOR_CRNL;
           }
           break;
         case PARSING_WAITING_FOR_CRNL:
           if(mybuffer[ii] == '\n'){
             parsing_state = PARSING_WAITING_FOR_CRNLCR;
           }         
           else{
             parsing_state = PARSING_WAITING_FOR_CR;
           }
           break;
         case PARSING_WAITING_FOR_CRNLCR:
           if(mybuffer[ii] == '\r'){
             parsing_state = PARSING_WAITING_FOR_CRNLCRNL;
           }         
           else{
             parsing_state = PARSING_WAITING_FOR_CR;
           }         
           break;
         case PARSING_WAITING_FOR_CRNLCRNL:
           if(mybuffer[ii] == '\n'){
             parsing_state = PARSING_FOUND_CRNLCRNL;
           }         
           else{
             parsing_state = PARSING_WAITING_FOR_CR;
           }         
           break;             
         default:           
           crc16_checksum = _crc16_update(crc16_checksum, mybuffer[ii]);
           if(responseBodyProcessor != 0){
             responseBodyProcessor(mybuffer[ii], false);
             body_bytes_read++;
           }
           break;
         }               
      }
      //Serial.println(num_bytes_read);
      total_bytes_read += num_bytes_read;
      uint16_t address = 0;
      uint8_t data_byte = 0;       
      lastRead = millis();
    }
  }
  
  www.close();
  
  if(responseBodyProcessor != 0){
    responseBodyProcessor(0, true); // signal end of stream
  }  
  
  unsigned long end_time = millis();
  Serial.println(F("-------------------------------------"));
  Serial.print("# Bytes Read: ");
  Serial.println(total_bytes_read);
  Serial.print("# Chunks Read: ");
  Serial.println(num_chunks);
  Serial.print("File Size: ");
  Serial.println(total_bytes_read - num_header_bytes);
  Serial.print("CRC16 Checksum: ");
  Serial.println(crc16_checksum);
  Serial.print("Download Time: ");
  Serial.println(end_time - start_time); 
  
  return num_header_bytes;
}

void processIntegrityCheckBody(uint8_t dataByte, boolean end_of_stream){
  char * endPtr;
  static char buff[64] = {0};
  static uint8_t buff_idx = 0;
  
  if(end_of_stream){
    integrity_num_bytes_total = strtoul(buff, &endPtr, 10);
    if(endPtr != 0){
      integrity_crc16_checksum = strtoul(endPtr, 0, 10);
    }
    Serial.println("Integrity Checks: ");
    Serial.print(  "   File Size: ");
    Serial.println(integrity_num_bytes_total);
    Serial.print(  "   CRC16 Checksum: ");
    Serial.println(integrity_crc16_checksum);             
  }
  else{    
    if(buff_idx < 63){
      buff[buff_idx++] = dataByte;
    }
  }
}

void processUpdateHexBody(uint8_t dataByte, boolean end_of_stream){
  static uint8_t page[256] = {0};
  static uint16_t page_idx = 0;
  static uint32_t page_address = 0;
  
  page[page_idx++] = dataByte;
  if(page_idx >= 256){
     page_idx = 0;
  }
  
  if(end_of_stream || (page_idx == 0)){
    if((page_address % 4096) == 0){
      while(flash.busy()){;}    
      flash.blockErase4K(page_address); 
      while(flash.busy()){;}   
    }    
    
    uint16_t top_bound = 256;
    if(page_idx != 0){
      top_bound = page_idx;
    }
    flash.writeBytes(page_address, page, top_bound);
    
    
    // clear the page
    memset(page, 0, 256);
    
    // advance the page address
    page_address += 256;
    
  }
  
  if(end_of_stream){
    if((body_bytes_read == integrity_num_bytes_total) && (crc16_checksum == integrity_crc16_checksum)){
      flash.writeByte(MAGIC_NUMBER_ADDRESS + 0, MAGIC_NUMBER >> 24); 
      flash.writeByte(MAGIC_NUMBER_ADDRESS + 1, MAGIC_NUMBER >> 16); 
      flash.writeByte(MAGIC_NUMBER_ADDRESS + 2, MAGIC_NUMBER >> 8); 
      flash.writeByte(MAGIC_NUMBER_ADDRESS + 3, MAGIC_NUMBER >> 0); 
      Serial.println(F("Integrity Check Succeeded!"));
    }
    else{
      Serial.println(F("Integrity Check Failed!"));
      Serial.print(F("Expected Checksum: "));
      Serial.print(integrity_crc16_checksum);
      Serial.print(F(", Actual Checksum: "));
      Serial.println(crc16_checksum);
      Serial.print(F("Expected Filesize: "));
      Serial.print(integrity_num_bytes_total);
      Serial.print(F(", Actual Filesize: "));
      Serial.println(body_bytes_read);
    }
  }
}

void readOutFlashContents(void){
  uint8_t page[257] = {0}; // leave a space at the end for an artificial null terminator
  uint16_t crc_check = 0;
  uint32_t file_size = 0;
  
  for(uint16_t jj = 0; jj < 2048; jj++){
    uint32_t page_address = (uint32_t) jj * 256;
    flash.readBytes(page_address, page, 256);   
    uint16_t page_length = strlen((char *) page);    
    file_size += page_length;
    crc_check = printFlashBlock(page, page_address, crc_check); 
    if(page_length < 256){
      break; 
    }    
  }

  if((file_size == integrity_num_bytes_total) && (crc_check == integrity_crc16_checksum)){
    Serial.println(F("Integrity Check Succeeded!"));
  }
  else{
    Serial.println(F("Integrity Check Failed!"));
    Serial.print(F("Expected Checksum: "));
    Serial.print(integrity_crc16_checksum);
    Serial.print(F(", Actual Checksum: "));
    Serial.println(crc_check);
    Serial.print(F("Expected Filesize: "));
    Serial.print(integrity_num_bytes_total);
    Serial.print(F(", Actual Filesize: "));
    Serial.println(file_size);
  }  
  
  Serial.println(F("---------------------------"));
  Serial.println(F("Integrity Values stored in SPI Flash:"));
  
  Serial.print(F("   File Size: "));
  uint32_t fsize = 0;
  fsize |= flash.readByte(FILESIZE_ADDRESS);
  fsize <<= 8;
  fsize |= flash.readByte(FILESIZE_ADDRESS+1);
  fsize <<= 8;
  fsize |= flash.readByte(FILESIZE_ADDRESS+2);
  fsize <<= 8;
  fsize |= flash.readByte(FILESIZE_ADDRESS+3);  
  Serial.println(fsize);
  
  Serial.print(F("   Checksum: "));
  uint16_t chk = 0;
  chk |= flash.readByte(CRC16_CHECKSUM_ADDRESS);
  chk <<= 8;
  chk |= flash.readByte(CRC16_CHECKSUM_ADDRESS+1);
  Serial.println(chk);  
  
  Serial.print(F("   Magic Number: "));
  uint8_t val = flash.readByte(MAGIC_NUMBER_ADDRESS);
  if(val < 0x10) Serial.print(F("0")); Serial.print(val, HEX);
  val = flash.readByte(MAGIC_NUMBER_ADDRESS + 1);
  if(val < 0x10) Serial.print(F("0")); Serial.print(val, HEX);
  val = flash.readByte(MAGIC_NUMBER_ADDRESS + 2);
  if(val < 0x10) Serial.print(F("0")); Serial.print(val, HEX);
  val = flash.readByte(MAGIC_NUMBER_ADDRESS + 3);
  if(val < 0x10) Serial.print(F("0")); Serial.print(val, HEX);  
}

uint16_t printFlashBlock(uint8_t * page, uint32_t page_address, uint16_t crc){
  uint16_t ret = crc;
  const uint8_t row_size = 64; // equally divides 256
  for(uint16_t ii = 0; ii < 256/row_size; ii++){
    uint32_t row_address = (uint32_t) ii * row_size;
    for(uint8_t jj = 0; jj < row_size; jj++){
      if(page[row_address+jj] != 0xFF && page[row_address+jj] != 0){
        Serial.print((char) page[row_address+jj]);  
        ret = _crc16_update(ret, page[row_address+jj]);
      }
      else{
        return ret; 
      }
    }
  }
 
  return ret;
}
