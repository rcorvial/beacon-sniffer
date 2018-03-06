/**
 * @file      beacon-sniffer.c
 * @author    RCorvial
 * @date      February
 * 
 * @brief     802.11 Beacon Sniffer
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <endian.h>      // For changing radiotap fields from little endian to host byte order

#define IEEE80211_RADIOTAP_EXT 31  // Bit that indicates if there is another group of present flags

/* 
 * This struct is the RadioTap header: https://radiotap.org
 * The Radiotap headers are added by the wireless adapter (or its driver) that is being 
 * used to perform the frame capture
 */
struct radiotap_header {
  u_int8_t        it_version;     /* Allways is 0 */
  u_int8_t        it_pad;         /* Allways is 0 */
  u_int16_t       it_len;         /* Radiotap length */
  u_int32_t       it_present;     /* Fields present */
} __attribute__((__packed__));

/**
 * @brief    Packet handler
 */
void packetParser(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  // All fields contained in the Radiotap Header are stored little-endian (use le16toh and le32toh to convert them)
  struct radiotap_header *rtaphdr = (struct radiotap_header *)packet;
  u_int16_t radiotap_len = le16toh(rtaphdr->it_len);    // Size of Radiotap Header
  
  /* 
   * Extract the number of groups of flags included in the Radiotap Header.
   *
   * The flags will vary depending on the information that can be provided by the NIC card that is performing the capture.
   * (http://wifinigel.blogspot.com.es/2013/11/what-are-radiotap-headers.html)
   *
   * You also have to keep in mind that the arguments of the Radiotap Header must be aligned to a boundary of the argument 
   * size using padding. So an u16 argument must start on the next u16 boundary if it isn't already on one, an u32 must start 
   * on the next u32 boundary and so on. (https://www.kernel.org/doc/Documentation/networking/radiotap-headers.txt)
   */
  int i = 0;
  while (le32toh(*(&rtaphdr->it_present+i)) & (1<<IEEE80211_RADIOTAP_EXT))  // If bit 31 (IEEE80211_RADIOTAP_EXT) of the present flags
    i++;                                                                      // is '1', there is another group of present flags
  int nr_present_flags = 1+i;
  if ((nr_present_flags % 2) == 0)
    nr_present_flags++;
  
  // DEBUG
  //fprintf(stdout, "Radiotap it_version: %u\nRadiotap it_pad: %u\nRadiotap it_len: %u\nRadiotap it_present: %u\n", 
  //                  rtaphdr->it_version, rtaphdr->it_pad, le16toh(rtaphdr->it_len), le32toh(rtaphdr->it_present));
  //fprintf(stdout, "Number of flags: %d (Bytes: %d)\n", nr_present_flags, 4*nr_present_flags);
  //fprintf(stdout, "Radiotap length: %u bytes\n", radiotap_len);

  const u_char *channel   = packet + 4*nr_present_flags + 14;   // Frequency (in MHz) of the AP Radio (2 bytes) (In the Radiotap)
  const u_char *rssi      = packet + 4*nr_present_flags + 18;   // This value is subtracted from 256 to get -X Dbm (1 byte) (In the Radiotap)
  
  const u_char *bssid     = packet + radiotap_len + 16;         // Radiotap Lengh (radiotap_len) + Type/Subtype (0.5) + Frame Control (1.5) +
                                                                // Duration (2) + Receiver Address (6) + Transmitter Address (6)
  const u_char *essidLen  = packet + radiotap_len + 37;         // Radiotap Lengh (radiotap_len) + Type/Subtype (0.5) + Frame Control (1.5) +
                                                                // Duration (2) + Receiver Address (6) + Transmitter Address (6) + BSSID (6) +
                                                                // Sequence Number (2) + Timestamp (8) + Beacon Interval (2) + Inmediate Block ACK (2) +
                                                                // Tag Number (1)
  const u_char *essid     = packet + radiotap_len + 38;         // Radiotap Lengh (radiotap_len) + Type/Subtype (0.5) + Frame Control (1.5) +
                                                                // Duration (2) + Receiver Address (6) + Transmitter Address (6) + BSSID (6) +
                                                                // Sequence Number (2) + Timestamp (8) + Beacon Interval (2) + Inmediate Block ACK (2) +
                                                                // Tag Number (1) + Tag Lengh (1)

  // 87 bytes offset contains the "channel number" as per 802.11, e.g. 2412 = "channel 11"
  int channelFreq = le16toh(*(u_int16_t *)channel);
  int rssiDbm = le16toh(*(u_int16_t *)rssi) - 256;
  
  int ssidLen = *(u_int8_t *)essidLen;
  char *ssid = malloc(32); // 32 byte limit (see Standard 802.11)
  i = 0;
  while (i < ssidLen)
  {
    // DEBUG
    //fprintf(stdout, "Hex byte: %x\n", essid[i]); // view byte
    //fprintf(stdout, "Hex char: %c\n", essid[i]); // view ASCII
    ssid[i] = essid[i]; // Store the ESSID bytes in ssid
    i++;
  }
  ssid[i] = '\0'; // Terminate the string

  // Print information
  fprintf( stdout, "Channel Frequency: %u Mhz\n", channelFreq );
  fprintf( stdout, "RSSI: %d dBm\n", rssiDbm );
  fprintf( stdout, "BSSID: %02X:%02X:%02X:%02X:%02X:%02X\n", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5] );
  fprintf( stdout, "ESSID length: %i bytes\n", ssidLen);
  fprintf( stdout, "ESSID string: %s\n", ssid);

  // Write the beacon to a file
  pcap_dumper_t *outputFile;
  pcap_t *fileHandle;
  char *outputFileName = "beacon_sniffed.cap";
  fileHandle = pcap_open_dead( DLT_IEEE802_11_RADIO, BUFSIZ );
  outputFile = pcap_dump_open( fileHandle, outputFileName );
  pcap_dump( (u_char *)outputFile, header, packet );
  pcap_close( fileHandle );
}

int main(int argc, char **argv)
{
  int error = 0;

  if (argc != 2) {
    fprintf(stderr, "Usage: ./beacon-sniffer DeviceName\n");
    error = 1;
  } else {
    char errbuf[PCAP_ERRBUF_SIZE];            // For errors (required by libpcap)
    char *dev = argv[1];                      // Get wlan device from command line
    pcap_t *pcap_handle;
    char *filter = "type mgt subtype beacon"; // Filter beacon frames WLAN
    struct bpf_program fp;
    bpf_u_int32 netp;                         // Berkley Packet Filter

    // DEBUG
    //fprintf(stdout, "%s\n", pcap_lib_version());
    //fprintf(stdout, "Device: %s\n", dev);

    pcap_handle = pcap_open_live( dev, BUFSIZ, 0, 3000, errbuf );
    //pcap_handle = pcap_open_offline("beacon_sniffed.cap", errbuf);
    if(pcap_handle == NULL) {
      fprintf(stderr, "Error open Libpcap sniffer: %s\n", errbuf);
      error = 1;
      goto end;
    }

    // DEBUG
    //fprintf(stdout, "Type: %d\n", pcap_datalink(pcap_handle));

    if(pcap_compile(pcap_handle, &fp, filter, 0, netp) == -1) {
      fprintf(stderr, "Error compiling Libpcap filter (%s)\n", filter);
      error = 1;
      goto end;
    }

    if(pcap_setfilter(pcap_handle, &fp) == -1) {
      fprintf(stderr, "Error setting Libpcap filter (%s)\n", filter);
      error = 1;
      goto end;
    }

    pcap_dispatch(pcap_handle, 1, packetParser, NULL);
    //pcap_loop(pcap_handle, -1, packetParser, NULL);
    
    pcap_freecode(&fp);
    pcap_close(pcap_handle);
  }

end:
  return error;
}