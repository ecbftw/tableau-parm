/*
 * A utility to read information from Tableau, LLC forensics bridges
 * via proprietary SCSI commands.  Specifically, this tool queries for 
 * any detected HPA/DCO settings on connected (S)ATA drives.
 * 
 * This program was possible due to documentation provided by 
 * Tableau, LLC. (http://www.tableau.com/)
 *
 * Copyright (C) 2007 Timothy D. Morgan
 * Copyright (C) 1999 D. Gilbert
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  
 *
 * $Id: $
 */


#include <sys/ioctl.h>
#include <sys/types.h>
#include <scsi/sg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>


#define TABLEAU_HEADER_LEN 120
#define TABLEAU_HPADCO_PAGE_LEN 32
#define TABLEAU_RESPONSE_SIG 0x0ECC

void usage()
{
  printf("ERROR: Requires exactly one argument.\n");
}

void bailOut(int code, char* message)
{
  fprintf(stderr, message);
  exit(code);
}


/* Returns a newly malloc()ed string which contains original buffer,
 * except for non-printable or special characters are quoted in hex
 * with the syntax '\xQQ' where QQ is the hex ascii value of the quoted
 * character.  A null terminator is added, since only ascii, not binary,
 * is returned.
 */
static char* quote_buffer(const unsigned char* str, 
                          unsigned int len, const char* special)
{
  unsigned int i, added_len;
  unsigned int num_written = 0;

  unsigned int buf_len = sizeof(char)*(len+1);
  char* ret_val = malloc(buf_len);
  char* tmp_buf;

  if(ret_val == NULL)
    return NULL;

  for(i=0; i<len; i++)
  {
    if(buf_len <= (num_written+5))
    {
      /* Expand the buffer by the memory consumption rate seen so far 
       * times the amount of input left to process.  The expansion is bounded 
       * below by a minimum safety increase, and above by the maximum possible 
       * output string length.  This should minimize both the number of 
       * reallocs() and the amount of wasted memory.
       */
      added_len = (len-i)*num_written/(i+1);
      if((buf_len+added_len) > (len*4+1))
        buf_len = len*4+1;
      else
      {
        if (added_len < 5)
          buf_len += 5;
        else
          buf_len += added_len;
      }

      tmp_buf = realloc(ret_val, buf_len);
      if(tmp_buf == NULL)
      {
        free(ret_val);
        return NULL;
      }
      ret_val = tmp_buf;
    }
    
    if(str[i] < 32 || str[i] > 126 || strchr(special, str[i]) != NULL)
    {
      num_written += snprintf(ret_val + num_written, buf_len - num_written,
                              "\\x%.2X", str[i]);
    }
    else
      ret_val[num_written++] = str[i];
  }
  ret_val[num_written] = '\0';

  return ret_val;
}


char* convertStringField(const char* f, unsigned short flen)
{
  int i;
  for(i=flen-1; (i >= 0) && (f[i] == ' '); i--)
    continue;

  return quote_buffer(f, i+1, "");
}


int main(int argc, char** argv)
{
  const unsigned char sense_len = 64;
  const unsigned char recv_len = TABLEAU_HEADER_LEN+TABLEAU_HPADCO_PAGE_LEN;
  const unsigned char* chan_type_map[4] = {"IDE/ATA", "SATA", "SCSI", "USB"};
  unsigned int i, j;
  int sg_fd;
  struct sg_io_hdr io_hdr;
  char* dev_file;
  unsigned char sense_b[sense_len];
  unsigned char recv_b[recv_len];
  unsigned char tableau_cmd_blk[] = {0xec, 0, 0, 0, recv_len, 0};

  /* response fields
  /*  common header fields */
  unsigned char res_len;
  unsigned short res_sig;
  unsigned char chan_index;
  unsigned char chan_type;
  bool writes_permitted;
  bool declare_write_blocked;
  bool declare_write_errors;

  char* bridge_serial;
  char* bridge_vendor;
  char* bridge_model;
  char* firmware_date;
  char* firmware_time;
  char* drive_vendor;
  char* drive_model;
  char* drive_serial;
  char* drive_revision;

  /*  HPA/DCO page fields */
  unsigned char page_id;
  unsigned char page_len;
  bool security_in_use;
  bool security_support;
  bool hpa_in_use;
  bool hpa_support;
  bool dco_in_use;
  bool dco_support;
  /* XXX: is this user capacity, or real capacity? */
  unsigned int drive_capacity;
  unsigned int hpa_capacity;
  unsigned int dco_capacity;
  

  if(argc != 2)
  {
    usage();
    exit(1);
  }
  dev_file = argv[1];

  /* XXX: What if this isn't a tableau device?
   *      Can we detect this before we query? 
   */
  memset(sense_b, 0, sense_len);
  memset(recv_b, 0, recv_len);
  memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
  io_hdr.interface_id = 'S';
  io_hdr.cmdp = tableau_cmd_blk;
  io_hdr.cmd_len = sizeof(tableau_cmd_blk);
  io_hdr.sbp = sense_b;
  io_hdr.mx_sb_len = sense_len;
  io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
  io_hdr.dxferp = recv_b;
  io_hdr.dxfer_len = recv_len;
  io_hdr.timeout = 30000; /* 30 sec */

  sg_fd = open(dev_file, O_RDONLY);
  if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) 
  {
    perror("ioctl failed");
    bailOut(3, "ERROR: Could not query device.\n");
  }
  close(sg_fd);

  /*
  j = 0;
  for(i = 0; i < recv_len; i++)
  {
    printf(" %.2X", recv_b[i]);
    if((j %= 16) == 15)
      printf("\n");
    j++;
  }
  printf("\n");
  */  

  res_len = recv_b[1];
  res_sig = (recv_b[2]<<8) | recv_b[3];
  if((res_len != TABLEAU_HEADER_LEN) 
     && (res_len != TABLEAU_HEADER_LEN+TABLEAU_HPADCO_PAGE_LEN))
    bailOut(2, "ERROR: Response length not valid for any known response.\n");

  if(res_sig != TABLEAU_RESPONSE_SIG)
    bailOut(2, "ERROR: Response signature mismatch.\n");
  
  printf("## Bridge Information ##\n");

  chan_index = (recv_b[6] >> 4) & 0x0F;
  chan_type = recv_b[6] & 0x0F;

  printf("chan_index: 0x%.2X\n", chan_index);
  printf("chan_type: %s\n", chan_type_map[chan_type]);
  
  writes_permitted = (recv_b[7] & 0x02) ? true : false;
  declare_write_blocked = (recv_b[7] & 0x04) ? true : false;
  declare_write_errors = (recv_b[7] & 0x08) ? true : false;

  printf("writes_permitted: %s\n", writes_permitted ? "TRUE" : "FALSE");
  printf("declare_write_blocked: %s\n", declare_write_blocked ? "TRUE" : "FALSE");
  printf("declare_write_errors: %s\n", declare_write_blocked ? "TRUE" : "FALSE");
  
  printf("bridge_serial: ");
  for (i=0; i < 8; i++)
    printf("%.2X", recv_b[8+i]);
  printf("\n");
  
  bridge_vendor = convertStringField(recv_b+16, 8);
  printf("bridge_vendor: %s\n", bridge_vendor);
  free(bridge_vendor);
  
  bridge_model = convertStringField(recv_b+24, 8);
  printf("bridge_model: %s\n", bridge_model);
  free(bridge_model);
  
  firmware_date = convertStringField(recv_b+32, 12);
  printf("firmware_date: %s\n", firmware_date);
  free(firmware_date);
  
  firmware_time = convertStringField(recv_b+44, 12);
  printf("firmware_time: %s\n", firmware_time);
  free(firmware_time);
  
  printf("\n## Drive Information ##\n");

  drive_vendor = convertStringField(recv_b+56, 8);
  printf("drive_vendor: %s\n", drive_vendor);
  free(drive_vendor);
  
  drive_model = convertStringField(recv_b+64, 28);
  printf("drive_model: %s\n", drive_model);
  free(drive_model);
  
  drive_serial = convertStringField(recv_b+92, 20);
  printf("drive_serial: %s\n", drive_serial);
  free(drive_serial);
  
  drive_revision = convertStringField(recv_b+112, 8);
  printf("drive_revision: %s\n", drive_revision);
  free(drive_revision);

  if(res_len == TABLEAU_HEADER_LEN+TABLEAU_HPADCO_PAGE_LEN)
  { /* HPA/DCO page is available */
    printf("\n## Drive HPA/DCO/Security Information ##\n");
    page_id = recv_b[TABLEAU_HEADER_LEN];
    if(page_id != 0)
    {
      fprintf(stderr, "ERROR: Expected HPA/DCO page, but "
	      "found page_id=0x%X instead.\n", page_id);
      bailOut(4, "ERROR: Not attempting to parse additional page.\n");
    }
    
    page_len = recv_b[TABLEAU_HEADER_LEN+1];
    if(page_len != TABLEAU_HPADCO_PAGE_LEN)
    {
      fprintf(stderr, "ERROR: HPA/DCO page does not have expected "
	      "length (0x%X).\n", page_len);
      bailOut(4, "ERROR: Not attempting to parse additional page.\n");      
    }

    security_in_use = (recv_b[TABLEAU_HEADER_LEN+2] & 0x20) ? true : false;
    security_support = (recv_b[TABLEAU_HEADER_LEN+2] & 0x10) ? true : false;
    hpa_in_use = (recv_b[TABLEAU_HEADER_LEN+2] & 0x08) ? true : false;
    hpa_support = (recv_b[TABLEAU_HEADER_LEN+2] & 0x04) ? true : false;
    dco_in_use = (recv_b[TABLEAU_HEADER_LEN+2] & 0x02) ? true : false;
    dco_support = (recv_b[TABLEAU_HEADER_LEN+2] & 0x01) ? true : false;

    printf("security_in_use: %s\n", security_in_use ? "TRUE" : "FALSE");
    printf("security_support: %s\n", security_support ? "TRUE" : "FALSE");
    printf("hpa_in_use: %s\n", security_in_use ? "TRUE" : "FALSE");
    printf("hpa_support: %s\n", security_support ? "TRUE" : "FALSE");
    printf("dco_in_use: %s\n", security_in_use ? "TRUE" : "FALSE");
    printf("dco_support: %s\n", security_support ? "TRUE" : "FALSE");

    drive_capacity = (recv_b[TABLEAU_HEADER_LEN+8] << 24)
      | (recv_b[TABLEAU_HEADER_LEN+9] << 16)
      | (recv_b[TABLEAU_HEADER_LEN+10] << 8)
      | recv_b[TABLEAU_HEADER_LEN+11];
    printf("drive_capacity: %u\n", drive_capacity);
    
    if(hpa_support && hpa_in_use)
    {
      hpa_capacity = (recv_b[TABLEAU_HEADER_LEN+16] << 24)
	| (recv_b[TABLEAU_HEADER_LEN+17] << 16)
	| (recv_b[TABLEAU_HEADER_LEN+18] << 8)
	| recv_b[TABLEAU_HEADER_LEN+19];
      printf("hpa_capacity: %u\n", hpa_capacity);
    }

    if(dco_support && dco_in_use)
    {
      dco_capacity = (recv_b[TABLEAU_HEADER_LEN+24] << 24)
	| (recv_b[TABLEAU_HEADER_LEN+25] << 16)
	| (recv_b[TABLEAU_HEADER_LEN+26] << 8)
	| recv_b[TABLEAU_HEADER_LEN+27];
      printf("dco_capacity: %u\n", dco_capacity);
    }
  }
  return 0;
}
