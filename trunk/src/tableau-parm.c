/*
 * A utility to read information from Tableau, LLC forensics bridges
 * via proprietary SCSI commands.  Specifically, this tool queries for 
 * any detected HPA/DCO settings on connected (S)ATA drives.
 * 
 * This program was only possible due to documentation and support
 * provided by Tableau, LLC. (http://www.tableau.com/)  Tableau does not
 * endorse or warrant this software in any way.
 *
 * Copyright (C) 2007,2009 Timothy D. Morgan
 * Copyright (C) 1999,2001,2006,2007 D. Gilbert
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License,
 * version 3, along with this program.  If not, see:
 *   http://www.gnu.org/licenses/.
 *
 * $Id$
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <scsi/sg_lib.h>
#include <scsi/sg_pt.h>

#define TABLEAU_SCSI_CMD 0xEC
#define TABLEAU_HEADER_LEN 120
#define TABLEAU_HPADCO_PAGE_LEN 32
#define TABLEAU_RESPONSE_SIG 0x0ECC

#define SENSE_LEN 64
#define RECV_LEN 255
#define CMD_TIMEOUT_SECS 20

void usage()
{
  fprintf(stderr, "Usage: tableau-parm [-r] <DEVICE>\n");
  fprintf(stderr, "Version: 0.2.0\n\n");
  fprintf(stderr, "\tDEVICE\t\tA SCSI block device, such as /dev/sd?\n\n");
  fprintf(stderr, "\t-r\t\tRemoves DCO (and possibly HPA) from the device.\n");
  fprintf(stderr, "\t\t\tTHIS WILL MODIFY THE STATE OF THE DEVICE!!\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "Copyright (C) 2007,2009 Timothy D. Morgan\n");
  fprintf(stderr, "Copyright (C) 1999,2001,2006,2007 D. Gilbert\n\n");
  fprintf(stderr, "This program comes with ABSOLUTELY NO WARRANTY.\n");
  fprintf(stderr, "This is free software, and you are welcome to redistribute it\n");
  fprintf(stderr, "under the conditions of the GNU Public License, version 3.\n");
  fprintf(stderr, "For more information, see the LICENSE file included in this\n");
  fprintf(stderr, "software distribution, or http://www.gnu.org/licenses/.\n\n");
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


/* Trims spaces off of string fields and quotes any non-printables. */
char* convertStringField(const unsigned char* f, unsigned short flen)
{
  int i;
  for(i=flen-1; (i >= 0) && (f[i] == ' '); i--)
    continue;

  return quote_buffer(f, i+1, "");
}


/* Returns the DCO challenge key, if a DCO is set, otherwise returns 0. */
const unsigned char* printQueryResponse(const unsigned char* recv_b)
{
  unsigned int i;
  unsigned char next_page_off = 0;
  const unsigned char* ret_val = NULL;
  const char* chan_type_map[4] = {"IDE/ATA", "SATA", "SCSI", "USB"};

  /* response fields */
  /*  common header fields */
  unsigned char res_len;
  unsigned short res_sig;
  unsigned char chan_index;
  unsigned char chan_type;
  bool writes_permitted;
  bool declare_write_blocked;
  bool declare_write_errors;

  /*char* bridge_serial;*/
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
  bool security_in_use, security_support;
  bool hpa_in_use, hpa_support;
  bool dco_in_use, dco_support;
  unsigned char hpa_disable_err_code;
  /*   this is user capacity */
  unsigned int drive_capacity;
  unsigned int hpa_capacity;
  /*   this is real capacity */
  unsigned int dco_capacity;
  
  /*  
  printf("DEBUG: Response data:");
  for(i = 0; i < RECV_LEN; i++)
  {
    if((i % 16) == 0)
      printf("\n");
    printf(" %.2X", recv_b[i]);
  }
  printf("\n");
  */

  res_len = recv_b[1];
  if (res_len < TABLEAU_HEADER_LEN)
    bailOut(2, "ERROR: Response length not valid for any known response.\n");

  res_sig = (recv_b[2]<<8) | recv_b[3];
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

  next_page_off = TABLEAU_HEADER_LEN;
  /* This is more like an if statement, but later additional 
   * optional pages may be added to Tableau firmwares.
   */
  while (next_page_off < res_len)
  {
    /* Make sure we can read the id and length of next page */
    if(next_page_off+2 > res_len)
    {
      fprintf(stderr, "ERROR: Next page exists, but not large"
	      " enough to be valid.\n");
      bailOut(4, "ERROR: Not attempting to parse additional page.\n");
    }

    page_id = recv_b[next_page_off];
    page_len = recv_b[next_page_off+1];

    switch (page_id)
    {
    case 0x00:
      /* HPA/DCO page */
      printf("\n## Drive HPA/DCO/Security Information ##\n");
      if(page_len != TABLEAU_HPADCO_PAGE_LEN)
      {
	fprintf(stderr, "ERROR: HPA/DCO page does not have expected "
		"length (0x%X).\n", page_len);
	bailOut(4, "ERROR: Not attempting to parse additional page.\n");      
      }
      
      security_in_use = (recv_b[next_page_off+2] & 0x20) ? true : false;
      security_support = (recv_b[next_page_off+2] & 0x10) ? true : false;
      dco_in_use = (recv_b[next_page_off+2] & 0x08) ? true : false;
      dco_support = (recv_b[next_page_off+2] & 0x04) ? true : false;
      hpa_in_use = (recv_b[next_page_off+2] & 0x02) ? true : false;
      hpa_support = (recv_b[next_page_off+2] & 0x01) ? true : false;
      
      hpa_disable_err_code = recv_b[next_page_off+3] & 0x0F;
      
      printf("security_in_use: %s\n", security_in_use ? "TRUE" : "FALSE");
      printf("security_support: %s\n", security_support ? "TRUE" : "FALSE");
      printf("hpa_in_use: %s\n", hpa_in_use ? "TRUE" : "FALSE");
      printf("hpa_support: %s\n", hpa_support ? "TRUE" : "FALSE");
      printf("dco_in_use: %s\n", dco_in_use ? "TRUE" : "FALSE");
      printf("dco_support: %s\n", dco_support ? "TRUE" : "FALSE");
      
      drive_capacity = (recv_b[next_page_off+8] << 24)
	| (recv_b[next_page_off+9] << 16)
	| (recv_b[next_page_off+10] << 8)
	| recv_b[next_page_off+11];
      printf("drive_capacity: %u\n", drive_capacity);
      
      hpa_capacity = (recv_b[next_page_off+16] << 24)
	| (recv_b[next_page_off+17] << 16)
	| (recv_b[next_page_off+18] << 8)
	| recv_b[next_page_off+19];
      printf("hpa_capacity: %u\n", hpa_capacity);
      
      dco_capacity = (recv_b[next_page_off+24] << 24)
	| (recv_b[next_page_off+25] << 16)
	| (recv_b[next_page_off+26] << 8)
	| recv_b[next_page_off+27];
      printf("dco_capacity: %u\n", dco_capacity);

      if(dco_capacity != hpa_capacity)
	ret_val = recv_b+(next_page_off+28);
      
      if(hpa_disable_err_code != 0)
	fprintf(stderr, "WARNING: HPA section could not be automatically, "
		"temporarily disabled!  Error code: %d\n",hpa_disable_err_code);
      break;

    default:
      /* Unknown page */
      fprintf(stderr, 
	      "ERROR: Encountered unknown info page (0x%.2X).", page_id);
      bailOut(4, "ERROR: Not attempting to parse additional page.\n");      
    }
    next_page_off += page_len;
  }

  return ret_val;
}


int sendCommand(int sg_fd, 
		unsigned char* cmd_block, unsigned int cmd_block_len,
		unsigned char* recv_b, unsigned int recv_len,
		unsigned char* sense_b, unsigned int sense_len)
{
  
  int res, resid, cat, got, slen;
  char err_b[512];
  int verbose = 1;
  struct sg_pt_base* ptvp;
  
  memset(recv_b, 0, recv_len);
  memset(sense_b, 0, sense_len);
  
  ptvp = construct_scsi_pt_obj();     /* one object per command */
  if (NULL == ptvp) 
  {
    fprintf(stderr, "ERROR: construct_scsi_pt_obj failed. "
	            "Memory allocation failure likely.\n");
    return -1;
  }

  set_scsi_pt_cdb(ptvp, cmd_block, cmd_block_len);
  set_scsi_pt_sense(ptvp, sense_b, sense_len);
  set_scsi_pt_data_in(ptvp, recv_b, recv_len);
  res = do_scsi_pt(ptvp, sg_fd, CMD_TIMEOUT_SECS, 0);
  if (res < 0)
  {
    fprintf(stderr, "ERROR: do_scsi_pt returned: %s\n", strerror(-res));
    goto error;
  }
  
  if (SCSI_PT_DO_BAD_PARAMS == res)
  {
    fprintf(stderr, "ERROR: do_scsi_pt returned SCSI_PT_DO_BAD_PARAMS.\n");
    goto error;
  }

  if (SCSI_PT_DO_TIMEOUT == res)
  {
    fprintf(stderr, "ERROR: do_scsi_pt returned SCSI_PT_DO_TIMEOUT.\n");
    goto error;
  }

  resid = get_scsi_pt_resid(ptvp);
  switch ((cat = get_scsi_pt_result_category(ptvp))) 
  {
  case SCSI_PT_RESULT_GOOD:
    got = recv_len - resid;
    if (verbose && (resid > 0))
      fprintf(stderr, "WARNING: Requested %d bytes but "
	      "got %d bytes)\n", recv_len, got);
    break;
    
  case SCSI_PT_RESULT_STATUS: /* other than GOOD and CHECK CONDITION */
    if (verbose) {
      sg_get_scsi_status_str(get_scsi_pt_status_response(ptvp),
			     sizeof(err_b), err_b);
      fprintf(stderr, "INFO: SCSI status: %s\n", err_b);
    }
    break;
    
  case SCSI_PT_RESULT_SENSE:
    if (verbose) 
    {
      slen = get_scsi_pt_sense_len(ptvp);
      sg_get_sense_str("", sense_b, slen, 1,
		       sizeof(err_b), err_b);
      fprintf(stderr, "INFO: Sense string: %s\n", err_b);
      
      if(resid > 0)
      {
	got = recv_len - resid;
	if (got > 0)
	  fprintf(stderr, "WARNING: Requested %d bytes but "
		  "got %d bytes\n", recv_len, got);
      }
    }
    break;
    
  case SCSI_PT_RESULT_TRANSPORT_ERR:
    if (verbose) {
      get_scsi_pt_transport_err_str(ptvp, sizeof(err_b), err_b);
      fprintf(stderr, "INFO: Transport: %s\n", err_b);
    }
    break;
    
  case SCSI_PT_RESULT_OS_ERR:
    if (verbose) {
      get_scsi_pt_os_err_str(ptvp, sizeof(err_b), err_b);
      fprintf(stderr, "INFO: os: %s\n", err_b);
    }
    break;
    
  default:
    fprintf(stderr, "ERROR: Unknown pass through result "
	    "category (%d)\n", cat);
    break;
  }

  destruct_scsi_pt_obj(ptvp);
  return 0;

 error:
  destruct_scsi_pt_obj(ptvp);
  return 1;
}


int main(int argc, char** argv)
{
  int sg_fd, cmd_ret;
  char* dev_file;
  bool remove_dco = false;
  unsigned char recv_b[RECV_LEN];
  unsigned char sense_b[SENSE_LEN];
  unsigned char tableau_query_cmd[] = {TABLEAU_SCSI_CMD, 0, 0, 0, RECV_LEN, 0};
  const unsigned char* dco_challenge_key;
  unsigned char tableau_dco_restore_cmd[] = {TABLEAU_SCSI_CMD, 0, 1, 0, 0, 
					     0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0};

  if(argc < 2 || argc > 3)
  {
    fprintf(stderr, "ERROR: Wrong number of arguments.\n");
    usage();
    exit(1);
  }

  if (strcmp(argv[1], "-r") == 0)
  {
    remove_dco = true;
    dev_file = argv[2];
  }
  else
    dev_file = argv[1];

  /* XXX: What if this isn't a tableau device?
   *      Can we detect this before we query? 
   */
  sg_fd = scsi_pt_open_device(dev_file, 0 /* rw */, 0);
  if (sg_fd < 0) {
    fprintf(stderr, "ERROR: scsi_pt_open_device failed on '%s' with: %s\n",
	    dev_file, strerror(-sg_fd));
    return 1;
  }

  cmd_ret = sendCommand(sg_fd, tableau_query_cmd, 6, 
			recv_b, RECV_LEN, sense_b, SENSE_LEN);

  if(cmd_ret != 0)
    bailOut(cmd_ret, "ERROR: Query command failed.\n");    

  dco_challenge_key = printQueryResponse(recv_b);

  if(dco_challenge_key != NULL)
    printf("dco_challenge_key: %.2X %.2X %.2X %.2X\n", 
	   dco_challenge_key[0], dco_challenge_key[1], 
	   dco_challenge_key[2], dco_challenge_key[3]);

  if(remove_dco)
  {
    if(dco_challenge_key != NULL)
    {
      printf("\n## DCO detected, attempting to remove as requested. ##\n");
      tableau_dco_restore_cmd[5] = dco_challenge_key[0];
      tableau_dco_restore_cmd[6] = dco_challenge_key[1];
      tableau_dco_restore_cmd[7] = dco_challenge_key[2];
      tableau_dco_restore_cmd[8] = dco_challenge_key[3];
      
      cmd_ret = sendCommand(sg_fd, tableau_dco_restore_cmd, 12, 
			    recv_b, RECV_LEN, sense_b, SENSE_LEN);

      if(cmd_ret != 0)
	bailOut(cmd_ret, "ERROR: DCO restore command failed.\n");

      
      printf("## DCO removal request returned no errors. ##\n"
	     "## You must now power cycle the drive to detect the changes. ##\n");
    }
    else
      printf("\n## DCO removal requested, but DCO no found! Quitting. ##\n");
  }  
  scsi_pt_close_device(sg_fd);

  return 0;
}
