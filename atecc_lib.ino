/*
 * Copyright (C) 2016-2017 Robert Totte
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifdef USE_WOLFSSL
#include "WolfCryptoAuth.h"
#else
#include "AtCryptoAuthLib.h"
#endif

#ifdef CORE_TEENSY
#include "Entropy.h"
#include "EEPROM.h"
#endif

#include "Readline.h"
#include "Wire.h"

#include <stdio.h>
#include <stdint.h>
#include <ctype.h>

#define AWS_CERT_LENGH_MAX  (1024)

#define ECC_BUFSIZE     256

extern Readline_cmd_list command_list[];

extern "C"
void print_debug(int l, char *s)
{
  Serial.print(l);
  Serial.print(" : ");
  Serial.println(s);
  Serial.flush();
}

static char g_print_buf[80];

#define T_PRINTF(...)    \
{ \
  snprintf(g_print_buf, 80, __VA_ARGS__); \
  Serial.print(g_print_buf); \
}

uint8_t slot_key[ATCA_KEY_SIZE] = {
// new
/*
  0x44,0x95,0x16,0xb9,0xa5,0xe8,0xd9,0x22,
  0xc1,0x4a,0x65,0xbc,0xc8,0x55,0xcf,0x26,
  0x31,0xc2,0x8f,0xa7,0xa2,0x15,0xcc,0x98,
  0x23,0xd0,0x84,0x10,0x46,0x77,0x47,0x23
*/
// old
  0xF9, 0x47, 0x2C, 0xBD, 0x33, 0x1D, 0x51, 0x00,
  0x0C, 0x45, 0x36, 0x34, 0x81, 0x37, 0x2F, 0xD8,
  0x5D, 0x5F, 0xB4, 0xB7, 0x25, 0x21, 0xF8, 0x90,
  0x52, 0xFA, 0xFC, 0x41, 0x02, 0x40, 0xE6, 0xF5,
};
//F9472CBD331D51000C45363481372FD85D5FB4B72521F89052FAFC410240E6F5

extern "C"
void hexdump(const void *buffer, uint32_t len, uint8_t cols)
{
   uint32_t i;

   for(i = 0; i < len + ((len % cols) ? (cols - len % cols) : 0); i++)
   {
      /* print hex data */
      if(i < len) {
        int x = ((uint8_t*)buffer)[i] & 0xFF;
        if (x < 16) Serial.print('0');
        Serial.print(x, HEX);
      }

      if(i % cols == (uint32_t)(cols - 1)) {
         Serial.println("");
      }
   }
}

size_t read_bin_data(uint8_t *data, size_t data_size)
{
  return Readline_read_buf(data, data_size, true);
}

size_t read_certificate(char *data, size_t data_size)
{
  return Readline_read_buf((uint8_t*)data, data_size, false);
}

uint8_t signer_ca_public_key[64] = {
  0xc0,0xd4,0xfd,0x41,0xcc,0x83,0x31,0xe8,
  0x96,0xc9,0xc2,0x96,0x2e,0xf4,0xdc,0x42,
  0xc0,0x69,0x89,0x6d,0x7f,0x52,0x51,0xf5,
  0xcc,0x54,0x66,0x4e,0xa0,0xcb,0xa8,0xa5,
  0x98,0xff,0xa4,0x94,0x91,0x8d,0x21,0x8c,
  0xd5,0xff,0x5e,0xc7,0xa6,0xcf,0x51,0x95,
  0x2f,0x2a,0x05,0x28,0x9c,0x6b,0xd6,0x2f,
  0x20,0x73,0xe6,0x8f,0xde,0xfb,0xbe,0x73
};

#ifdef USE_WOLFSSL
WolfCryptoAuth ecc;
#else
AtCryptoAuthLib ecc;
#endif

#ifdef CORE_TEENSY
void read_eeprom_key(uint8_t *data)
{
  // read first 32 bytes from EEPROM
  int i;
  for (i = 0; i < 32; i++) {
    data[i] = EEPROM.read(i);
  }
}
#endif

void setup()
{
  ATCA_STATUS ret;
  bool lockstate = false;
  bool match = false;
  
#ifdef CORE_TEENSY
  Entropy.Initialize();
#endif

  Serial.begin(115200);

  while (!Serial) { delay(100); }

//  Serial.print((char)0x0c);
  Serial.println("Starting...");
  Serial.flush();

#ifdef CORE_TEENSY
  read_eeprom_key(slot_key);
#endif

#ifdef USE_WOLFSSL
  if (!ecc.crypt_init(slot_key)) {
    Serial.println("ERROR: init");
    Serial.flush();
    while (1) { delay(10000); }
  }
#else
  if (ecc.init(slot_key) != ATCA_SUCCESS) {
    Serial.println("ERROR: init");
    Serial.flush();
    while (1) { delay(10000); }
  }
#endif

  ret = ecc.config_locked(lockstate);
  if (ret != ATCA_SUCCESS) {
    Serial.println("ERROR: config_locked");
    Serial.flush();
    while (1) { delay(10000); }
  }

  if (!lockstate) {
    Serial.println("config_chip start");
    Serial.flush();
    ret = ecc.config_chip(slot_key);
    if (ret != ATCA_SUCCESS) {
      Serial.println("ERROR: config_chip");
      while (1) { delay(10000); }
    }
    Serial.println("config_chip OK");

    ret = ecc.config_locked(lockstate);
    if (ret != ATCA_SUCCESS) {
      Serial.println("ERROR: config_locked 2");
      while (1) { delay(10000); }
    }
    if (!lockstate) {
      Serial.println("ERROR: not locked after config");
      while (1) { delay(10000); }
    }
  }

  ret = ecc.check_config(match);
  if (ret != ATCA_SUCCESS) {
    Serial.println("ERROR: init");
    while (1) { delay(10000); }
  }
  if (!match) {
    uint8_t configdata[ATCA_CONFIG_SIZE] = { 0 };
    Serial.println("config check MISMATCH");
    atcab_read_ecc_config_zone((uint8_t*)configdata);
    hexdump(configdata, ATCA_CONFIG_SIZE, 16);
//    while (1) { delay(10000); }
  } else {
    Serial.println("config check match");
    Serial.println(" ");
  }

  Readline_print_command_list(command_list);
}

void print_help(uint32_t *args, uint32_t num_args)
{
  Readline_print_command_list(command_list);
}

void print_serial(uint32_t *args, uint32_t num_args)
{

}

void print_random(uint32_t *args, uint32_t num_args)
{
  ATCA_STATUS ret;
  uint8_t rand_out[32] = {0};
  Serial.println("Random:");
  Serial.flush();
  ret = ecc.random(rand_out);
  if (ret != ATCA_SUCCESS) {
    Serial.print("ERROR: ramdom ");
    Serial.println(ret);
  }
  hexdump(rand_out, 32, 16);
  Serial.println(" ");
}

void print_slot_len(uint32_t *args, uint32_t num_args)
{
  int slot;

  if (num_args != 1)
    return;

  slot = args[0];

  if ((slot < 0) || (slot > 15)) {
    Serial.print("ERROR: slot_len slot - ");
    Serial.println(slot);
    return;
  }

  size_t sz = ecc.slot_size((AtCryptoAuthLib::SlotCfg)slot);

  Serial.print("slot_len ");
  Serial.print(slot);
  Serial.print(" = ");
  if (ecc.slot_encrypted((AtCryptoAuthLib::SlotCfg)slot)) {
    Serial.print(sz);
    Serial.println(" Encrypted");
  } else {
    Serial.println(sz);
  }
}

bool verif_slot_params(long slot, long start, long len)
{
  if ((slot < 0) || (slot > 15)) {
    return false;
  }
  long sz = ecc.slot_size((AtCryptoAuthLib::SlotCfg)slot);
  if ((start + len) > sz)
    return false;

  return true;
}

void read_slot(uint32_t *args, uint32_t num_args)
{
 // ecc:read(slot,start,len)
  int slot, start, len;

  if (num_args != 3)
    return;

  slot = args[0];
  start = args[1];
  len = args[2];

  Serial.print("read : slot ");
  Serial.print(slot);
  Serial.print(" start ");
  Serial.print(start);
  Serial.print(" len ");
  Serial.println(len);

  if (!verif_slot_params(slot, start, len)) {
    Serial.println("read : ERROR verif_slot_params");
    return;
  }

  ATCA_STATUS ret;
  uint8_t *data = (uint8_t*)malloc(len);
  if (data == NULL) {
    Serial.print("ERROR: malloc ");
    Serial.println(len);
    return;
  }
  memset(data, 0, len);

  ret = ecc.read_slot((AtCryptoAuthLib::SlotCfg)slot, data, start, len);
  if (ret != ATCA_SUCCESS) {
    Serial.print("ERROR: readslot ");
    Serial.println(ret);
  }
  Serial.println("Read Data:");
  hexdump(data, len, 16);

  free(data);
}

void write_slot(uint32_t *args, uint32_t num_args)
{
  uint8_t data[1024];
  int slot, start;
  size_t len;

  if (num_args != 2)
    return;

  slot = args[0];
  start = args[1];

  len = read_bin_data(data, 1024);

  Serial.print("write : slot ");
  Serial.print(slot);
  Serial.print(" start ");
  Serial.print(start);
  Serial.print(" len ");
  Serial.println(len);
  hexdump(data, len, 16);

  if (!verif_slot_params(slot, start, len)) {
    Serial.println("write : ERROR verif_slot_params");
    return;
  }

  ATCA_STATUS ret;
  ret = ecc.write_slot((AtCryptoAuthLib::SlotCfg)slot, data, start, len);
  if (ret != ATCA_SUCCESS) {
    Serial.print("ERROR: write slot ");
    Serial.println(ret);
  }
}

#ifdef USE_WOLFSSL
void gen_csr(uint32_t *args, uint32_t num_args)
{
  WolfCryptoAuth::cert_info ci;
  int slot;
  uint8_t pem[1024];
  char cert_data[8*64];
  size_t tmp_len;
  int pemSz;
  int ret;

  if (num_args != 5)
    return;

  slot = args[0];
  ci.year = args[1];
  ci.mon = args[2];
  ci.day = args[3];
  ci.valid_years = args[4];

  tmp_len = 0;
  Serial.print("country: ");
  Readline_read_str_data(&ci.country,    cert_data, 8*64, &tmp_len);
  Serial.print("state: ");
  Readline_read_str_data(&ci.state,      cert_data, 8*64, &tmp_len);
  Serial.print("locality: ");
  Readline_read_str_data(&ci.locality,   cert_data, 8*64, &tmp_len);
  Serial.print("sur: ");
  Readline_read_str_data(&ci.sur,        cert_data, 8*64, &tmp_len);
  Serial.print("org: ");
  Readline_read_str_data(&ci.org,        cert_data, 8*64, &tmp_len);
  Serial.print("unit: ");
  Readline_read_str_data(&ci.unit,       cert_data, 8*64, &tmp_len);
  Serial.print("commonName: ");
  Readline_read_str_data(&ci.commonName, cert_data, 8*64, &tmp_len);
  Serial.print("email: ");
  Readline_read_str_data(&ci.email,      cert_data, 8*64, &tmp_len);

/*
ssl:csr(1,country, state, locality, sur, org, unit, commonName, email, 2017, 0, 10, 12)
ssl:csr(1,country, state,,,,,,, 2017, 0, 10, 12)
*/

  pemSz = 1024;
  ret = ecc.make_csr((AtCryptoAuthLib::SlotCfg)slot, ci, pem, &pemSz);
  if (ret != 0) {
    Serial.print("make_csr: ");
    Serial.println(ret);
  }
  pem[pemSz] = '\0';
  Serial.println((char*)pem);

  Serial.println("gen_csr : Success!");
}
#endif

uint8_t g_signer_id[2];
atcacert_tm_utc_t  g_issue_date;

void load_signer_cert(uint32_t *args, uint32_t num_args)
{
  char pem_cert[1024];
  size_t  pem_cert_len;
  uint8_t tbs_data[ATCA_SHA_DIGEST_SIZE];
  int ret;

  if (num_args != 3)
    return;

  memset(&g_issue_date, 0, sizeof(g_issue_date));
  g_issue_date.tm_year = args[0];
  g_issue_date.tm_mon = args[1];
  g_issue_date.tm_mday = args[2];

// atcacert_tm_utc_t *atcacert_gmtime32(const uint32_t *posix_time, atcacert_tm_utc_t *result)

  pem_cert_len = read_certificate(pem_cert, 1024);
  if (pem_cert_len == 0)
    return;

  T_PRINTF("issue data: %04d - %02d - %02d\n",
    g_issue_date.tm_year, g_issue_date.tm_mon, g_issue_date.tm_mday);
  g_issue_date.tm_year -= 1900;
/*
  memset(&g_issue_date, 0, sizeof(g_issue_date));
  g_issue_date.tm_year = 2017-1900;
  g_issue_date.tm_mon = 0;
  g_issue_date.tm_mday = 11;
*/
  ret = ecc.provision_load_signer_cert(pem_cert, pem_cert_len, tbs_data, g_signer_id, &g_issue_date);
  if (ret != ATCA_SUCCESS) {
    Serial.print("load_signer_cert : ecc.provision_load_signer_cert ");
    Serial.println(ret);
    return;
  }
  Serial.println("TBS Data:");
  hexdump(tbs_data, ATCA_SHA_DIGEST_SIZE, ATCA_SHA_DIGEST_SIZE*2);
}

void save_signature(uint32_t *args, uint32_t num_args)
{
  int ret;
  size_t len;
  uint8_t cert_signature[64*2+2];

  len = read_bin_data(cert_signature, 64*2+2);
  if (len != ATCA_SIG_SIZE) {
    Serial.print("save_signature : len error ");
    Serial.println(len);
    return;
  }
  hexdump(cert_signature, ATCA_SIG_SIZE, 2*ATCA_SIG_SIZE);
/*
  memset(&g_issue_date, 0, sizeof(g_issue_date));
  g_issue_date.tm_year = 2016-1900;
  g_issue_date.tm_mon = 1;
  g_issue_date.tm_mday = 1;
*/
  ret = ecc.provision_save_signature(cert_signature, g_signer_id, &g_issue_date);
  if (ret != ATCA_SUCCESS) {
    Serial.print("save_signature : ecc.ecc.provision_save_signature ");
    Serial.println(ret);
    return;
  }
  Serial.println("Success!");
}

void get_signer_cert(uint32_t *args, uint32_t num_args)
{
  int ret;
  uint8_t signer_der[1024];
  size_t signer_der_size;
  uint8_t signer_pem[1024];
  size_t signer_pem_size;

  signer_der_size = 1024;
  signer_pem_size = 1024;
  ret = ecc.build_signer_cert(signer_der, &signer_der_size,
      signer_pem, &signer_pem_size);
  if (ret != ATCA_SUCCESS) {
    Serial.print("build_signer_cert ");
    Serial.println(ret);
    return;
  }
  signer_pem[signer_pem_size] = '\0';
  T_PRINTF("Der size %d, Pem size %d\n", signer_der_size, signer_pem_size);
  Serial.println("Signer Cert\n");
  Serial.println((char*)signer_pem);
}

void get_device_cert(uint32_t *args, uint32_t num_args)
{
  int ret;
  uint8_t device_der[1024];
  size_t device_der_size;
  uint8_t device_pem[1024];
  size_t device_pem_size;

  device_der_size = 1024;
  device_pem_size = 1024;
  ret = ecc.build_device_cert(device_der, &device_der_size,
      device_pem, &device_pem_size);
  if (ret != ATCA_SUCCESS) {
    Serial.print("build_device_cert ");
    Serial.println(ret);
    return;
  }
  device_pem[device_pem_size] = '\0';
  T_PRINTF("Der size %d, Pem size %d\n", device_der_size, device_pem_size);
  Serial.println("Device Cert\n");
  Serial.println((char*)device_pem);

}

void sign_data(uint32_t *args, uint32_t num_args)
{
  uint8_t data[32*2+2];
  int slot;
  size_t len;
  ATCA_STATUS ret;
  uint8_t signature[64];

// ecc:sign(slot,data)

  if (num_args != 1)
    return;

  slot = args[0];

  len = read_bin_data(data, 32*2+2);
  if (len != 32) {
    Serial.print("sign len should be 32, got ");
    Serial.println(len);
  }

  ret = ecc.sign((AtCryptoAuthLib::SlotCfg)slot, data, signature);
  if (ret != ATCA_SUCCESS) {
    Serial.print("build_device_cert ");
    Serial.println(ret);
    return;
  }
  Serial.println("Signature:");
  hexdump(signature, 64, 32);
}

void get_pub_key(uint32_t *args, uint32_t num_args)
{
  int slot;
  ATCA_STATUS ret;
  uint8_t pubkey[64] = { 0 };

  if (num_args != 1)
    return;

  slot = args[0];

  ret = ecc.get_pub_key((AtCryptoAuthLib::SlotCfg)slot, pubkey);
  if (ret != ATCA_SUCCESS) {
    Serial.print("build_device_cert ");
    Serial.println(ret);
    return;
  }
  Serial.println("Public Key:");
  hexdump(pubkey, 64, 32);
}

void gen_key(uint32_t *args, uint32_t num_args)
{
  int slot;
  ATCA_STATUS ret;
  uint8_t pubkey[64] = { 0 };

  if (num_args != 1)
    return;

  slot = args[0];

  ret = ecc.gen_key((AtCryptoAuthLib::SlotCfg)slot, pubkey);
  if (ret != ATCA_SUCCESS) {
    Serial.print("ecc.gen_key ");
    Serial.println(ret);
    return;
  }
  Serial.println("Public Key:");
  hexdump(pubkey, 64, 32);
}


#ifdef USE_WOLFSSL
void test_sign(uint32_t *args, uint32_t num_args)
{
  int slot;
  int ret;
  uint8_t pubkey[65] = { 0 };
  uint8_t msg[32] = { 0 };
  RNG rng;
  ecc_key key;
  uint8_t signature[64] = { 0 };
  int stat;
  mp_int    r;
  mp_int    s;
  int start, fin;

  if (num_args != 1)
    return;

  slot = args[0];

  pubkey[0] = 0x04;
  ret = ecc.get_pub_key((AtCryptoAuthLib::SlotCfg)slot, &(pubkey[1]));
  if (ret != ATCA_SUCCESS) {
    Serial.print("ecc.get_pub_key ");
    Serial.println(ret);
    return;
  }
  T_PRINTF("Public Key %d:\n", slot);
  hexdump(&(pubkey[1]), 64, 32);
  Serial.println("");

  start = millis();
  ret = ecc.sign((AtCryptoAuthLib::SlotCfg)slot, msg, signature);
  fin = millis();
  if (ret != ATCA_SUCCESS) {
    Serial.print("ecc.sign ");
    Serial.println(ret);
    return;
  }
  Serial.println("Signature:");
  hexdump(signature, 64, 32);
  T_PRINTF("%d ms\n", fin - start);

// int wc_ecc_verify_hash(const byte* sig, word32 siglen, const byte* hash,
//                        word32 hashlen, int* stat, ecc_key* key)
//  stat        Result of signature, 1==valid, 0==invalid

  wc_InitRng(&rng);

  do {
    wc_ecc_init(&key);

    XMEMSET(&r, 0, sizeof(r));
    XMEMSET(&s, 0, sizeof(s));

    ret = wc_ecc_import_x963(pubkey, 65, &key);
    if (ret != 0) {
      T_PRINTF("ERROR: wc_ecc_import_x963 %d\n", ret);
      break;
    }

    ret = wc_ecc_check_key(&key);
    if (ret != 0) {
      T_PRINTF("ERROR: wc_ecc_check_key %d\n", ret);
      break;
    }

    /* Load R and S */
    ret = mp_read_unsigned_bin(&r, &signature[0], ATCA_KEY_SIZE);
    if (ret != MP_OKAY) {
      T_PRINTF("ERROR: mp_read_unsigned_bin r %d\n", ret);
      break;
    }
    ret = mp_read_unsigned_bin(&s, &signature[ATCA_KEY_SIZE], ATCA_KEY_SIZE);
    if (ret != MP_OKAY) {
      T_PRINTF("ERROR: mp_read_unsigned_bin s %d\n", ret);
      break;
    }
/*
    ret = DecodeECC_DSA_Sig(signature, 64, &r, &s);
    if (ret != 0) {
      T_PRINTF("ERROR: DecodeECC_DSA_Sig %d\n", ret);
      break;
    }
*/
    start = millis();
    ret = wc_ecc_verify_hash_ex(&r, &s, msg, 32, &stat, &key);
    fin = millis();
    if (ret != 0) {
      T_PRINTF("ERROR: wc_ecc_verify_hash_ex %d\n", ret);
      break;
    }

    if (stat) {
      T_PRINTF("Verify SUCCESS!\n");
    } else {
      T_PRINTF("Verify FAIL!\n");
    }
    T_PRINTF("%d ms\n", fin - start);

  } while (0);

  mp_clear(&r);
  mp_clear(&s);

  wc_FreeRng(&rng);
}

void test_verify(uint32_t *args, uint32_t num_args, bool store)
{
  int slot = 0;
  int ret;
  RNG rng;
  ecc_key key;
  uint8_t signature[128] = { 0 };
  word32 slen = 128;
  uint8_t sigRS[ATCA_SIG_SIZE+4];
  uint8_t pubKey[68];
  unsigned int pubKeyLen = sizeof(pubKey);
  bool stat;
  mp_int    r;
  mp_int    s;
  uint8_t msg[32] = { 0 };
  int start, fin;

  if (store) {
    if (num_args != 1)
      return;
    slot = args[0];
  }

// int wc_ecc_sign_hash(const byte* in, word32 inlen, byte* out, word32 *outlen,
//                      WC_RNG* rng, ecc_key* key)

  ret = ecc.random(msg);
  if (ret != ATCA_SUCCESS) {
    Serial.print("ERROR: ramdom ");
    Serial.println(ret);
  }
  Serial.println("Message to sign:");
  hexdump(msg, 32, 16);
  Serial.println("");

  wc_InitRng(&rng);

  do {
    wc_ecc_init(&key);

    Serial.println("Make key...");
    ret = wc_ecc_make_key(&rng, 32, &key);
    if (ret != 0) {
      T_PRINTF("ERROR: wc_ecc_make_key %d\n", ret);
      break;
    }

    ret = wc_ecc_export_x963(&key, pubKey, &pubKeyLen);
    if ((ret != MP_OKAY) || (pubKeyLen != 65)) {
      T_PRINTF("ERROR: wc_ecc_export_x963 len=%d ret=%d\n", pubKeyLen, ret);
      break;
    }

    Serial.println("Sign msg...");
    start = millis();
    ret = wc_ecc_sign_hash(msg, 32, signature, &slen, &rng, &key);
    fin = millis();
    if (ret != 0) {
      T_PRINTF("ERROR: wc_ecc_sign_hash %d\n", ret);
      break;
    }
    T_PRINTF("%d ms\n", fin - start);

    XMEMSET(&r, 0, sizeof(r));
    XMEMSET(&s, 0, sizeof(s));

    ret = DecodeECC_DSA_Sig(signature, slen, &r, &s);
    if (ret != 0) {
      T_PRINTF("ERROR: DecodeECC_DSA_Sig %d\n", ret);
      break;
    }

    if (store) {
      T_PRINTF("Store Public Key %d ...\n", slot);
      hexdump(pubKey+1,64,64);
      // load pubKey+1 to slot
      ret = ecc.write_pub_key((AtCryptoAuthLib::SlotCfg)slot, pubKey+1);
      if (ret != ATCA_SUCCESS) {
        T_PRINTF("ERROR: ecc.write_pub_key %d\n", ret);
        break;
      }
    }

    /* Extract R and S */
    ret = mp_to_unsigned_bin(&r, &sigRS[0]);
    if (ret != MP_OKAY) {
      T_PRINTF("ERROR: mp_to_unsigned_bin r %d\n", ret);
      break;
    }   
    ret = mp_to_unsigned_bin(&s, &sigRS[ATCA_KEY_SIZE]);
    if (ret != MP_OKAY) {
      T_PRINTF("ERROR: mp_to_unsigned_bin s %d\n", ret);
      break;
    }  

    T_PRINTF("Start Verify...\n");

    stat = false;
    if (store) {
/*
      start = millis();
      ret = ecc.verify_stored((AtCryptoAuthLib::SlotCfg)slot, msg, sigRS, stat);
      fin = millis();
      if (ret != ATCA_SUCCESS) {
        T_PRINTF("ERROR: ecc.verify s %d\n", ret);
        break;
      }
*/
    } else {
//      msg[5] ^= 1;
      start = millis();
      ret = ecc.verify(pubKey+1, msg, sigRS, stat);
      fin = millis();
      if (ret != ATCA_SUCCESS) {
        T_PRINTF("ERROR: ecc.verify %d\n", ret);
        break;
      }
    }
    if (stat) {
      T_PRINTF("Verify SUCCESS!\n");
    } else {
      T_PRINTF("Verify FAIL!\n");
    }
    T_PRINTF("%d ms\n", fin - start);

  } while (0);

  wc_FreeRng(&rng);
}

void test_verify_extern(uint32_t *args, uint32_t num_args)
{
  test_verify(args, num_args, false);
}

void test_verify_store(uint32_t *args, uint32_t num_args)
{
//  test_verify(args, num_args, true);

  ATCA_STATUS status;
  bool is_verified = false;
  const uint16_t private_key_id = 2;
  const uint16_t public_key_id = 11;
  uint8_t message[ATCA_KEY_SIZE*2];
  uint8_t signature[ATCA_SIG_SIZE*2];
  uint8_t public_key[72*2];
  
  do {
    // Generate new key pair
    status = atcab_genkey(private_key_id, public_key);
    if (status != ATCA_SUCCESS) {
      T_PRINTF("ERROR: ecc.verify @%d %X\n", __LINE__, status);
      break;
    }
    
    // Reformat public key into padded format
    memmove(&public_key[40], &public_key[32], 32); // Move Y to padded position
    memset(&public_key[36], 0, 4);                 // Add Y padding bytes
    memmove(&public_key[4], &public_key[0], 32);   // Move X to padded position
    memset(&public_key[0], 0, 4);                  // Add X padding bytes
    
    // Write public key to slot
    status = atcab_write_bytes_zone(ATCA_ZONE_DATA, public_key_id, 0, public_key, 72);
    if (status != ATCA_SUCCESS) {
      T_PRINTF("ERROR: ecc.verify @%d %X\n", __LINE__, status);
      break;
    }

    // Generate random message to be signed
    status = atcab_random(message);
    if (status != ATCA_SUCCESS) {
      T_PRINTF("ERROR: ecc.verify @%d %X\n", __LINE__, status);
      break;
    }

    // Sign the message
    status = atcab_sign(private_key_id, message, signature);
    if (status != ATCA_SUCCESS) {
      T_PRINTF("ERROR: ecc.verify @%d %X\n", __LINE__, status);
      break;
    }

    // Verify the signature
    is_verified = false;
    status = atcab_verify_stored(message, signature, public_key_id, &is_verified);
    if (status != ATCA_SUCCESS) {
      T_PRINTF("ERROR: ecc.verify @%d %X\n", __LINE__, status);
      break;
    }
    if (!is_verified) {
      T_PRINTF("ERROR: ecc.verify @%d %X\n", __LINE__, status);
      break;
    }
    
    // Modify message to create failure
    message[0]++;
    
    // Verify with bad message, should fail
    is_verified = false;
    status = atcab_verify_stored(message, signature, public_key_id, &is_verified);
    if (status != ATCA_SUCCESS) {
      T_PRINTF("ERROR: ecc.verify @%d %X\n", __LINE__, status);
      break;
    }
    if (is_verified) {
      T_PRINTF("ERROR: ecc.verify @%d %X\n", __LINE__, status);
      break;
    }

    T_PRINTF("ecc.verify PASS!\n");
  } while (0);

}
#endif

// ecc:hmac_test(slot)
void test_hmac(uint32_t *args, uint32_t num_args)
{
  ATCA_STATUS ret;
  uint8_t msg[96] = { 0 };
  uint8_t digest[64] = { 0 };

  ret = ecc.hmac_start(msg, 32);
  if (ret != ATCA_SUCCESS) {
    T_PRINTF("ERROR: ecc.hmac_start %d\n", ret);
    return;
  }
  ret = ecc.hmac_update(msg, 64);
  if (ret != ATCA_SUCCESS) {
    T_PRINTF("ERROR: ecc.hmac_update %d\n", ret);
    return;
  }
  ret = ecc.hmac_finish(digest);
  if (ret != ATCA_SUCCESS) {
    T_PRINTF("ERROR: ecc.hmac_finish %d\n", ret);
    return;
  }

  T_PRINTF("HMAC success!\n");
  hexdump(digest, 32, 32);
}

#ifdef USE_WOLFSSL
void test_ecdh(uint32_t *args, uint32_t num_args)
{
  int slot;
  int ret;
  RNG rng;
  word32    bufSz;
  ecc_key   myKey;
  ecc_key   myKeyP;
  ecc_key   key;
  uint8_t   pubKey[68] = { 0 };
  uint8_t   peerKey[68] = { 0 };
  uint8_t   preMasterSecret_1[68] = { 0 };
  uint8_t   preMasterSecret_2[68] = { 0 };
  int       r, t_sw=0, t_hw=0;

  if (num_args != 1)
    return;

  slot = args[0];

  memset(peerKey, 0xFF, 68);
  memset(pubKey, 0xFF, 68);
  memset(preMasterSecret_1, 0xFF, 68);
  memset(preMasterSecret_2, 0xFF, 68);

  if (slot != 0) {
    r = millis();
    pubKey[0] = 0x04;
    ret = ecc.gen_key((AtCryptoAuthLib::SlotCfg)slot, &(pubKey[1]));
    if (ret != ATCA_SUCCESS) {
      T_PRINTF("ecc.gen_key %d\n", ret);
      return;
    }
    t_hw += millis() - r;
  } else {
    pubKey[0] = 0x04;
    ret = ecc.get_pub_key((AtCryptoAuthLib::SlotCfg)slot, &(pubKey[1]));
    if (ret != ATCA_SUCCESS) {
      T_PRINTF("ecc.get_pub_key %d\n", ret);
      return;
    }
  }

  T_PRINTF("ecc508 pub:\n");
  hexdump(pubKey+1, 64, 32);

  wc_ecc_init(&key);

  ret = wc_ecc_import_x963(pubKey, 65, &key);
  if (ret != 0) {
    T_PRINTF("ERROR: wc_ecc_import_x963 %d @%d\n", ret, __LINE__);
    return;
  }

  ret = wc_ecc_check_key(&key);
  if (ret != 0) {
    T_PRINTF("ERROR: wc_ecc_check_key %d @%d\n", ret, __LINE__);
    return;
  }

  wc_InitRng(&rng);

  wc_ecc_init(&myKey);
  r = millis();
  ret = wc_ecc_make_key(&rng, 32, &myKey);
  if (ret != 0) {
    T_PRINTF("ERROR: wc_ecc_make_key %d @%d\n", ret, __LINE__);
    return;
  }
  t_sw += millis() - r;

  /* precede export with 1 byte length */
  bufSz = 68;
  ret = wc_ecc_export_x963(&myKey, peerKey, &bufSz);
  if ((ret != 0) || (bufSz != 65)) {
    T_PRINTF("ERROR: wc_ecc_export_x963 %d @%d\n", ret, __LINE__);
    return;
  }
  wc_ecc_init(&myKeyP);
  ret = wc_ecc_import_x963(peerKey, 65, &myKeyP);
  if (ret != 0) {
    T_PRINTF("ERROR: wc_ecc_import_x963 %d @%d\n", ret, __LINE__);
    return;
  }
  ret = wc_ecc_check_key(&myKeyP);
  if (ret != 0) {
    T_PRINTF("ERROR: wc_ecc_check_key %d @%d\n", ret, __LINE__);
    return;
  }
  T_PRINTF("wolf pub:\n");
  hexdump(peerKey, 65, 16);

//int wc_ecc_shared_secret(ecc_key* private_key, ecc_key* public_key,
//          byte* out, word32* outlen)

  r = millis();
  ret = ecc.ecdh(&(peerKey[1]), preMasterSecret_1, (AtCryptoAuthLib::SlotCfg)slot);
  if (ret != ATCA_SUCCESS) {
    T_PRINTF("ecc.ecdh %d\n", ret);
    return;
  }
  t_hw += millis() - r;
  T_PRINTF("Secret ecc508:\n");
  hexdump(preMasterSecret_1, 32, 16);

  bufSz = 68;
  r = millis();
  ret  = wc_ecc_shared_secret(&myKey, &key, preMasterSecret_2, &bufSz);
  if (ret != 0) {
    T_PRINTF("ERROR: wc_ecc_shared_secret %d\n", ret);
    return;
  }
  t_sw += millis() - r;

  T_PRINTF("Secret wolf:\n");
  hexdump(preMasterSecret_2, 32, 16);

  T_PRINTF("Time: HW %d ms, SW %d ms\n", t_hw, t_sw);

  wc_ecc_free(&myKey);
  wc_ecc_free(&key);

  wc_FreeRng(&rng);
}
#endif

void test_cert_chain(uint32_t *args, uint32_t num_args)
{
  uint8_t signerCert[1024];
  size_t  signerCertSize = 1024;
  uint8_t deviceCert[1024];
  size_t  deviceCertSize = 1024;
  bool ret;

  ret = ecc.verify_cert_chain(signer_ca_public_key,
    signerCert, &signerCertSize,
    deviceCert, &deviceCertSize);

  if (ret) {
    Serial.println("Certificate Chain Verify SUCCESS!");
  } else{
    Serial.println("Certificate Chain Verify FAIL!");
  }
}

static const uint8_t g_signer_ca_private_key[36] = {
  0x00, 0x00, 0x00, 0x00,
  0x49, 0x0c, 0x1e, 0x09, 0xe2, 0x40, 0xaf, 0x00,
  0xe9, 0x6b, 0x43, 0x32, 0x92, 0x0e, 0x15, 0x8f,
  0x69, 0x58, 0x8e, 0xd4, 0x25, 0xc7, 0xf6, 0x8b,
  0x0c, 0x6a, 0x52, 0x5d, 0x0d, 0x21, 0x4f, 0xee
};

#ifdef USE_WOLFSSL
void test_load_priv(uint32_t *args, uint32_t num_args)
{
  int ret;
  RNG rng;
  int slot;
  ecc_key key;
  uint8_t priv_key[128] = { 0 };
  unsigned int priv_key_len = sizeof(priv_key);
  uint8_t pubKey[68];
  unsigned int pubKeyLen = sizeof(pubKey);

  if (num_args != 1)
    return;

  slot = args[0];
  if ((slot != 5) && (slot != 6) && (slot != 7)) {
    Serial.println("load_priv only works with slots 5,6,7");
    return;
  }

  wc_InitRng(&rng);

  do {
    wc_ecc_init(&key);

    Serial.println("Make key...");
    ret = wc_ecc_make_key(&rng, 32, &key);
    if (ret != 0) {
      T_PRINTF("ERROR: wc_ecc_make_key %d\n", ret);
      break;
    }

    ret = wc_ecc_export_x963(&key, pubKey, &pubKeyLen);
    if ((ret != MP_OKAY) || (pubKeyLen != 65)) {
      T_PRINTF("ERROR: wc_ecc_export_x963 len=%d ret=%d\n", pubKeyLen, ret);
      break;
    }
    hexdump(pubKey+1, pubKeyLen-1, 32);

    ret = wc_ecc_export_private_only(&key, priv_key, &priv_key_len);
    if ((ret != MP_OKAY) || (priv_key_len != 32)) {
      T_PRINTF("ERROR: wc_ecc_export_private_only len=%d ret=%d\n",
                priv_key_len, ret);
      break;
    }
    T_PRINTF("Priv key...\n");
    hexdump(priv_key, priv_key_len, 32);

    ret = ecc.priv_key_write((AtCryptoAuthLib::SlotCfg)slot, priv_key);
    if (ret != ATCA_SUCCESS) {
      T_PRINTF("ERROR: PrivWrite : ret %d %X\n", ret, ret);
    } else
      T_PRINTF("Slot %d\n", slot);

    T_PRINTF("Done.\n");
  } while (0);

  wc_FreeRng(&rng);
}
#endif

#ifdef USE_EEPROM
#define EEPROM_I2C_ADDR  0x50

static int i2c_eeprom_read(int addr, uint32_t eeaddress,
                            uint8_t *buffer, int length )
{
  size_t ret;
  int rr;

  Wire.beginTransmission(addr);
  ret = Wire.write((int)(eeaddress >> 8)); // MSB
  if (ret != 1) return 101;
  ret = Wire.write((int)(eeaddress & 0xFF)); // LSB
  if (ret != 1) return 102;
  ret = Wire.endTransmission();
  if (ret != 0) return ret;
  ret = Wire.requestFrom(addr,length);
  if (ret == 0) return 103;
  for (int c = 0; c < length; c++ ) {
    if (Wire.available()) {
      rr = Wire.read();
      if (rr < 0) return 104;
      buffer[c] = rr;
    } else {
      return 105;
    }
  }
  return 0;
}

static int i2c_eeprom_write( int addr, uint32_t eeaddr,
                              uint8_t* data, uint8_t length )
{
  size_t ret;
  Wire.beginTransmission(addr);
  ret = Wire.write((int)(eeaddr >> 8)); // MSB
  if (ret != 1) return 201;
  ret = Wire.write((int)(eeaddr & 0xFF)); // LSB
  if (ret != 1) return 202;
  for (uint8_t c = 0; c < length; c++) {
    ret = Wire.write(data[c]);
    if (ret != 1) {
      T_PRINTF("ERROR write %d @%d\n", ret, (int)c);
      return 203;
    }
  }
  ret = Wire.endTransmission();
  if (ret != 0) return ret;

  delay(100);
  return 0;
}

void erase_eeprom(uint32_t *args, uint32_t num_args)
{
  int start, len, i;
  int ret;
  uint8_t buf[32] = { 0 };

  if (num_args != 2)
    return;

  start = args[0];
  len = args[1];

  for (i = 0; i < len; i+= 32) {
    ret = i2c_eeprom_write(EEPROM_I2C_ADDR, start+i, buf,
            ((len >= 32) ? 32 : len));
    T_PRINTF("erase eeprom %d\n", start+i);
    if (ret != 0) {
      T_PRINTF("erase eeprom error: %d\n", ret);
      return;
    }
  }
}

void write_cert_eeprom(uint32_t *args, uint32_t num_args)
{
  int cert_id;
  uint8_t data[1024];
  size_t dsize, i;
  uint16_t wr_start;
  int ret;

  if (num_args != 1)
    return;

  cert_id = args[0];
  if ((cert_id < 1) || (cert_id > 15)) {
    return;
  }
  wr_start = 2048*cert_id;

  dsize = read_certificate((char*)data, 1023);
  for (i = 0; i < dsize; i++) {
    if (data[i] == '\r') {
      data[i] = '\n';
    }
  }
  data[dsize] = '\0';
  dsize++;

  for (i = 0; i < dsize; i += 32) {
    uint8_t l = (((dsize-i) > 32) ? 32 : (dsize-i));
    ret = i2c_eeprom_write(EEPROM_I2C_ADDR, wr_start+i, &(data[i]), l);
    if (ret != 0) {
      T_PRINTF("ERROR i2c_eeprom_write %d @%d\n", ret, i);
      return;
    }
  }
}

void read_cert_eeprom(uint32_t *args, uint32_t num_args)
{
  int cert_id;
  uint8_t data[1024];
  uint16_t wr_start;
  int ret, i, w;

  if (num_args != 1)
    return;

  cert_id = args[0];
  if ((cert_id < 1) || (cert_id > 15)) {
    return;
  }
  wr_start = 2048*cert_id;

  for (i = 0; i < 1024; i += 32) {
    ret = i2c_eeprom_read(EEPROM_I2C_ADDR, wr_start+i, &(data[i]), 32);
    if (ret != 0) {
      T_PRINTF("ERROR i2c_eeprom_read %d @%d\n", ret, i);
      return;
    }
    for (w = 0; w < 32; w++) {
      if (data[i+w] == '\0') {
        Serial.println((char*)data);
/*
      int x, sl;
      char *p;
        sl = strlen((char*)data);
        p = (char *)data;
        for (x = 0; x < sl; x++) {
          if (data[x] == '\r') {
            data[x] = '\0';
            Serial.println(p);
            p = (char *)&(data[x+1]);
          }
        }
*/
        return;
      }
    }
  }
}
#endif

Readline_cmd_list command_list[] = {
  { "help  ", "Print this help", print_help },
  { "sn  ", "Print Serial Number", print_serial },
  { "rand  ", "Gen Random Number", print_random },
  { "gen_key     slot", "Generate private key", gen_key },
  { "get_pub_key slot", "Get slot public key", get_pub_key },
  { "slot_len    slot", "Get slot capacity", print_slot_len },
  { "read        slot start len", "Read from slot", read_slot },
  { "write       slot start  -> data", "Write to slot", write_slot },
  { "sign        slot  -> data", "Sign data (32 bytes)", sign_data },
  { "hmac  ", "Try command", test_hmac},
  { "ldsig  year mon day  -> Signer Cert", "Load Signer Cert", load_signer_cert},
  { "svsig  -> signature", "Save Signature", save_signature},
  { "rdev  ", "Print device cert", get_device_cert},
  { "rsig  ", "Print signer cert", get_signer_cert},
#ifdef USE_WOLFSSL
  { "csr         slot year mon day valid_years -> country state locality sur org unit commonName email",
      "Generate CSR", gen_csr},
  { "test_sign   slot  ", "Sign in HW verify in SW", test_sign},
  { "test_verify_ext  ", "Sign in SW verify in HW", test_verify_extern},
//  { "test_verify  slot", "Sign in SW verify in HW (stored key)", test_verify_store},
  { "ecdh_test   slot", "Try ECDH command", test_ecdh},
  { "load_priv   slot", "Private Key Write", test_load_priv},
#ifdef USE_EEPROM
  { "erase_eeprom  start len", "Erase EEPROM", erase_eeprom},
  { "write_cert_eeprom  ID", "Write EEPROM", write_cert_eeprom},
  { "read_cert_eeprom  ID", "read EEPROM", read_cert_eeprom},
#endif
#endif
  { "verify_chain  ", "Verify Cert Chain (stored)", test_cert_chain},
  { NULL, NULL, NULL }
};

void loop()
{
  String cmd;

  cmd = Readline("atecc> ");

  if (cmd.length() > 0)
    Readline_parse_command(cmd, command_list);

//      print_command_list();

}

extern "C"
void atca_delay_ms(uint32_t d)
{
  delay(d);
}

