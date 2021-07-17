#pragma once
#include <cpr/cpr.h>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <string.h>
#include <time.h>
#include <vector>
/*
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
*/
struct Block {
  std::string uidHash, pubKeyHash;
  char vote;
  time_t timestamp;
};

class Data {
public:
  Block b, *block = &b;
  std::string pKey = "";
  const char *candidates[6] = {"XYZ", "ZYW", "LOL", "PQR", "CAT", "NOTA"};
  void getUidHash(std::string key);
  void getVote();
  void getTimestamp();
  void getPubKeyhash();
  std::string sha256(std::string str);
  void displayBlock();
};

class DvsClient : public Data {
public:
  std::vector<std::pair<std::string, unsigned short>> nodeAddr;
  void getNodeAddress();
  std::string getPriKey();
  RSA *createRSA(unsigned char *key);
  void encryptBlock();
  void sendData(std::string msg);
};
