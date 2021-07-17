#pragma once
#include "fields_alloc.hpp"
#include "merklecpp.h"
#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <cpr/cpr.h>
#include <forward_list>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <list>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = net::ip::tcp;

struct BLOCK {
  std::string uidHash, pubKeyHash, prevHash;
  char vote;
  time_t timestamp;
};

class Blockchain {
public:
  BLOCK b, *block = &b;
  merkle::Tree tree;
  std::vector<std::pair<std::string, unsigned short>> nodeAddr;
  std::vector<std::pair<std::string, std::string>> mroot;
  std::string pubKey;
  std::forward_list<BLOCK> chain;
  int CheckpubKey(beast::string_view target);
  RSA *createRSA(unsigned char *key);
  int decrypt(beast::string_view target);
  void addBlock(std::string temp);
  void displayBlock();
  void getNodeAddress();
  std::string sha256(std::string str);
  void ledgerLoad();
  void ledgerWrite();
};

typedef std::shared_ptr<Blockchain> Blockchain_ptr;

class DvsNode {
private:
  using alloc_t = fields_alloc<char>;
  using request_body_t = http::string_body;
  tcp::acceptor &acceptor_;
  tcp::socket socket_{acceptor_.get_executor()};
  beast::flat_static_buffer<8192> buffer_;
  alloc_t alloc_{8192};
  boost::optional<http::request_parser<request_body_t, alloc_t>> parser_;
  net::steady_timer request_deadline_{
      acceptor_.get_executor(), (std::chrono::steady_clock::time_point::max)()};
  boost::optional<
      http::response<http::string_body, http::basic_fields<alloc_t>>>
      string_response_;
  boost::optional<
      http::response_serializer<http::string_body, http::basic_fields<alloc_t>>>
      string_serializer_;
  //		boost::optional<http::response<http::file_body,
  //http::basic_fields<alloc_t>>> file_response_;
  //		boost::optional<http::response_serializer<http::file_body,
  //http::basic_fields<alloc_t>>>file_serializer_;
  void accept();
  void read_request();
  void process_request(
      http::request<request_body_t, http::basic_fields<alloc_t>> const &req);
  void send_bad_response(http::status status, std::string const &error);
  void send_response(std::string msg);
  void check_deadline();

public:
  //	DvsNode(tcp::socket socket):socket_(std::move(socket)){}
  Blockchain_ptr b2;
  DvsNode(DvsNode const &) = delete;
  DvsNode &operator=(DvsNode const &) = delete;
  DvsNode(tcp::acceptor &acceptor, Blockchain_ptr b1) : acceptor_(acceptor) {
    b2 = b1;
  }
  void start();
  void server(Blockchain_ptr b1);
  void forwardRequest_client(beast::string_view target, short choice);
  bool getMerkleRoot();
  bool getLedger();
};
