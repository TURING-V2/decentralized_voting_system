#include "../include/dvsClient.hpp"
/*
namespace beast=boost::beast;
namespace http=beast::http;
namespace net=boost::asio;
using tcp=net::ip::tcp;
*/
void Data::getTimestamp(){
	block->timestamp=time(NULL);
}

void Data::getUidHash(std::string key){
	std::cout<<"Enter voter's Aadhaar user id\n";
	std::cin>>std::setw(12)>>block->uidHash;
	block->uidHash=sha256(block->uidHash.append(pKey));
}

void Data::getVote(){
	AGAIN: std::cout<<"\tList of candidates\n";
	for(int i=0;i<6;i++)
		std::cout<<(char)(65+i)<<": "<<candidates[i]<<"\n";
	std::cout<<"\tENTER YOUR VOTE\n";
	std::cin>>std::setw(1)>>block->vote;
	if((int)block->vote<65||(int)block->vote>70){
		std::cout<<"  WRONG VOTE\n";
		goto AGAIN;
	}
}

void Data::getPubKeyhash(){
	std::ifstream fkey;
	fkey.open("../keys/public.pem",std::ios::in);
	char ch;
	if(fkey.is_open()){
		while(!fkey.eof()){
			fkey>>ch;
			block->pubKeyHash.push_back(ch);
		}
		fkey.close();
	}
	else{
		std::cerr<<"No such pub key file\n";
		exit(1);
	}
	block->pubKeyHash=sha256(block->pubKeyHash);
}

std::string Data::sha256(std::string str){
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256,str.c_str(),str.length());
	SHA256_Final(hash,&sha256);
	std::stringstream ss;
	for(int i=0;i<SHA256_DIGEST_LENGTH;i++)
		ss<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)hash[i];
	return ss.str();
}

void Data::displayBlock(){
	std::cout<<"Displaying block contents...\n";
	std::cout<<"UID hash       : "<<(block->uidHash)<<"\n";	
	std::cout<<"Vote           : "<<block->vote<<"\n";		
	std::cout<<"Timestamp      : "<<block->timestamp<<"\n";	
	std::cout<<"Public key hash: "<<(block->pubKeyHash)<<"\n";
}

void DvsClient::getNodeAddress(){
	std::ifstream fin("../nodes_dvsClient",std::ios::in);
	std::string temp,domain;
	unsigned short int port;
	int i=0;
	if(fin.is_open()){	
	       while(fin.peek()!=EOF){
		       std::getline(fin,temp,' ');
		       if(i==0)
			      domain=temp;
		       else{
			       port=std::stoi(temp);
			       nodeAddr.push_back(std::make_pair(domain,port));
			       i=0;
		       }
		       ++i;
		}
		fin.close();
	}
	else {
		std::cerr<<"No such file nodes"<<std::endl;
		exit(1);
	}
}

std::string DvsClient::getPriKey(){
	std::ifstream fkey;
	fkey.open("../keys/private.pem",std::ios::in);
	char ch;
	if(fkey.is_open()){
		while(!fkey.eof()){
			fkey>>std::noskipws>>ch;
			pKey.push_back(ch);
		}
		fkey.close();
	}
	else{
		std::cerr<<"No such priv key file"<<std::endl;
		exit(1);
	}
	return pKey;
}

RSA *DvsClient::createRSA(unsigned char *key){
	RSA *rsa=NULL;
	BIO *keybio=BIO_new_mem_buf(key,-1);
	if (keybio==NULL){
		std::cerr<<"Failed to create key BIO"<<std::endl;
		exit(1);
	 }
	rsa=PEM_read_bio_RSAPrivateKey(keybio,&rsa,NULL,NULL);
        if(rsa==NULL){
	       std::cerr<<"Error PEM_read_bio_RSAPrivateKey\n";
	       char buffer[120];
	       ERR_error_string(ERR_get_error(), buffer);
	       std::cout<<key<<"\n"; 
	       std::cerr<<"OpenSSL error: "<<buffer<<std::endl;
	       exit(1);
        }	       
	return rsa;
}

void DvsClient::encryptBlock(){
	std::string temp;
	if(pKey=="")
		pKey=getPriKey();
	std::stringstream longBlock;
	longBlock<<block->uidHash<<"|"<<block->vote<<"|"<<block->timestamp;
	temp=longBlock.str();
	const unsigned char *longBlock1=(const unsigned char*)temp.c_str();
	unsigned char encrypted[2024],*encBlock=encrypted,*privateKey=(unsigned char*)pKey.c_str();
	RSA *rsa=createRSA(privateKey);
	int enc_len=RSA_private_encrypt(temp.length(),longBlock1,encBlock,rsa,RSA_PKCS1_PADDING);
	if(enc_len==-1){
		std::cerr<<"Private Encrypt FAILED"<<std::endl;
		exit(1);
	}
	else
		std::cout<<"Block Encrypted\n";
	const char *ehex=OPENSSL_buf2hexstr(encBlock,enc_len);
	if(ehex==NULL){
		std::cerr<<"Hex Encode FAILED"<<std::endl;
		exit(1);
	}
	std::string const fname="enc.txt";
	std::string msg(ehex);
	std::ofstream(fname)<<encBlock;
	std::cout<<msg<<"\n";
	sendData(msg);
}

void DvsClient::sendData(std::string msg){
	const char *port;
	std::string host,target;
//	int version;
	try{
		for(long unsigned int i=0;i<nodeAddr.size();i++){
			host=nodeAddr[i].first;
			port=(std::to_string(nodeAddr[i].second)).c_str();
			msg="encrypted="+msg;
			msg+="pubKeyHash="+block->pubKeyHash;
			target="http://"+host+":"+port+"/"+msg;
//		version=11;
			cpr::Response r=cpr::Post(cpr::Url{target});
			std::cout<<r.text<<"\n";
/*		net::io_context ioc;
		tcp::resolver resolver(ioc);
		beast::tcp_stream stream(ioc);
		auto const results=resolver.resolve(host,port);
		stream.connect(results);
		http::request<http::string_body> req{http::verb::post,target,version};
		req.set(http::field::host,host);
		req.set(http::field::user_agent,BOOST_BEAST_VERSION_STRING);
		http::write(stream,req);
		beast::flat_buffer buffer;
		http::response<http::dynamic_body>res;
		http::read(stream,buffer,res);
		std::cout<<res<<"\n";
		beast::error_code ec;
		stream.socket().shutdown(tcp::socket::shutdown_both,ec);
		if(ec&&ec!=beast::errc::not_connected)
			throw beast::system_error{ec};
*/		}
	}
	catch(std::exception const& e){
		std::cerr<<"Error: "<<e.what()<<std::endl;
	}
}	

int main(){
	DvsClient *d=new DvsClient();
	std::cout<<"\t\tWELCOME TO DECENTRALIZED VOTING SYSTEM \n";
	std::cout<<"loading node addreses, hashing keys....\n"; 
	d->getNodeAddress();
	d->getPubKeyhash();
	std::string pKey=d->getPriKey();
	char next;
	do{
		d->getUidHash(pKey);
		d->getVote();
		d->getTimestamp();
		d->displayBlock();
		d->encryptBlock();
		std::cout<<"\nNext voter (y/N)\n";
		std::cin>>next;
	}while(next=='y');
	std::cout<<"clearing mems..."<<std::endl;
	d->nodeAddr.clear();
	d->nodeAddr.shrink_to_fit();
	delete d;
	return 0;	
}
