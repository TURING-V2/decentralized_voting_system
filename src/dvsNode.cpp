#include "../include/dvsNode.hpp"
#include <cpr/cprtypes.h>

void DvsNode::start(){
	accept();
	check_deadline();
}

void DvsNode::accept(){
	beast::error_code ec1;
	socket_.close(ec1);
	buffer_.consume(buffer_.size());
	acceptor_.async_accept(socket_,[this](beast::error_code ec2){
			if(ec2){std::cout<<ec2<<"\n";accept();}
			else{
			     request_deadline_.expires_after(std::chrono::seconds(2));
			     read_request();
			}
	});
}

void DvsNode::read_request(){
	parser_.emplace(std::piecewise_construct,std::make_tuple(),std::make_tuple(alloc_));
	http::async_read(socket_,buffer_,*parser_,[this](beast::error_code ec,std::size_t){
			if(ec) accept();
			else{
			process_request(parser_->get());
			}
	});
}

void DvsNode::process_request(http::request<request_body_t,http::basic_fields<alloc_t>>const &req){
	switch(req.method()){
		case http::verb::post:{
			send_response("RECIEVED\r\n");
			forwardRequest_client(req.target(),1);				      
			if(req.target().find("pubKeyHash")!=std::string::npos){
				if(b2->CheckpubKey(req.target().substr(req.target().find("h=")+2,std::string::npos))==1){
					if(b2->decrypt(req.target().substr(req.target().find("d=")+2,req.target().find("pu")-11))==0){
						send_bad_response(http::status::bad_request,"PUBLIC DECRYPT FAILED");
					}
					else{
						b2->displayBlock();
						b2->ledgerWrite();
					}
				}
				else send_bad_response(http::status::bad_request,"WRONG PUBLIC KEY");
			}
			break;
		}
		case http::verb::get:{
			if(req.target().find("MerkleRoot")!=std::string::npos){
				std::string url=std::string{req.target().substr(0,req.target().find("merk")-12)};
				url=url+b2->tree.root().to_string(64,true);
				cpr::Response r=cpr::Post(cpr::Url{url});
				std::cout<<"MERKLE ROOT SENDED"<<"\n";
			}
			else if(req.target().find("ledger")!=std::string::npos){
				std::string url=std::string{req.target().substr(0,req.target().find("ledger")-7)};
				cpr::Response r = cpr::Post(cpr::Url{url},
			  			  cpr::Multipart{{"key", "large value"},
			  		          {"name", cpr::File{"../ledger"}}});
				std::cout<<"LEDGER SENDED"<<"\n";
			}
			else
				send_bad_response(http::status::bad_request,"WRONG REQUEST");
		}
		default:
			send_bad_response(http::status::bad_request,"Invalid request-method '"+std::string(req.method_string()) + "'\r\n");
			break;
	}
}

void DvsNode::send_bad_response(http::status status,std::string const &error){
	string_response_.emplace(std::piecewise_construct,std::make_tuple(),std::make_tuple(alloc_));
	string_response_->result(status);
	string_response_->keep_alive(false);
	string_response_->set(http::field::server, "Beast");
	string_response_->set(http::field::content_type,"text/plain");
	string_response_->body()=error;
	string_response_->prepare_payload();
	string_serializer_.emplace(*string_response_);
	http::async_write(socket_,*string_serializer_,[this](beast::error_code ec,std::size_t){
			socket_.shutdown(tcp::socket::shutdown_send,ec);
			string_serializer_.reset();
			string_response_.reset();
			accept();
	});
}

void DvsNode::send_response(std::string msg){
	send_bad_response(http::status::ok,msg);
}

void DvsNode::check_deadline(){
	if(request_deadline_.expiry()<=std::chrono::steady_clock::now()){
		socket_.close();
		request_deadline_.expires_at((std::chrono::steady_clock::time_point::max)());
	}
	request_deadline_.async_wait([this](beast::error_code){
			check_deadline();
			});
}

int Blockchain::CheckpubKey(beast::string_view target){
	std::ifstream fkey;
	std::string fname="../keys/"+std::string{target}+".pem";
	fkey.open(fname,std::ios::in);
	char ch;
	if(fkey.is_open()){
		while(!fkey.eof()){
			fkey>>std::noskipws>>ch;
			pubKey.push_back(ch);
		}
		fkey.close();
		block->pubKeyHash=std::string{target};
		return 1;
	}
	else{
		std::cerr<<"No such pub key file\n";
		return 0;
	}
}

void Blockchain::getNodeAddress(){
	std::ifstream fin("../nodes_dvsNode",std::ios::in);
	std::string temp,domain;
	unsigned short int port;
	short i=0;
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

void DvsNode::forwardRequest_client(beast::string_view target,short choice){
	std::string host,port;
//	int version;
	try{
		switch(choice){
			case 1:{
				 for(long unsigned int i=0;i<b2->nodeAddr.size();i++){
				 host=b2->nodeAddr[i].first;
			         port=(std::to_string(b2->nodeAddr[i].second));
				 host="http://"+host+":"+port+""+std::string{target};
				 cpr::Response r=cpr::Post(cpr::Url{host});
				 std::cout<<r.text<<"\n";
			  	 }
	//	version=11;
/*		net::io_context ioc;
		tcp::resolver resolver{ioc};
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
*/			}
			       break;
			 case 2:{
				 for(long unsigned int i=0;i<b2->nodeAddr.size();i++){
				 host=b2->nodeAddr[i].first;
			         port=(std::to_string(b2->nodeAddr[i].second));
				 host="http://"+host+":"+port+""+std::string{target};
				 cpr::Response r=cpr::Get(cpr::Url{host});
				 host=std::string{r.url};
				 b2->mroot.push_back(std::make_pair(r.text,host.substr(0,-11)));
				 }
			}
				break;
			default:{}
	        }
	}
	catch(std::exception const& e){
		std::cerr<<"Error: "<<e.what()<<std::endl;
	}
}

RSA *Blockchain::createRSA(unsigned char *key){
	RSA *rsa=NULL;
	BIO *keybio=BIO_new_mem_buf(key,-1);
	if (keybio==NULL){
		std::cerr<<"Failed to create key BIO"<<std::endl;
		exit(1);
	 }
	rsa=PEM_read_bio_RSA_PUBKEY(keybio,&rsa,NULL,NULL);
        if(rsa==NULL){
	       std::cerr<<"Error PEM_read_bio_RSA_PUBKEY\n";
	       char buffer[120];
	       ERR_error_string(ERR_get_error(), buffer);
	       std::cout<<key<<"\n"; 
	       std::cerr<<"OpenSSL error: "<<buffer<<std::endl;
	       exit(1);
        }	       
	return rsa;
}

int Blockchain::decrypt(beast::string_view target){
	std::string hexEnc=std::string{target};
	long len=((long)hexEnc.length()+1)/3;
	const unsigned char *encrypted=OPENSSL_hexstr2buf(hexEnc.c_str(),&len);
	if(encrypted==NULL){
		std::cerr<<"Hex Decode FAILED"<<std::endl;
		exit(1);
	}
	unsigned char decrypted[77],*decBlock=decrypted;
	unsigned char *publicKey=(unsigned char*)pubKey.c_str();
	RSA *rsa=createRSA(publicKey);
	int result=RSA_public_decrypt(len,encrypted,decBlock,rsa,RSA_PKCS1_PADDING);
	if(result==-1){
		std::cerr<<"Public decrypt FAILED"<<std::endl;
		return 0;
	}
	std::stringstream temp;
	temp<<decBlock;
	addBlock(temp.str());
	return 1;
}

std::string Blockchain::sha256(std::string str){
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

void Blockchain::addBlock(std::string temp){
	std::string timestamp;
	int found=temp.find("|");
	block->uidHash=temp.substr(0,found);
	block->vote=temp.at(found+1);
	timestamp=temp.substr(found+3,std::string::npos);
	block->timestamp=std::stol(timestamp);
	bool checkRedundant=0;
	for(auto const &it:chain)
		if(block->uidHash.compare(it.uidHash)==0)
			checkRedundant=1;
	if(checkRedundant==0){
		chain.push_front(*block);
		tree.insert(sha256(temp));
	}
	std::cout<<tree.statistics.to_string()<<"\n";
}

void Blockchain::displayBlock(){
	std::cout<<"Displaying block contents...\n";
	std::cout<<"UID hash       : "<<block->uidHash<<"\n";	
	std::cout<<"Vote           : "<<block->vote<<"\n";		
	std::cout<<"Timestamp      : "<<block->timestamp<<"\n";	
	std::cout<<"Public key hash: "<<block->pubKeyHash<<"\n";
}

void Blockchain::ledgerWrite(){
	std::ofstream fout("../ledger",std::ios::app);
	if(fout.is_open()){
		std::cout<<"writing in ledger...\n";
		auto const &it=chain.begin();
			fout<<it->uidHash;
			fout<<' '<<it->vote;
			fout<<' '<<it->timestamp;
			fout<<' '<<it->pubKeyHash<<"\n";
	fout.close();
	}
	else{
		std::cerr<<"FAIL TO WRITE LEDGER"<<std::endl;
		exit(1);
	}
}

void Blockchain::ledgerLoad(){
	std::ifstream fin("../ledger",std::ios::in);
	std::string temp;
	short c=0;
	if(fin.is_open()){
		while(fin.peek()!=EOF){
			std::getline(fin,temp,' ');
			++c;
			if(c==1)block->uidHash=temp;
			if(c==2)block->vote=temp[0];
			if(c==3)block->timestamp=std::stol(temp);
			if(c==4){
				block->pubKeyHash=temp;
				chain.push_front(*block);c=0;
			}
		}
		fin.close();
	}
	else{
		std::cerr<<"FAIL TO LOAD LEDGER"<<std::endl;
		exit(1);
	}
}

bool DvsNode::getMerkleRoot(){
	forwardRequest_client("MerkleRoot",2);
	std::map<std::string,int> m;
	int i;
	for(i=0;i<b2->mroot.size();i++){
		std::map<std::string,int>::iterator it=m.find(b2->mroot[i].first);
		if(it==m.end())
			m.insert(std::pair<std::string,int>(b2->mroot[i].first,1));
		else
			m[b2->mroot[i].first]+=1;
	}
	std::map<std::string,int>::iterator it=m.begin();
	for(std::map<std::string,int>::iterator it2=m.begin();it2!=m.end();++it2){
		if(it2->second>it->second)
			it=it2;
	}
	std::string merkle=it->first;
	for(i=0;i<b2->mroot.size();i++)
		if(b2->mroot[i].first==merkle)
			break;
	std::string url=b2->mroot[i].second+"/ledger";
	cpr::Response r=cpr::Get(cpr::Url{url});
	std::ofstream fout("../ledger",std::ios::out);
	if(fout.is_open()){
		std::cout<<"writing in ledger...\n";
		fout<<r.text;
	fout.close();
	}
	else{
		std::cerr<<"FAIL TO WRITE LEDGER"<<std::endl;
		exit(1);
	}
	return 1;
}

void DvsNode::server(Blockchain_ptr b1){
	try{
		std::cout<<"Enter ip address to bind\n";
		std::string input;
		std::cin>>std::setw(45)>>input;
		auto const address=net::ip::make_address(input);
		std::cout<<"Enter port\n";
		std::cin>>std::setw(5)>>input;
		unsigned short port=static_cast<unsigned short>(std::atoi(input.c_str()));
		std::cout<<"starting server...\n";
		net::io_context ioc{1};
		tcp::acceptor acceptor{ioc,{address,port}};
		std::list<DvsNode>workers;
		int num_workers=10;
		for(int i=0;i<num_workers;++i){
			workers.emplace_back(acceptor,b1);
			workers.back().start();
		}
		ioc.run();
	}
	catch(const std::exception &e){
		std::cerr<<"ERROR: "<<e.what()<<std::endl;
		std::exit(1);
	}
}

int main(){
	DvsNode *d1;
	Blockchain_ptr b1(new Blockchain);
	bool genesis;
	std::cout<<"\t\tWELCOME TO DECENTRALIZED VOTING SYSTEM\n";
	std::cout<<"Create genessis block 1/0\n";
	std::cin>>std::setw(1)>>genesis;
	if(genesis){
		b1->chain.push_front({"genesis","genesis","genesis",'F',1625040591});
		std::string hash=b1->sha256("genesis");
		b1->tree.insert(hash);
		std::ofstream fout("../ledger");
		fout.close();
		b1->ledgerWrite();
	}
	else{
		if(d1->getMerkleRoot()){
			std::cout<<"Ledger loaded...\n";
		}
	}
	b1->getNodeAddress();
	d1->server(b1);
	return 0;
}
