#include <bsoncxx/builder/stream/document.hpp>
#include <bsoncxx/types.hpp>
#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/uri.hpp>
#include <bsoncxx/json.hpp>



#include<netinet/in.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<sys/stat.h>
#include<sys/socket.h>
#include<pthread.h>
#include<semaphore.h>

#include<iostream>
#include<vector>
#include<fstream>
#include<cstring>
#include<algorithm>


#include<cstdio>
#include<string>
#include<sstream>
#include<regex>

#include<openssl/ec.h>
#include<openssl/pem.h>


using namespace std;
// using namespace mongocxx;
// using namespace bsoncxx;


//class for document receiving from organizations
class docReceiver
{
	private:
	static constexpr int BUFFER_SIZE=20480;
	static constexpr int FILE_END_MSG_LENGTH=6;
	static constexpr int DOC_END_MSG_LENGTH=6;
	static const char FILE_END_MARKER[];
	static const char DOC_END_MARKER[];
	static sem_t semaphore;
	static int doc_id;


	static mongocxx::instance inst;
    static mongocxx::client conn;
    static mongocxx::database db;
    static mongocxx::collection coll;

	
	int socketFileDescriptor;
	struct sockaddr_in serverAddr,clientAddr;
	vector<pthread_t> servingThreads;
	
	
	
	public:
	docReceiver(int portNumber,const string& dbName="ctlab_db",const string& collectionName="hash_collection")
	{
		conn=mongocxx::client(mongocxx::uri{"mongodb://localhost:27017"});
        db=conn[dbName];
        coll=db[collectionName];


		sem_init(&semaphore,0,1);
		doc_id=0;
		socketFileDescriptor=socket(AF_INET,SOCK_STREAM,0);
		if(socketFileDescriptor<0)
		{
			cerr<<"Error creating socket\n";
			exit(EXIT_FAILURE);
		}
		serverAddr.sin_family=AF_INET;
		serverAddr.sin_addr.s_addr=INADDR_ANY;
		serverAddr.sin_port=htons(portNumber);
		socklen_t serverSockLen=sizeof(serverAddr);
		int opt = 1;
		if(setsockopt(socketFileDescriptor,SOL_SOCKET,SO_REUSEADDR|SO_REUSEPORT,&opt,sizeof(opt))==-1) 
		{
			cerr<<"Error in setsockopt\n";
		    exit(EXIT_FAILURE);
		}
		if(bind(socketFileDescriptor,(struct sockaddr*)&serverAddr,serverSockLen)<0)
		{
			// cerr<<"Error in binding\n";
			perror("Bind failed");
			exit(EXIT_FAILURE);
		}
	}

	
	void listenForConnections(int maxConnections)
	{
		if(listen(socketFileDescriptor,maxConnections)<0)
		{
			cerr<<"Error in listen\n";
			exit(EXIT_FAILURE);
		}
		
		while(1)
		{
			socklen_t clientSockLen=sizeof(clientAddr);
			int clientSocketFileDescriptor=accept(socketFileDescriptor,(struct sockaddr*)&clientAddr,&clientSockLen);
			if(clientSocketFileDescriptor<0)
			{
				cerr<<"Error in accepting request\n";
				exit(EXIT_FAILURE);
			}
			pthread_t servingThread;
			servingThreads.push_back(servingThread);
			int* clientSocketPtr=new int(clientSocketFileDescriptor);
			if(pthread_create(&servingThreads.back(),nullptr,serveClients,(void*)clientSocketPtr)!=0)
			{
				cerr<<"Failed to create thread\n";
				close(clientSocketFileDescriptor);
				exit(EXIT_FAILURE);
			}
			pthread_detach(servingThreads.back());
		}
	}

	private:
	// Function to run the Python script and capture the output
	static string run_python_script(const string& script_name)
	{
		FILE* fp;
		char path[1035];
		string result = "";

		// Open the command for reading.
		fp = popen(script_name.c_str(), "r");
		if (fp == nullptr) {
			cerr << "Failed to run Python script." << endl;
			return "";
		}

		// Read the output of the command.
		while (fgets(path, sizeof(path), fp) != nullptr) {
			result += path;
		}

		// Close the file pointer
		fclose(fp);

		return result;
	}

	// // Function to extract the metadata using regex from the script's output
	static void extract_metadata(const string& script_output, string& unique_id, string& organization)
	{
		// Regex patterns to match each field
		regex unique_id_pattern(R"(Unique ID:([^\n]+))");
		regex organization_pattern(R"(Organization:([^\n]+))");

		smatch match;

		// Search for matches using regex

		if (regex_search(script_output, match, unique_id_pattern)) {
			unique_id = match[1];
		}

		if (regex_search(script_output, match, organization_pattern)) {
			organization = match[1];
		}
	}



	static vector<unsigned char> compute_sha512(const string& filename)
	{
		ifstream file(filename,ios::binary);
		if(!file)
		{
			cerr<<"Error opening file "<<filename<<"\n";
			return{};
		}

		SHA512_CTX sha512;
		SHA512_Init(&sha512);
		vector<unsigned char> buffer(4096);
		while(file.read(reinterpret_cast<char*>(buffer.data()),buffer.size()))
		{
			SHA512_Update(&sha512,buffer.data(),file.gcount());
		}
		SHA512_Update(&sha512,buffer.data(),file.gcount());

		vector<unsigned char> hash(SHA512_DIGEST_LENGTH);
		SHA512_Final(hash.data(),&sha512);
		return hash;
	}



	static bool verify_signature(EC_KEY* ec_key, const vector<unsigned char>& hash, const vector<unsigned char>& signature)
	{
		//ECDSA_verify(0, hash.data(), hash.size(), signature.data(), signature.size(), ec_key) != 1
		if (ECDSA_verify(0, hash.data(), SHA512_DIGEST_LENGTH, signature.data(), signature.size(), ec_key) != 1)
		{
			cerr << "Signature verification failed." << endl;
			return false;
		}
		return true;
	}



	static vector<unsigned char> hex_to_bytes(const string& hex_signature)
	{
		vector<unsigned char> bytes;
		size_t len = hex_signature.length();
		
		if (len % 2 != 0) 
		{
			cerr << "Invalid hex string length" << endl;
			return {};
		}

		for (size_t i = 0; i < len; i += 2) 
		{
			string byte_str = hex_signature.substr(i, 2);
			unsigned char byte = static_cast<unsigned char>(stoi(byte_str, nullptr, 16));
			bytes.push_back(byte);
		}

		return bytes;
	}





	static void insertDocument(const string& signature, const string& unique_id, const string& organization)
	{
		bsoncxx::builder::stream::document doc{};
		doc << "Signature(Hex)" << signature
			<< "unique_id" << unique_id
			<< "Organization" << organization;

		// Insert document
		coll.insert_one(doc.view());

		cout << "Document inserted successfully!" << endl;
	}
	
	// static vector<unsigned char> stringToVector(const string& str) {
	// 	return vector<unsigned char>(str.begin(), str.end());
	// }

	//process file
	static void process_file(string file_name,string hexSignature)
	{
		//string file_name=*(string*)args;
		EC_KEY* public_key = load_public_key("nitw_public_key.pem");
		string script_name = "python3 meta_data_verifier_single_file.py "+file_name;

		// Run the Python script and capture its output
		string script_output = run_python_script(script_name);

		if(script_output.empty())
		{
			cerr << "No output from the Python script." << endl;
			return;
		}

		// Declare variables to store the extracted metadata
		string title, signature, unique_id, organization;

		// Extract metadata from the script's output
		extract_metadata(script_output, unique_id, organization);


		// Print the extracted metadata
		cout << "Extracted Metadata:" << endl;
		cout << "Unique ID: " << unique_id << endl;
		cout << "Organization: " << organization << endl;

		vector<unsigned char> final_signature=hex_to_bytes(hexSignature);

		//add metadata to mongodb

		insertDocument(hexSignature,unique_id,organization);


		if (!public_key)
		{
		    cerr << "Error extracting public key" << endl;
		    EC_KEY_free(public_key);
		    return;
		}

		vector<unsigned char> hash=compute_sha512(file_name);

		
		// vector<unsigned char> final_signature=stringToVector(signature);

        if (verify_signature(public_key, hash, final_signature))
		{
		    cout << "Signature is valid!" << endl;
		} 
		else 
		{
		    cout << "Signature verification failed." << endl;
		}
		
		EC_KEY_free(public_key);
	}

	static EC_KEY* load_public_key(const char* filename)
	{
		FILE* file = fopen(filename, "r");
		if (!file) {
			cerr << "Error opening file: " << filename << endl;
			return nullptr;
		}
	
		EC_KEY* ec_key = PEM_read_EC_PUBKEY(file, nullptr, nullptr, nullptr);
		fclose(file);
	
		if (!ec_key) {
			cerr << "Error reading public key from PEM file.\n";
		}
	
		return ec_key;
	}

	static void save_public_key(const string& public_key_pem)
	{
		ofstream file("NIT_Warangal.pem");
		if(file.is_open())
		{
			file << public_key_pem;
			file.close();
			cout << "Public key saved to NIT_Warangal.pem\n";
		}
		else
		{
			cerr << "Failed to save public key\n";
		}
	}

	static bool fileExists(const char* filename)
	{
		struct stat buffer;
		return (stat(filename, &buffer) == 0);
	}
	
	static bool deleteFile(const char* filename)
	{
		if (!fileExists(filename))
		{
			cout << "File does not exist.\n";
			return false;
		}
		
		if (unlink(filename) == 0)
		{
			cout << "File deleted successfully.\n";
			return true;
		} 
		else
		{
			perror("Error deleting file");
			return false;
		}
	}

	static void* serveClients(void* args)
	{
		int clientSocketFileDescriptor=*(int*)args;
		delete (int*)args;
		
		char buffer[BUFFER_SIZE+1];
		int receivedBytes;
		if((receivedBytes=recv(clientSocketFileDescriptor,buffer,sizeof(buffer),0))!=0)
		{
			cout << "Received public key of NITW:\n" << buffer <<endl;
    		save_public_key(buffer);
		}
		

		send(clientSocketFileDescriptor,"ACK",3,0);

		bool docsEnded=false;
		while(1)
		{
			if(docsEnded)
			{
				cout<<"All docs received from client\n";
				pthread_exit(nullptr);
			}
			string file_name="signed_documents/";
			sem_wait(&semaphore);
			doc_id+=1;
			file_name+=to_string(doc_id)+".pdf";
			cout<<file_name<<endl;
			ofstream fileWriter(file_name,ios::binary);
			sem_post(&semaphore);
			if(!fileWriter)
			{
				cerr<<"Error opening file for writing\n";
				close(clientSocketFileDescriptor);
				pthread_exit(nullptr);
			}
			while((receivedBytes=recv(clientSocketFileDescriptor,buffer,sizeof(buffer),0))!=0)
			{
				cout<<receivedBytes<<endl;
				bool fileEnded=true;
				for(int i=0;i<FILE_END_MSG_LENGTH;i++)
				{
					if(FILE_END_MARKER[i]!=buffer[i])
					{
						fileEnded=false;
						break;
					}
				}
				
				docsEnded=true;
				for(int i=0;i<DOC_END_MSG_LENGTH;i++)
				{
					if(DOC_END_MARKER[i]!=buffer[i])
					{
						docsEnded=false;
						break;
					}
				}

				if(fileEnded)
				{
					cout<<"File transfer completed.\n";
					send(clientSocketFileDescriptor,"ACK",3,0);
					//memset(buffer,0,sizeof(buffer));
					fileWriter.close();
					break;
				}
				else if(docsEnded)
				{
					cout<<"Bytes received:"<<receivedBytes<<endl;
					//fileWriter.write(buffer,receivedBytes);
					send(clientSocketFileDescriptor,"ACK",3,0);
					cout<<"All files received"<<endl;
					fileWriter.close();
					break;
					// memset(buffer,0,sizeof(buffer));
				}
				else
				{
					cout<<"Bytes received:"<<receivedBytes<<endl;
					fileWriter.write(buffer,receivedBytes);
					send(clientSocketFileDescriptor,"ACK",3,0);
					// memset(buffer,0,sizeof(buffer));
				}
			}

			char signatureBuffer[512];
			receivedBytes = recv(clientSocketFileDescriptor, signatureBuffer, sizeof(signatureBuffer), 0);
			if (receivedBytes<= 0)
			{
				cerr << "Error receiving digital signature\n";
				close(clientSocketFileDescriptor);
				pthread_exit(nullptr);
			}
			string receivedSignatureHex(signatureBuffer,receivedBytes);
			cout << "Received Digital Signature: " << receivedSignatureHex << endl;
			

			send(clientSocketFileDescriptor, "ACK", 3, 0);
			
			process_file(file_name,receivedSignatureHex);

			if(deleteFile(file_name.c_str()))
			{
				cout<<"Document deleted, no more stored.\n";
			}
			else
			{
				cout<<"Error in deleting document.\n";
			}
			sem_wait(&semaphore);
			doc_id-=1;
			sem_post(&semaphore);
			memset(buffer,0,sizeof(buffer));
		}
		
		
		close(clientSocketFileDescriptor);
		// pthread_exit(nullptr);
		return nullptr;
	}
	
	public:
	~docReceiver()
	{
		sem_destroy(&semaphore);
		close(socketFileDescriptor);
	}
};





//class responsible for document verification


sem_t docReceiver::semaphore;
int docReceiver::doc_id = 0;
const char docReceiver::FILE_END_MARKER[]="-1 EOF";
const char docReceiver::DOC_END_MARKER[]="-1 EOD";

mongocxx::client docReceiver::conn{};
mongocxx::database docReceiver::db{};
mongocxx::collection docReceiver::coll{};


int main()
{
	int numConnections=10;
	docReceiver fileReceiver(9000);
	fileReceiver.listenForConnections(10);
	return 0;
}

