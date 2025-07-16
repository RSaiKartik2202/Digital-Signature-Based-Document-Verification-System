#include<netinet/in.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<sys/socket.h>
#include<pthread.h>
#include<semaphore.h>

#include<iostream>
#include<vector>
#include<fstream>
#include<cstring>

#include<iomanip>
#include<dirent.h>
#include<sys/stat.h>

#include <iostream>
#include <fstream>
#include <cstring>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <openssl/ec.h>
#include <openssl/pem.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
using namespace std;

class SocketCommunication
{
    private:
    int socketFileDescriptor;
    struct sockaddr_in serverAddr;
    vector<pthread_t> serverCommunications;
    static constexpr int BUFFER_SIZE=20480;
    
    public:
    SocketCommunication()
    {
        socketFileDescriptor=socket(AF_INET,SOCK_STREAM,0);
        if(socketFileDescriptor==-1)
        {
            cerr<<"Error creating socket\n";
            exit(EXIT_FAILURE);
        }
    }
    
    void connectOn(int portNumber)
    {
        serverAddr.sin_family=AF_INET;
        serverAddr.sin_addr.s_addr=inet_addr("127.0.0.1");
        serverAddr.sin_port=htons(portNumber);
        socklen_t serverSockLen=sizeof(serverAddr);
        
        if(connect(socketFileDescriptor,(struct sockaddr*)&serverAddr,serverSockLen)==-1)
        {
            cerr<<"Connection Failed\n";
            close(socketFileDescriptor);
            exit(EXIT_FAILURE);
        }
        
        pthread_t serverCommunication;
        serverCommunications.push_back(serverCommunication);
        int* socketPtr=new int(socketFileDescriptor);
        if(pthread_create(&serverCommunications.back(),nullptr,communicateWithServer,(void*)socketPtr)!=0)
        {
            cerr<<"Failed to create thread\n";
            close(socketFileDescriptor);
            exit(EXIT_FAILURE);
        }
        pthread_join(serverCommunications.back(),nullptr);
    }
    private:


    static EC_KEY* load_or_generate_key(const char* filename)
    {
        EC_KEY* ec_key=nullptr;
        FILE* file=fopen(filename,"r");

        if(file){
            ec_key=PEM_read_ECPrivateKey(file,nullptr,nullptr,nullptr);
            fclose(file);
            if(ec_key){
                cout<<"Loaded existing private key from "<<filename<<"\n";
                return ec_key;
            }
        }

        ec_key=EC_KEY_new_by_curve_name(NID_secp521r1);
        if(!ec_key||!EC_KEY_generate_key(ec_key))
        {
            cerr<<"Error generating EC key\n";
            EC_KEY_free(ec_key);
            return nullptr;
        }

        file=fopen(filename,"w");
        if(file)
        {
            PEM_write_ECPrivateKey(file,ec_key,nullptr,nullptr,0,nullptr,nullptr);
            fclose(file);
            cout<<"Generated and saved new private key to "<<filename<<"\n";
        }

        return ec_key;
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


    static vector<unsigned char> sign_hash(EC_KEY* ec_key,const vector<unsigned char>& hash)
    {
        unsigned int sig_len=0;
        vector<unsigned char> signature(ECDSA_size(ec_key));
        
        if(!ECDSA_sign(0,hash.data(),hash.size(),signature.data(),&sig_len,ec_key))
        {
            cerr<<"Error signing hash\n";
            return{};
        }
        
        signature.resize(sig_len);
        return signature;
    }

    static string signature_to_hex(const vector<unsigned char>& signature)
    {
        stringstream ss;
        for(unsigned char byte:signature)
        {
            ss<<hex<<setw(2)<<setfill('0')<<static_cast<int>(byte);
        }
        return ss.str();
    }


    static EC_KEY* load_key(const char* filename)
    {
        EC_KEY* ec_key = nullptr;
        FILE* file = fopen(filename, "r");
    
        if (file)
        {
            ec_key = PEM_read_ECPrivateKey(file, nullptr, nullptr, nullptr);
            fclose(file);
            if (ec_key)
            {
                cout << "Loaded existing private key from " << filename << "\n";
                return ec_key;
            }
            else
            {
                cerr<< "Error:Failed to load existing private key from " << filename << "\n";
            }
        }
        return nullptr;
    }

    static string extract_public_key(EC_KEY* ec_key)
    {
        BIO* bio = BIO_new(BIO_s_mem());
        PEM_write_bio_EC_PUBKEY(bio, ec_key);
    
        char* pem_data;
        size_t len = BIO_get_mem_data(bio, &pem_data);
    
        std::string public_key(pem_data, len);
        BIO_free(bio);
        return public_key;
    }

    static void* communicateWithServer(void* args)
    {
        char ack[4]={};
        int socketFileDescriptor=*(int*)args;

        EC_KEY* ec_key=load_key("private_key.pem");
        string public_key_pem = extract_public_key(ec_key);
        send(socketFileDescriptor, public_key_pem.c_str(), public_key_pem.size(), 0);
        int recvBytes=recv(socketFileDescriptor,ack,sizeof(ack),0);
        if(recvBytes<0)
        {
            cerr<<"Error in receiving data\n";
            close(socketFileDescriptor);
            return nullptr;
        }
        else if(recvBytes==0)
        {
            cout<<"Connection Closed at Server\n";
            close(socketFileDescriptor);
            return nullptr;
        }
        else
        {
            cout<<"Received response from Server:"<<ack<<endl;
        }


        const string curr_dir="signed_documents/";
        DIR* dir;
        struct dirent* entry;
        bool docsEnded=false;
        if((dir=opendir(curr_dir.c_str()))==nullptr)
        {
            cerr<<"Error:Unable to open directory "<<curr_dir<<endl;
            return nullptr;
        }

        if((entry=readdir(dir))==nullptr)
        {
            cerr<<"Error:Unable to read directory "<<curr_dir<<endl;
        }
        do
        {
            // cout<<"do start\n";
            string file_name=entry->d_name;
            if(file_name=="." || file_name=="..")
            {
                if((entry=readdir(dir))==nullptr)
                {
                    cerr<<"Error:Unable to read directory "<<curr_dir<<endl;
                }
                continue;
            }

            if(file_name.size()>4 && file_name.substr(file_name.size()-4)==".pdf")
            {
                const string pdf_file=curr_dir+file_name;
                ifstream fileReader(pdf_file,ios::binary);
            
                if(!fileReader)
                {
                    cerr<<"File could not be opened\n";
                    close(socketFileDescriptor);
                    return nullptr;
                }
                cout<<"Sending: "<<pdf_file<<endl;
                char buffer[BUFFER_SIZE+1];
                
                
                while(fileReader.read(buffer,BUFFER_SIZE) || fileReader.gcount()>0)
                {
                    int bytesToSend=fileReader.gcount();
                    buffer[bytesToSend]='\0';
                    int bytesSent=send(socketFileDescriptor,buffer,bytesToSend,0);
                    if(bytesSent<0)
                    {
                        cerr<<"Error in sending data\n";
                        close(socketFileDescriptor);
                        return nullptr;
                    }
                    else if(bytesSent==0)
                    {
                        cerr<<"Connection Closed at Server\n";
                        close(socketFileDescriptor);
                        return nullptr;
                    }
                    else
                    {
                        int bytesReceived=recv(socketFileDescriptor,ack,sizeof(ack),0);
                        if(bytesReceived<0)
                        {
                            cerr<<"Error in receiving data\n";
                            close(socketFileDescriptor);
                            return nullptr;
                        }
                        else if(bytesReceived==0)
                        {
                            cout<<"Connection Closed at Server\n";
                            close(socketFileDescriptor);
                            return nullptr;
                        }
                        else
                        {
                            cout<<"Received response from Server:"<<ack<<endl;
                        }
                    }
                    memset(buffer,0,sizeof(buffer));
                }
                if((entry=readdir(dir))==nullptr)
                {
                    docsEnded=true;
                    //cerr<<"Error:Unable to read directory "<<curr_dir<<endl;
                    send(socketFileDescriptor,"-1 EOD",6,0);
                    //after each file, send its digital signature as well

                    //break;
                }
                else
                { 
                    send(socketFileDescriptor,"-1 EOF",6,0);
                    //after each file, send its digital signature as well
                    
                }
                int bytesReceived=recv(socketFileDescriptor,ack,sizeof(ack),0);
                if(bytesReceived<0)
                {
                    cerr<<"Error in receiving data\n";
                    close(socketFileDescriptor);
                    return nullptr;
                }
                else if(bytesReceived==0)
                {
                    cout<<"Connection Closed at Server\n";
                    close(socketFileDescriptor);
                    return nullptr;
                }
                else
                {
                    cout<<"Received response from Server:"<<ack<<endl;
                }
                //may need to add another recv -->added
                fileReader.close();

                //to generate digital signature
                // const string pdf_file=curr_dir+file_name;
                cout<<"Generating Signature of: "<<pdf_file<<endl;
                vector<unsigned char> hash=compute_sha512(pdf_file);
                if(hash.empty())
                {
                    cerr<<"Failed to compute hash.\n";
                    EC_KEY_free(ec_key);
                    return nullptr;
                }

                //converts hash to hex format
                string hex_hash=signature_to_hex(hash);
                cout<<"Hex hash:"<<hex_hash<<endl;

                vector<unsigned char> signature=sign_hash(ec_key,hash);
                if(signature.empty())
                {
                    cerr<<"Failed to sign hash.\n";
                    EC_KEY_free(ec_key);
                    return nullptr;
                }

                string hex_signature=signature_to_hex(signature);
                cout<<"Signature generated successfully. Signature size: "<<signature.size()<<" bytes\n";
                cout<<"Hex Signature: "<<hex_signature<<endl;


                cout<<"Sending digital signature...\n";
                int bytesSent=send(socketFileDescriptor, hex_signature.c_str(), hex_signature.size(), 0);
                if (bytesSent < 0)
                {
                    cerr << "Error in sending digital signature\n";
                    close(socketFileDescriptor);
                    return nullptr;
                }
                else if (bytesSent == 0)
                {
                    cerr << "Connection Closed at Server\n";
                    close(socketFileDescriptor);
                    return nullptr;
                }

                //Receive acknowledgment from the server for the signature
                bytesReceived = recv(socketFileDescriptor, ack, sizeof(ack), 0);
                if (bytesReceived < 0)
                {
                    cerr << "Error in receiving acknowledgment for signature\n";
                    close(socketFileDescriptor);
                    return nullptr;
                }
                else if (bytesReceived == 0)
                {
                    cout << "Connection Closed at Server\n";
                    close(socketFileDescriptor);
                    return nullptr;
                }
                else
                {
                    cout << "Received acknowledgment for signature from Server: " << ack << endl;
                }
                if(docsEnded)
                break;
            }
            else
            {
                if((entry=readdir(dir))==nullptr)
                {
                    cerr<<"Error:Unable to read directory "<<curr_dir<<endl;
                    //send(socketFileDescriptor,"-1 EOD",6,0);
                    //break;
                }
            }
        }while(1);
        //send(socketFileDescriptor,"-1 EOD",6,0);
        close(socketFileDescriptor);
        // pthread_exit(NULL);
        return nullptr;
    }
    
    public:
    ~SocketCommunication()
    {
        close(socketFileDescriptor);
    }
};



int main()
{
    SocketCommunication fileSharing;
    fileSharing.connectOn(9000);
    return 0;
}
            