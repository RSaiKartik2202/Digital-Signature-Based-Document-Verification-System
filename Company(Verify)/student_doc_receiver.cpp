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
#include<algorithm>
#include<sstream>
#include<iomanip>


#include<cstdio>
#include<string>
#include<sstream>
#include<regex>

using namespace std;

class docVerifier
{
	private:
	static constexpr int BUFFER_SIZE=20480;
	static constexpr int FILE_END_MSG_LENGTH=6;
	static constexpr int DOC_END_MSG_LENGTH=6;
	static const char FILE_END_MARKER[];
	static const char DOC_END_MARKER[];
	static sem_t semaphore;
	static int doc_id;


	
	int socketFileDescriptor;
	struct sockaddr_in serverAddr,clientAddr;
	vector<pthread_t> servingThreads;
	
	
	
	public:
	docVerifier(int portNumber)
	{
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
        //|SO_REUSEPORT
		if(setsockopt(socketFileDescriptor,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt))==-1) 
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
		// cerr << "Socket FD: " << socketFileDescriptor << endl;
		// cerr << "Max connections: " << maxConnections << endl;
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
	static void* serveClients(void* args)
	{
		int clientSocketFileDescriptor=*(int*)args;
		delete (int*)args;
		
		char buffer[BUFFER_SIZE+1];
		int receivedBytes;
		// if((receivedBytes=recv(clientSocketFileDescriptor,buffer,sizeof(buffer),0))!=0)
		// {
		// 	cout << "Received public key of NITW:\n" << buffer <<endl;
    	// 	save_public_key(buffer);
		// }
		

		// send(clientSocketFileDescriptor,"ACK",3,0);
		memset(buffer,0,sizeof(buffer));
		bool docsEnded=false;
		while(1)
		{
			if(docsEnded)
			{
				cout<<"All docs received from client\n";
				pthread_exit(nullptr);
			}
			string file_name="student_documents/";
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
				memset(buffer,0,sizeof(buffer));
			}
			memset(buffer,0,sizeof(buffer));
		}
		
		
		close(clientSocketFileDescriptor);
		// pthread_exit(nullptr);
		return nullptr;
	}
	
	public:
	~docVerifier()
	{
		sem_destroy(&semaphore);
		close(socketFileDescriptor);
	}
};


sem_t docVerifier::semaphore;
int docVerifier::doc_id = 0;
const char docVerifier::FILE_END_MARKER[]="-1 EOF";
const char docVerifier::DOC_END_MARKER[]="-1 EOD";



int main()
{
	int numConnections=10;
	docVerifier docVerification(11000);
	docVerification.listenForConnections(numConnections);
	return 0;
}
