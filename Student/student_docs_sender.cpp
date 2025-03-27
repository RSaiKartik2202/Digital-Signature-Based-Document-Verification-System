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

	static void* communicateWithServer(void* args)
	{
		char ack[4]={};
		int socketFileDescriptor=*(int*)args;
		
		const string curr_dir="marks_sheets/";
		DIR* dir;
		struct dirent* entry;
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
					//cerr<<"Error:Unable to read directory "<<curr_dir<<endl;
					send(socketFileDescriptor,"-1 EOD",6,0);
					//after each file, send its digital signature as well

					break;
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
				sleep(1);
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
	fileSharing.connectOn(11000);
	return 0;
}
