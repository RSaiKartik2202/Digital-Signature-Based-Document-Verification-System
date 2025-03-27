NOTE:
consider this is a root directory
the commands after >> should be executed
for each folder crate a new terminal window or new terminal tab
For more info see our project report in current directory



1)---------------------------------------------------------------------------------------------------------------------------------------------

Organization should sign its documents and put in metadata
so move into its directory
create a new terminal tab

>> cd Organization\(docSender\)/

2)---------------------------------------------------------------------------------------------------------------------------------------------

Now sign the documents and put in metadata

>> python3 meta_data_writer.py

now metadata( roll_no , organization name ) is written into documents 

3)---------------------------------------------------------------------------------------------------------------------------------------------

It also generates public key for NITW by itself in below program

4)---------------------------------------------------------------------------------------------------------------------------------------------

Start the organization Server

>> g++ signed_docs_sender.cpp -o signed_docs_sender -lssl -lcrypto $(pkg-config --cflags --libs libmongocxx)

5)---------------------------------------------------------------------------------------------------------------------------------------------

Start the Central Server 
create a new terminal tab

>> cd Central_Server/

>> g++ central_server.cpp -o central_server -lssl -lcrypto $(pkg-config --cflags --libs libmongocxx)


6)---------------------------------------------------------------------------------------------------------------------------------------------

run central_server and organization

In central server terminal tab

>> ./central_server

In organization's  terminal tab

>> ./signed_docs_sender 

Now all the documents are sent to central server 
and central server will upload them into their database

7)---------------------------------------------------------------------------------------------------------------------------------------------

Now student will download documents and send it to company

also start server in company in company's terminal tab

>> cd Company\(Verify\)/
>> g++ student_docs_receiver.cpp -o sender 
>> ./student_docs_receiver

create new terminal tab for student

Sending

>> cd Student/
>> g++ student_docs_sender.cpp -o sender 
>> ./student_docs_sender


8)---------------------------------------------------------------------------------------------------------------------------------------------

Now company should verify whether the docs provided by student are correct or not

compile code for company
create new terminal tab for company

>> g++ file_sender.cpp -o file_sender -lssl -lcrypto

Run the central server code for receiving & verifying documents in central server terminal tab

>> g++ doc_verifier_server.cpp -o doc_verifier_server -lssl -lcrypto $(pkg-config --cflags --libs libmongocxx)
>> ./doc_verifier_server

Run the file_sender code of company

>> ./file_sender

Now company will be acknowledged about all the files it has sent after verification by central server
