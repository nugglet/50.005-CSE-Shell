# 50.005 Programming Assignment 2
Authored: Victoria Yong 1004455, Lim Hng Yi 1004289

## Problem with the Original Protocol

![](diagram1.png)

The original protocol does not prevent playback attacks. Malicious users can intercept the data shown in the diagram above and send it to the client, acting as the server thereby deceiving the client. The client is unable to detect whether the message is coming from the malicious user or the server. In order to tackle this, we introduced a nonce, which is a one time generated random number, into our system. The nonce is generated by the client and then sent to the server in plaintext. Afterwards, the server will encrypt the nonce with its own private key and send it back to the client. The client can then use the server's public key to decrypt the nonce and check whether it is the same nonce as the one previously generated. If the nonce matches, the client has successfully verified the identity of the server!

## Prerequisites
Java is required to run the program. This program was created in JDK 13 and higher.

## Compiling the Program

Compile the program using the `javac` command

```
javac ClientCP1.java ClientCP2.java ServerCP1.java ServerCP2.java ClientAP.java ServerAP.java

```

## Running the Program

To run, open two separate terminal instances, one to run the Client script and the other to run the Server.
First, navigate to the correct directory i.e. `cd PA2\PA2`

### For CP1
Run on the server terminal:
```
java ServerCP1
```

and on the client terminal:
```
java ClientCP1
```

you can also run the client with filenames as command line arguments like so:
```
java ClientCP1 100.txt 1000.txt 5000.txt
```


### For CP2
Run on the server terminal:
```
java ServerCP2
```

and on the client terminal:
```
java ClientCP2
```
you can also run the client with filenames as command line arguments like so:
```
java ClientCP2 100.txt 1000.txt 5000.txt

```

<i>Note: Please run the server before the client.</i>

## Specifications

## Output
The output files are named recv_<your_filename>
Multiple output files will be produced if multiple input files are specified in the command line.

## Conclusion