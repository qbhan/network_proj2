/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>


#include <E/E_TimerModule.hpp>

namespace E
{

typedef struct socket_info socket_info;
struct socket_info{
	int socket;
	long addr;
	short port;
};


class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:

private:
	virtual void timerCallback(void* payload) final;
	virtual void syscall_socket(UUID syscallUUID, int pid, int param1, int param2);
	virtual void syscall_close(UUID syscallUUID, int pid, int socket);
    virtual void syscall_bind(UUID syscallUUID, int pid, int socket, struct sockaddr *addr, socklen_t sock_len);
	virtual void syscall_getsockname(UUID syscallUUID, int pid, int socket, struct sockaddr *addr, socklen_t* sock_len);

public:
	TCPAssignment(Host* host);
	std::list<socket_info> socket_list;
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
	//virtual void syscall_socket(UUID syscallUUID, int pid, int param1, int param2);
	//virtual void syscall_bind(UUID syscallUUID, int pid, int socket, struct sockaddr *addr, socklen_t sock_len);
protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
