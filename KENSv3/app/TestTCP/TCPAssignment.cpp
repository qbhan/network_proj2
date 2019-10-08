/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"

namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{

}

void TCPAssignment::finalize()
{

}

//void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int param1, int param2)
//{
//	this->returnSystemCall(syscallUUID, createFileDescriptor(pid))
//}


void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:
		syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		//syscall_socket(syscallUUID, pid);
		break;
	case CLOSE:
		this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		//this->syscall_connect(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		this->syscall_getsockname(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		//this->syscall_getpeername(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{

}

void TCPAssignment::timerCallback(void* payload)
{

}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int param1, int param2)
{ 
	this->returnSystemCall(syscallUUID, createFileDescriptor(pid));
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int socket)
{
//	std::list<socket_info>close_socket_list = this->socket_list;
/*
	std::list<socket_info>::iterator iter;
	for(iter=this->socket_list.begin(); iter != this->socket_list.end(); ++iter){
		if ((*iter).socket == socket){
			this->socket_list.erase(iter);
			break;
		}
	}
	this->removeFileDescriptor(pid, socket);
	this->returnSystemCall(syscallUUID, 0);
	*/
	
	for(int i = 0; i < this->socket_list.size(); i++){
		if (std::get<0>(this->socket_list[i]) == socket){
			this->socket_list.erase(this->socket_list.begin() + i);
			break;
		}
	}
	this->removeFileDescriptor(pid, socket);											
	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int socket, struct sockaddr *(addr), socklen_t sock_len)
{
/*	socket_info new_socket;
	struct sockaddr_in *sock_addr = (sockaddr_in *)addr;
	new_socket.socket = socket;
	new_socket.addr = sock_addr->sin_addr.s_addr;
	new_socket.port = sock_addr->sin_port;

	std::list<socket_info>check_socket_list = this->socket_list;
	std::list<socket_info>::iterator iter;

	int cnt = 0;
	for (iter=check_socket_list.begin(); iter!=check_socket_list.end(); ++iter){
		if (new_socket.socket == (*iter).socket){
//			this->returnSystemCall(syscallUUID, -1);
			cnt++;
//			break;
		} else if (new_socket.addr == 0 || (*iter).addr == 0){
//			this->returnSystemCall(syscallUUID, -1);
			cnt++;
//		    break;
		} else if ((new_socket.addr == (*iter).addr) && (new_socket.port == (*iter).port)){
//		    this->returnSystemCall(syscallUUID, -1);
			cnt++;
//		    break;
		}
	}
	if (cnt > 0){
		this->returnSystemCall(syscallUUID, -1);
	}
	
	else {
		this->socket_list.push_back(new_socket);
		this->returnSystemCall(syscallUUID, 0);
	} */

	socket_info new_socket;
	struct sockaddr_in *sock_addr = (sockaddr_in *)addr;
	new_socket = std::make_tuple(socket, sock_addr->sin_addr.s_addr, sock_addr->sin_port);

	int cnt = 0;
	int size = this->socket_list.size();
	for (int i=0; i<size; i++){
		if (std::get<0>(new_socket) == std::get<0>(this->socket_list[i])){
			cnt++;
		} else if (std::get<1>(new_socket)==0 || std::get<1>(this->socket_list[i])==0){
			cnt++;
		} else if (std::get<1>(new_socket) == std::get<1>(this->socket_list[i]) && std::get<2>(new_socket) == std::get<2>(this->socket_list[i])){
			cnt++;
		}
	}
	if (cnt > 0) {
		this->returnSystemCall(syscallUUID, -1); 
	}
	else {
		this->socket_list.push_back(new_socket);
		this->returnSystemCall(syscallUUID, 0);
	}
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int socket, struct sockaddr *addr, socklen_t*(sock_len))
{
	struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
	addr_in->sin_family = AF_INET;

/*	std::list<socket_info> name_socket_list = this->socket_list;
	std::list<socket_info>::iterator iter ;
	for(iter=name_socket_list.begin(); iter!=name_socket_list.end(); iter++){
		if ((*iter).socket == socket){
			addr_in->sin_addr.s_addr = (*iter).addr;
			addr_in->sin_port = (*iter).port;
			this->returnSystemCall(syscallUUID, 0);
		}
	}
	*/
	int size = this->socket_list.size();
	for(int i = 0; i<size; i++){
		if (std::get<0>(this->socket_list[i]) == socket){
			addr_in->sin_addr.s_addr = std::get<1>(this->socket_list[i]);
			addr_in->sin_port = std::get<2>(this->socket_list[i]);
			this->returnSystemCall(syscallUUID, 0);
		}
	}
}





}



