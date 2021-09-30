#pragma once

#include <modules/physical_port/physical_port.h>
#include "modules/ice/stun/stun_message.h"
#include <map>
#include <mutex>
#include <condition_variable>
#include <list>

class TurnThread
{
public:
    static TurnThread& GetInstance();

    void addPort(const std::shared_ptr<PhysicalPort>& port);

    class IceSession
    {
    public:
      ov::SocketAddress GetLocalAddress() {return localAddr;}
      ov::SocketAddress GetReflexiveAddress() {return publicAddr;}
      ov::SocketAddress GetRelayedAddress() {return relayedAddr;}
    protected:
      enum State {
        STATE_NEW,
        STATE_BINDING,
        STATE_CHALLENGING,
        STATE_ALLOCATING, // Authenticating
        STATE_ALLOCATED,
        STATE_CLOSED
      };

      struct Peer
      {
        enum PeerState
        {
          PEER_NEW,
          PEER_REQUESTING_PERMISSION,
          PEER_PERMITTED
        };

        PeerState state = PEER_NEW;

        ov::SocketAddress remoteCandidate;
        std::string localUfrag;
        std::string remoteUfrag;
      };

      State state = STATE_NEW;

      std::condition_variable cond;
      ov::SocketAddress turnAddress;
      std::string user;
      std::string password;
      std::shared_ptr<PhysicalPort> localPort;

      std::string turnTransaction;
      ov::SocketAddress localAddr;
      ov::SocketAddress publicAddr;
      std::string nonce;
      std::string realm;
      ov::SocketAddress relayedAddr;

      std::list<Peer> peers;

      friend class TurnThread;
    };
    std::shared_ptr<IceSession> createTurnSession(const ov::SocketAddress& localAddress, const ov::SocketAddress& turnAddress, const std::string& turnUser, const std::string turnPassword);
    bool getTurnCandidate(const std::shared_ptr<IceSession>& turnSession);
    bool setTurnPermission(const std::shared_ptr<IceSession>& turnSession, const ov::SocketAddress& remoteCandidate);

    bool onStunBinding(const StunMessage& msg);
    bool onTurnAllocateError(const StunMessage& msg);
    bool onTurnAllocateSuccess(const StunMessage& msg);
protected:
    void run();
    TurnThread();

private:

    void addTimeout(const std::string& transaction, unsigned seconds);
    void addLifetime(const std::shared_ptr<IceSession>& session, unsigned seconds);
    void sendInitialAllocate(const std::shared_ptr<IceSession>& session);
    void sendAuthAllocate(const std::shared_ptr<IceSession>& session);

    std::mutex mutex;
    std::condition_variable cond;
    std::map<std::string, std::shared_ptr<IceSession>> iceTransactions;
    std::multimap<std::chrono::time_point<std::chrono::steady_clock>, std::string> iceTimeouts;
    std::multimap<std::chrono::time_point<std::chrono::steady_clock>, std::shared_ptr<IceSession>> iceLifetimes;
    std::map<ov::SocketAddress, std::shared_ptr<PhysicalPort>> portMap;

};
